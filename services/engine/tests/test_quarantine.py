from __future__ import annotations

import ctypes
import hashlib
import json
import os
import sqlite3
import stat
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

import zombie_killer_engine.quarantine as quarantine_module
from zombie_killer_engine.models import ProcessIdentity
from zombie_killer_engine.paths import AppPaths, WindowsPermissionBackend
from zombie_killer_engine.quarantine import (
    CleanupManifest,
    CleanupRejectedError,
    InMemoryCleanupRegistry,
    QuarantineEntry,
    QuarantineError,
    QuarantineResult,
    QuarantineState,
    ResourceType,
)
from zombie_killer_engine.quarantine import (
    QuarantineExecutor as _QuarantineExecutor,
)
from zombie_killer_engine.quarantine import (
    QuarantinePlanner as _QuarantinePlanner,
)
from zombie_killer_engine.service import (
    PROTOCOL_VERSION,
    Capability,
    ClientKind,
    Method,
    RequestContext,
    RequestEnvelope,
    build_default_service,
)
from zombie_killer_engine.store import PlanClaimError, SQLiteStateStore

NOW = datetime(2026, 8, 12, 12, 0, tzinfo=UTC)
IDENTITY = ProcessIdentity(
    boot_id="test-boot",
    pid=4242,
    create_time=1_765_000_000.25,
    executable="/test/python",
    user="test-user",
)
REGISTRY = InMemoryCleanupRegistry()


@pytest.fixture(autouse=True)
def authoritative_registry() -> None:
    REGISTRY.clear()


class QuarantinePlanner(_QuarantinePlanner):
    def __init__(self, *args: object, **kwargs: object) -> None:
        if os.name == "nt" and args:
            for raw_root in args[0]:  # type: ignore[union-attr]
                root = Path(raw_root)
                if not root.is_dir():
                    continue
                WindowsPermissionBackend().restrict(root)
        kwargs.setdefault("registration_resolver", REGISTRY)
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]


class QuarantineExecutor(_QuarantineExecutor):
    def __init__(self, *args: object, **kwargs: object) -> None:
        kwargs.setdefault("registration_resolver", REGISTRY)
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]


class MutableClock:
    def __init__(self, value: datetime = NOW) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


def app_paths(tmp_path: Path) -> AppPaths:
    return AppPaths(
        data_dir=tmp_path / "data",
        state_dir=tmp_path / "state",
        runtime_dir=tmp_path / "runtime",
        backups_dir=tmp_path / "backups",
        graveyard_dir=tmp_path / "graveyard",
    )


def manifest(
    root: Path,
    target: Path,
    *,
    resource_type: ResourceType = ResourceType.FILE,
    managed: bool = True,
    created_at: datetime = NOW,
) -> CleanupManifest:
    cleanup_manifest = CleanupManifest.create(
        agent_id="test-agent",
        creating_identity=IDENTITY,
        approved_root=root,
        target=target,
        resource_type=resource_type,
        declaration_source="sdk",
        managed=managed,
        created_at=created_at,
    )
    REGISTRY.register(cleanup_manifest)
    return cleanup_manifest


@pytest.mark.skipif(os.name != "nt", reason="Windows ACLs are platform-specific")
def test_test_planner_replaces_explicit_untrusted_root_acl(tmp_path: Path) -> None:
    root = tmp_path / "approved"
    root.mkdir()
    target = root / "artifact.bin"
    target.write_bytes(b"test")
    granted = subprocess.run(
        ["icacls", str(root), "/grant", "*S-1-1-0:(OI)(CI)M"],
        capture_output=True,
        text=True,
        check=False,
    )
    if granted.returncode != 0:
        pytest.skip(f"ACL modification unavailable: {granted.stderr.strip()}")
    try:
        plan = QuarantinePlanner((root,), clock=MutableClock()).create_plan(manifest(root, target))
        assert plan.fingerprint.owner == quarantine_module._windows_current_user_sid()
        WindowsPermissionBackend().verify(root)
    finally:
        WindowsPermissionBackend().restrict(root)


def initialized_store(paths: AppPaths, clock: MutableClock) -> SQLiteStateStore:
    store = SQLiteStateStore(paths, clock=clock, session_id="test-session")
    store.initialize(now=clock())
    return store


def plan_file(
    tmp_path: Path,
    *,
    content: bytes = b"owned test material",
    clock: MutableClock | None = None,
) -> tuple[AppPaths, SQLiteStateStore, CleanupManifest, object, Path, Path]:
    selected_clock = clock or MutableClock()
    paths = app_paths(tmp_path)
    store = initialized_store(paths, selected_clock)
    root = tmp_path / "approved"
    root.mkdir(mode=0o700)
    target = root / "artifact.bin"
    target.write_bytes(content)
    cleanup_manifest = manifest(root, target)
    cleanup_plan = QuarantinePlanner((root,), clock=selected_clock).create_plan(cleanup_manifest)
    store.save_quarantine_plan(cleanup_plan)
    return paths, store, cleanup_manifest, cleanup_plan, root, target


def quarantine_file(
    *,
    store: SQLiteStateStore,
    paths: AppPaths,
    root: Path,
    target: Path,
    clock: MutableClock,
) -> QuarantineEntry:
    cleanup_manifest = manifest(root, target, created_at=clock.value)
    cleanup_plan = QuarantinePlanner((root,), clock=clock).create_plan(cleanup_manifest)
    store.save_quarantine_plan(cleanup_plan)
    receipt = QuarantineExecutor(store, paths, actor="test-user", clock=clock).execute(
        cleanup_plan.plan_id,
        expected_digest=cleanup_plan.digest,
    )
    entry = store.get_quarantine_entry(receipt.entry_id)
    assert entry is not None
    return entry


def test_quarantine_entry_listing_is_newest_first_and_bounded(tmp_path: Path) -> None:
    clock = MutableClock()
    paths = app_paths(tmp_path)
    store = initialized_store(paths, clock)
    root = tmp_path / "approved"
    root.mkdir(mode=0o700)
    entries = []
    for index in range(2):
        target = root / f"artifact-{index}.bin"
        target.write_bytes(f"owned-{index}".encode())
        entries.append(
            quarantine_file(
                store=store,
                paths=paths,
                root=root,
                target=target,
                clock=clock,
            )
        )
        clock.value += timedelta(seconds=1)

    listed = store.list_quarantine_entries(limit=1)

    assert [listing.entry.entry_id for listing in listed] == [entries[1].entry_id]

    with pytest.raises(ValueError, match="limit"):
        store.list_quarantine_entries(limit=0)
    with pytest.raises(ValueError, match="limit"):
        store.list_quarantine_entries(limit=501)


def test_quarantine_entry_listing_uses_authoritative_status(tmp_path: Path) -> None:
    clock = MutableClock()
    paths, store, _, cleanup_plan, _, _ = plan_file(tmp_path, clock=clock)
    receipt = QuarantineExecutor(store, paths, actor="test-user", clock=clock).execute(
        cleanup_plan.plan_id, expected_digest=cleanup_plan.digest
    )
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE quarantine_entries SET status = ? WHERE entry_id = ?",
            (QuarantineState.RESTORED.value, receipt.entry_id),
        )

    listed = store.list_quarantine_entries()

    assert len(listed) == 1
    assert listed[0].entry.state is QuarantineState.RESTORED


def test_quarantine_entry_listing_omits_nonterminal_journal_rows(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    paths, store, _, cleanup_plan, _, _ = plan_file(tmp_path, clock=clock)
    receipt = QuarantineExecutor(store, paths, actor="test-user", clock=clock).execute(
        cleanup_plan.plan_id, expected_digest=cleanup_plan.digest
    )
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE quarantine_entries SET status = ? WHERE entry_id = ?",
            (QuarantineState.RUNNING.value, receipt.entry_id),
        )

    assert store.list_quarantine_entries() == ()


def test_default_service_quarantine_list_exposes_only_safe_terminal_state(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    paths, store, _, cleanup_plan, _, _ = plan_file(tmp_path, clock=clock)
    receipt = QuarantineExecutor(store, paths, actor="test-user", clock=clock).execute(
        cleanup_plan.plan_id, expected_digest=cleanup_plan.digest
    )
    entry = store.get_quarantine_entry(receipt.entry_id)
    assert entry is not None
    service = build_default_service(paths=paths)

    response = service.dispatch(
        RequestEnvelope(
            protocol_version=PROTOCOL_VERSION,
            request_id=uuid4(),
            method=Method.QUARANTINE_LIST.value,
            payload={"limit": 100},
        ),
        context=RequestContext(
            client=ClientKind.CONTROLLER,
            capability=Capability.READ,
            local_control=True,
        ),
    )

    assert response.ok is True
    assert response.result is not None
    result = response.result.model_dump(mode="json")
    assert result == {
        "entries": [
            {
                "entry_id": entry.entry_id,
                "agent_id": entry.agent_id,
                "resource_type": "file",
                "state": "quarantined",
                "restorable": True,
                "created_at": entry.created_at.isoformat(),
                "updated_at": entry.updated_at.isoformat(),
            }
        ],
        "next_cursor": None,
    }
    encoded = json.dumps(result, sort_keys=True)
    assert str(entry.original_path) not in encoded
    assert str(entry.quarantine_path) not in encoded
    assert entry.digest not in encoded


@pytest.mark.parametrize(
    ("stored_state", "public_state", "restorable"),
    [
        (QuarantineState.PARTIAL, "partial", False),
        (QuarantineState.INTERRUPTED, "interrupted", False),
        (QuarantineState.RESTORED, "restored", False),
    ],
)
def test_default_service_quarantine_list_maps_terminal_states(
    tmp_path: Path,
    stored_state: QuarantineState,
    public_state: str,
    restorable: bool,
) -> None:
    clock = MutableClock()
    paths, store, _, cleanup_plan, _, _ = plan_file(tmp_path, clock=clock)
    receipt = QuarantineExecutor(store, paths, actor="test-user", clock=clock).execute(
        cleanup_plan.plan_id, expected_digest=cleanup_plan.digest
    )
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE quarantine_entries SET status = ? WHERE entry_id = ?",
            (stored_state.value, receipt.entry_id),
        )
    response = build_default_service(paths=paths).dispatch(
        RequestEnvelope(
            protocol_version=PROTOCOL_VERSION,
            request_id=uuid4(),
            method=Method.QUARANTINE_LIST.value,
            payload={},
        ),
        context=RequestContext(
            client=ClientKind.CONTROLLER,
            capability=Capability.READ,
            local_control=True,
        ),
    )

    assert response.ok is True
    assert response.result is not None
    entries = response.result.model_dump(mode="json")["entries"]
    assert len(entries) == 1
    assert entries[0]["state"] == public_state
    assert entries[0]["restorable"] is restorable


def _clone_quarantine_entry(
    source: QuarantineEntry,
    *,
    index: int,
    timestamp: datetime,
) -> QuarantineEntry:
    updates = {
        "entry_id": f"paged-entry-{index:04d}",
        "plan_id": f"paged-plan-{index:04d}",
        "created_at": timestamp,
        "updated_at": timestamp,
        "retention_until": timestamp + timedelta(days=30),
    }
    unsigned = source.model_copy(update={**updates, "digest": "0" * 64})
    digest = hashlib.sha256(
        json.dumps(
            unsigned.immutable_fields(),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    return source.model_copy(update={**updates, "digest": digest})


def test_default_service_quarantine_list_paginates_beyond_five_hundred(
    tmp_path: Path, request: pytest.FixtureRequest
) -> None:
    clock = MutableClock()
    paths, store, _, cleanup_plan, _, _ = plan_file(tmp_path, clock=clock)
    receipt = QuarantineExecutor(store, paths, actor="test-user", clock=clock).execute(
        cleanup_plan.plan_id, expected_digest=cleanup_plan.digest
    )
    source = store.get_quarantine_entry(receipt.entry_id)
    assert source is not None
    clones = [
        _clone_quarantine_entry(
            source,
            index=index,
            timestamp=NOW + timedelta(seconds=index + 1),
        )
        for index in range(500)
    ]
    with sqlite3.connect(store.database_path) as connection:
        connection.executemany(
            "INSERT INTO quarantine_entries("
            "entry_id, state_json, created_at, plan_id, status, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            [
                (
                    entry.entry_id,
                    entry.model_dump_json(),
                    entry.created_at.isoformat(),
                    entry.plan_id,
                    entry.state.value,
                    entry.updated_at.isoformat(),
                )
                for entry in clones
            ],
        )
    service = build_default_service(paths=paths)
    request.addfinalizer(service.close)
    context = RequestContext(
        client=ClientKind.CONTROLLER,
        capability=Capability.READ,
        local_control=True,
    )

    first = service.dispatch(
        RequestEnvelope(
            protocol_version=PROTOCOL_VERSION,
            request_id=uuid4(),
            method=Method.QUARANTINE_LIST.value,
            payload={"limit": 500},
        ),
        context=context,
    )
    assert first.ok is True
    assert first.result is not None
    first_page = first.result.model_dump(mode="json")
    assert len(first_page["entries"]) == 500
    assert first_page["next_cursor"] is not None

    second = service.dispatch(
        RequestEnvelope(
            protocol_version=PROTOCOL_VERSION,
            request_id=uuid4(),
            method=Method.QUARANTINE_LIST.value,
            payload={"limit": 500, "cursor": first_page["next_cursor"]},
        ),
        context=context,
    )
    assert second.ok is True
    assert second.result is not None
    second_page = second.result.model_dump(mode="json")
    assert len(second_page["entries"]) == 1
    assert second_page["next_cursor"] is None
    first_ids = {entry["entry_id"] for entry in first_page["entries"]}
    second_ids = {entry["entry_id"] for entry in second_page["entries"]}
    assert first_ids.isdisjoint(second_ids)
    assert len(first_ids | second_ids) == 501


def test_quarantine_cursor_is_stable_when_boundary_entry_is_updated(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    paths, store, _, cleanup_plan, _, _ = plan_file(tmp_path, clock=clock)
    receipt = QuarantineExecutor(store, paths, actor="test-user", clock=clock).execute(
        cleanup_plan.plan_id, expected_digest=cleanup_plan.digest
    )
    source = store.get_quarantine_entry(receipt.entry_id)
    assert source is not None
    clones = [
        _clone_quarantine_entry(
            source,
            index=index,
            timestamp=NOW + timedelta(seconds=index + 1),
        )
        for index in range(2)
    ]
    with sqlite3.connect(store.database_path) as connection:
        connection.executemany(
            "INSERT INTO quarantine_entries("
            "entry_id, state_json, created_at, plan_id, status, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            [
                (
                    entry.entry_id,
                    entry.model_dump_json(),
                    entry.created_at.isoformat(),
                    entry.plan_id,
                    entry.state.value,
                    entry.updated_at.isoformat(),
                )
                for entry in clones
            ],
        )

    first_page = store.list_quarantine_entries(limit=2)
    assert [listing.entry.entry_id for listing in first_page] == [
        "paged-entry-0001",
        "paged-entry-0000",
    ]
    cursor = first_page[-1].entry.entry_id
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE quarantine_entries SET updated_at = ? WHERE entry_id = ?",
            ((NOW + timedelta(days=1)).isoformat(), cursor),
        )

    second_page = store.list_quarantine_entries(limit=2, cursor=cursor)

    assert [listing.entry.entry_id for listing in second_page] == [source.entry_id]


def test_default_service_quarantine_list_reports_live_restore_claim(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    paths, store, _, cleanup_plan, _, _ = plan_file(tmp_path, clock=clock)
    receipt = QuarantineExecutor(store, paths, actor="test-user", clock=clock).execute(
        cleanup_plan.plan_id, expected_digest=cleanup_plan.digest
    )
    store.claim_quarantine_restore(receipt.entry_id)

    response = build_default_service(paths=paths).dispatch(
        RequestEnvelope(
            protocol_version=PROTOCOL_VERSION,
            request_id=uuid4(),
            method=Method.QUARANTINE_LIST.value,
            payload={},
        ),
        context=RequestContext(
            client=ClientKind.CONTROLLER,
            capability=Capability.READ,
            local_control=True,
        ),
    )

    assert response.ok is True
    assert response.result is not None
    entries = response.result.model_dump(mode="json")["entries"]
    assert len(entries) == 1
    assert entries[0]["state"] == "restoring"
    assert entries[0]["restorable"] is False


@pytest.mark.parametrize(
    "state",
    [QuarantineState.PARTIAL, QuarantineState.INTERRUPTED, QuarantineState.RESTORED],
)
def test_restore_claim_rejects_nonrestorable_terminal_state(
    tmp_path: Path,
    state: QuarantineState,
) -> None:
    clock = MutableClock()
    paths, store, _, cleanup_plan, _, _ = plan_file(tmp_path, clock=clock)
    receipt = QuarantineExecutor(store, paths, actor="test-user", clock=clock).execute(
        cleanup_plan.plan_id, expected_digest=cleanup_plan.digest
    )
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE quarantine_entries SET status = ? WHERE entry_id = ?",
            (state.value, receipt.entry_id),
        )

    with pytest.raises(PlanClaimError, match="not restoreable"):
        store.claim_quarantine_restore(receipt.entry_id)


def legacy_v5_plan(plan: object) -> tuple[str, str]:
    payload = plan.model_dump(mode="json")  # type: ignore[attr-defined]
    payload.pop("manifest_created_at")
    payload.pop("manifest_expires_at")
    immutable = {key: value for key, value in payload.items() if key not in {"digest", "state"}}
    digest = hashlib.sha256(
        json.dumps(
            immutable,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    payload["digest"] = digest
    return json.dumps(payload, sort_keys=True, separators=(",", ":")), digest


def create_schema_v5_database(paths: AppPaths) -> SQLiteStateStore:
    store = SQLiteStateStore(paths, clock=MutableClock(), session_id="v5-upgrade")
    store._security_backend.prepare_state_directory(paths.state_dir)
    with sqlite3.connect(store.database_path) as connection:
        SQLiteStateStore._ensure_version_table(connection)
        for version in range(1, 6):
            SQLiteStateStore._apply_migration(connection, version)
            connection.execute(
                "INSERT INTO schema_versions(version, applied_at) VALUES (?, ?)",
                (version, "2026-08-12T12:00:00.000000Z"),
            )
        connection.execute("PRAGMA user_version = 5")
    store._security_backend.secure_database(store.database_path, allow_missing=False)
    return store


def create_schema_v6_database(paths: AppPaths) -> SQLiteStateStore:
    """Build the released v6 shape, before legacy classification existed."""
    store = create_schema_v5_database(paths)
    with sqlite3.connect(store.database_path) as connection:
        for statement in (
            "ALTER TABLE quarantine_entries ADD COLUMN restore_claim_owner TEXT",
            "ALTER TABLE quarantine_entries ADD COLUMN restore_claim_owner_pid INTEGER",
            "ALTER TABLE quarantine_entries ADD COLUMN restore_claim_owner_create_time REAL",
        ):
            connection.execute(statement)
        connection.execute(
            "INSERT INTO schema_versions(version, applied_at) VALUES (?, ?)",
            (6, "2026-08-12T12:00:00.000000Z"),
        )
        connection.execute("PRAGMA user_version = 6")
    store._security_backend.secure_database(store.database_path, allow_missing=False)
    return store


def legacy_succeeded_fixture(
    tmp_path: Path,
    *,
    database_factory: Callable[[AppPaths], SQLiteStateStore] = (create_schema_v5_database),
) -> tuple[AppPaths, SQLiteStateStore, object, object, Path]:
    paths = app_paths(tmp_path)
    root = tmp_path / "approved"
    root.mkdir()
    target = root / "artifact.txt"
    target.write_bytes(b"legacy quarantined material")
    plan = QuarantinePlanner((root,), clock=MutableClock()).create_plan(manifest(root, target))
    raw_plan, legacy_digest = legacy_v5_plan(plan)
    store = database_factory(paths)
    executor = QuarantineExecutor(store, paths, actor="test", clock=MutableClock())
    entry = executor._entry_for_plan(plan, "legacy-entry", NOW)
    namespace = executor._prepare_graveyard(entry.entry_id)
    quarantine_path = namespace / target.name
    os.replace(target, quarantine_path)
    entry = entry.model_copy(update={"state": QuarantineState.SUCCEEDED})
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "INSERT INTO quarantine_plans("
            "plan_id, digest, plan_json, status, phase, created_at, expires_at, "
            "finished_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                plan.plan_id,
                legacy_digest,
                raw_plan,
                QuarantineState.SUCCEEDED.value,
                "succeeded",
                "2026-08-12T12:00:00.000000Z",
                "2026-08-12T12:00:30.000000Z",
                "2026-08-12T12:00:01.000000Z",
            ),
        )
        connection.execute(
            "INSERT INTO quarantine_entries("
            "entry_id, state_json, created_at, plan_id, status, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                entry.entry_id,
                json.dumps(
                    entry.model_dump(mode="json"),
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                "2026-08-12T12:00:00.000000Z",
                plan.plan_id,
                QuarantineState.SUCCEEDED.value,
                "2026-08-12T12:00:01.000000Z",
            ),
        )
    store.initialize(now=NOW)
    return paths, store, plan, entry, target


def test_file_quarantine_and_restore_preserves_identity_and_sha256(
    tmp_path: Path,
) -> None:
    content = b"only this test owns these bytes"
    clock = MutableClock()
    paths, store, _, cleanup_plan, _, target = plan_file(tmp_path, content=content, clock=clock)
    expected_hash = hashlib.sha256(content).hexdigest()
    executor = QuarantineExecutor(store, paths, actor="test-user", clock=clock)

    receipt = executor.execute(
        cleanup_plan.plan_id,
        expected_digest=cleanup_plan.digest,
    )

    assert receipt.result is QuarantineResult.QUARANTINED
    assert receipt.target_hash == cleanup_plan.target_hash
    assert target.exists() is False
    entry = store.get_quarantine_entry(receipt.entry_id)
    assert entry is not None
    assert entry.state is QuarantineState.SUCCEEDED
    assert entry.fingerprint.sha256 == expected_hash
    assert Path(entry.quarantine_path).read_bytes() == content

    restore = executor.restore(entry.entry_id)

    assert restore.result is QuarantineResult.RESTORED
    assert target.read_bytes() == content
    assert hashlib.sha256(target.read_bytes()).hexdigest() == expected_hash
    restored = store.get_quarantine_entry(entry.entry_id)
    assert restored is not None
    assert restored.state is QuarantineState.RESTORED
    already = executor.restore(entry.entry_id)
    repeated = executor.restore(entry.entry_id)
    assert already.result is QuarantineResult.ALREADY_RESTORED
    assert repeated.receipt_id == already.receipt_id


def test_already_restored_revalidates_physical_content(tmp_path: Path) -> None:
    clock = MutableClock()
    paths, store, _, cleanup_plan, _, target = plan_file(tmp_path, clock=clock)
    executor = QuarantineExecutor(store, paths, actor="test", clock=clock)
    quarantined = executor.execute(cleanup_plan.plan_id, expected_digest=cleanup_plan.digest)
    assert executor.restore(quarantined.entry_id).result is QuarantineResult.RESTORED
    target.write_bytes(b"changed after restore")

    result = executor.restore(quarantined.entry_id)

    assert result.result is QuarantineResult.FAILED
    assert target.read_bytes() == b"changed after restore"


def test_restore_rechecks_authoritative_registration_before_move(tmp_path: Path) -> None:
    clock = MutableClock()
    paths, store, cleanup_manifest, cleanup_plan, _, target = plan_file(tmp_path, clock=clock)
    executor = QuarantineExecutor(store, paths, actor="test-user", clock=clock)
    quarantine = executor.execute(
        cleanup_plan.plan_id,
        expected_digest=cleanup_plan.digest,
    )
    entry = store.get_quarantine_entry(quarantine.entry_id)
    assert entry is not None
    REGISTRY.unregister(cleanup_manifest)

    restore = executor.restore(entry.entry_id)

    assert restore.result is QuarantineResult.FAILED
    assert not target.exists()
    assert Path(entry.quarantine_path).exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows owner SIDs are platform-specific")
def test_windows_fingerprint_uses_canonical_owner_sid(tmp_path: Path) -> None:
    _, _, _, cleanup_plan, _, _ = plan_file(tmp_path)

    assert cleanup_plan.fingerprint.owner.startswith("S-")
    assert cleanup_plan.root_chain
    assert all(component.owner.startswith("S-") for component in cleanup_plan.root_chain)


@pytest.mark.skipif(os.name != "nt", reason="Windows ACLs are platform-specific")
def test_windows_approved_root_rejects_everyone_write_acl(tmp_path: Path) -> None:
    root = tmp_path / "approved"
    root.mkdir()
    WindowsPermissionBackend().restrict(root)
    target = root / "artifact.bin"
    target.write_bytes(b"test")
    granted = subprocess.run(
        ["icacls", str(root), "/grant", "*S-1-1-0:(OI)(CI)M"],
        capture_output=True,
        text=True,
        check=False,
    )
    if granted.returncode != 0:
        pytest.skip(f"ACL modification unavailable: {granted.stderr.strip()}")
    try:
        with pytest.raises(CleanupRejectedError, match="ACL|access"):
            _QuarantinePlanner(
                (root,), registration_resolver=REGISTRY, clock=MutableClock()
            ).create_plan(manifest(root, target))
    finally:
        subprocess.run(
            ["icacls", str(root), "/remove:g", "*S-1-1-0"],
            capture_output=True,
            text=True,
            check=False,
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows ACLs are platform-specific")
def test_windows_approved_root_rejects_interactive_users_modify_acl(
    tmp_path: Path,
) -> None:
    root = tmp_path / "approved"
    root.mkdir()
    WindowsPermissionBackend().restrict(root)
    target = root / "artifact.bin"
    target.write_bytes(b"test")
    interactive_users = "*S-1-5-4"
    granted = subprocess.run(
        ["icacls", str(root), "/grant", f"{interactive_users}:(OI)(CI)M"],
        capture_output=True,
        text=True,
        check=False,
    )
    if granted.returncode != 0:
        pytest.skip(f"ACL modification unavailable: {granted.stderr.strip()}")
    try:
        with pytest.raises(CleanupRejectedError, match="ACL|access"):
            _QuarantinePlanner(
                (root,), registration_resolver=REGISTRY, clock=MutableClock()
            ).create_plan(manifest(root, target))
    finally:
        subprocess.run(
            ["icacls", str(root), "/remove:g", interactive_users],
            capture_output=True,
            text=True,
            check=False,
        )


@pytest.mark.parametrize(
    "target_factory",
    [
        lambda root, tmp: Path("relative.txt"),
        lambda root, tmp: root / "sub" / ".." / "artifact.txt",
        lambda root, tmp: root,
        lambda root, tmp: tmp / "approved-sibling" / "artifact.txt",
        lambda root, tmp: tmp / "outside.txt",
        lambda root, tmp: root / "*.txt",
    ],
    ids=("relative", "dotdot", "root", "sibling-prefix", "outside", "glob"),
)
def test_planner_rejects_unsafe_path_forms(
    tmp_path: Path,
    target_factory: object,
) -> None:
    root = tmp_path / "approved"
    root.mkdir(mode=0o700)
    sibling = tmp_path / "approved-sibling"
    sibling.mkdir()
    (sibling / "artifact.txt").write_text("test")
    (tmp_path / "outside.txt").write_text("test")
    target = target_factory(root, tmp_path)  # type: ignore[operator]

    with pytest.raises(CleanupRejectedError):
        QuarantinePlanner((root,)).create_plan(manifest(root, target))


@pytest.mark.skipif(os.name != "nt", reason="Windows path syntax is platform-specific")
@pytest.mark.parametrize(
    "raw",
    (
        r"\\server\share\artifact.txt",
        r"\\?\C:\artifact.txt",
        r"\\.\C:\artifact.txt",
        r"C:\artifact.txt:secret",
    ),
)
def test_windows_network_device_and_ads_paths_are_rejected(tmp_path: Path, raw: str) -> None:
    root = tmp_path / "approved"
    root.mkdir()

    with pytest.raises(CleanupRejectedError):
        QuarantinePlanner((root,), platform_name="windows").create_plan(manifest(root, Path(raw)))


def test_unmanaged_and_listening_port_declarations_never_gain_cleanup_authority(
    tmp_path: Path,
) -> None:
    root = tmp_path / "approved"
    root.mkdir()
    target = root / "artifact.txt"
    target.write_text("test")

    with pytest.raises(ValueError):
        manifest(root, target, managed=False)
    with pytest.raises(CleanupRejectedError):
        QuarantinePlanner((root,)).create_plan(
            manifest(root, target, resource_type=ResourceType.LISTENING_PORT)
        )


def test_planner_and_executor_require_authoritative_registration_resolver(
    tmp_path: Path,
) -> None:
    paths = app_paths(tmp_path)
    store = initialized_store(paths, MutableClock())
    root = tmp_path / "approved"
    root.mkdir()

    with pytest.raises(TypeError):
        _QuarantinePlanner((root,))
    with pytest.raises(TypeError):
        _QuarantineExecutor(store, paths, actor="test")


def test_manifest_must_be_current_and_exactly_registered(tmp_path: Path) -> None:
    root = tmp_path / "approved"
    root.mkdir()
    target = root / "artifact.bin"
    target.write_bytes(b"test")
    future = CleanupManifest.create(
        agent_id="test-agent",
        creating_identity=IDENTITY,
        approved_root=root,
        target=target,
        resource_type=ResourceType.FILE,
        declaration_source="sdk",
        managed=True,
        created_at=NOW + timedelta(seconds=1),
    )
    REGISTRY.register(future)
    with pytest.raises(CleanupRejectedError, match="future"):
        QuarantinePlanner((root,), clock=MutableClock()).create_plan(future)

    original = manifest(root, target)
    clone = CleanupManifest.create(
        agent_id=original.agent_id,
        creating_identity=original.creating_identity,
        approved_root=original.approved_root,
        target=original.target,
        resource_type=original.resource_type,
        declaration_source=original.declaration_source,
        managed=True,
        created_at=original.created_at,
    )
    with pytest.raises(CleanupRejectedError, match="registration"):
        QuarantinePlanner((root,), clock=MutableClock()).create_plan(clone)


def test_real_advancing_clocks_preserve_exact_manifest_authority(
    tmp_path: Path,
) -> None:
    paths = app_paths(tmp_path)
    store = SQLiteStateStore(paths)
    store.initialize(now=datetime.now(UTC))
    root = tmp_path / "approved"
    root.mkdir()
    target = root / "artifact.txt"
    target.write_text("real clock")
    cleanup_manifest = CleanupManifest.create(
        agent_id="managed-agent",
        creating_identity=IDENTITY,
        approved_root=root,
        target=target,
        resource_type=ResourceType.FILE,
        declaration_source="sdk",
        managed=True,
    )
    REGISTRY.register(cleanup_manifest)
    cleanup_plan = QuarantinePlanner((root,)).create_plan(cleanup_manifest)
    store.save_quarantine_plan(cleanup_plan)

    assert cleanup_plan.manifest_created_at == cleanup_manifest.created_at
    assert cleanup_plan.manifest_expires_at == cleanup_manifest.expires_at
    receipt = QuarantineExecutor(store, paths, actor="test").execute(
        cleanup_plan.plan_id,
        expected_digest=cleanup_plan.digest,
    )

    assert receipt.result is QuarantineResult.QUARANTINED


def test_schema_v5_migration_classifies_legacy_and_corrupt_plans_idempotently(
    tmp_path: Path,
) -> None:
    paths = app_paths(tmp_path)
    root = tmp_path / "approved"
    root.mkdir()
    target = root / "artifact.txt"
    target.write_text("legacy")
    planner = QuarantinePlanner((root,), clock=MutableClock())
    planned = planner.create_plan(manifest(root, target))
    running = planner.create_plan(manifest(root, target))
    planned_json, planned_digest = legacy_v5_plan(planned)
    running_json, running_digest = legacy_v5_plan(running)
    corrupt_json = "{preserve-corrupt-json"
    store = create_schema_v5_database(paths)
    with sqlite3.connect(store.database_path) as connection:
        for plan_id, digest, raw_json, status, phase in (
            (
                planned.plan_id,
                planned_digest,
                planned_json,
                QuarantineState.PLANNED.value,
                "planned",
            ),
            (
                running.plan_id,
                running_digest,
                running_json,
                QuarantineState.RUNNING.value,
                "running",
            ),
            (
                "corrupt-legacy-plan",
                "f" * 64,
                corrupt_json,
                QuarantineState.PLANNED.value,
                "planned",
            ),
        ):
            connection.execute(
                "INSERT INTO quarantine_plans("
                "plan_id, digest, plan_json, status, phase, created_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    plan_id,
                    digest,
                    raw_json,
                    status,
                    phase,
                    "2026-08-12T12:00:00.000000Z",
                    "2026-08-12T12:00:30.000000Z",
                ),
            )

    store.initialize(now=NOW)
    store.initialize(now=NOW)

    with sqlite3.connect(store.database_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = {
            str(row["plan_id"]): row
            for row in connection.execute(
                "SELECT plan_id, digest, plan_json, status, phase, "
                "legacy_recovery_reason FROM quarantine_plans"
            )
        }
    assert rows[planned.plan_id]["status"] == QuarantineState.INTERRUPTED.value
    assert rows[running.plan_id]["status"] == QuarantineState.INTERRUPTED.value
    assert rows[planned.plan_id]["phase"] == "legacy_incompatible"
    assert rows[running.plan_id]["phase"] == "legacy_incompatible"
    assert rows[planned.plan_id]["plan_json"] == planned_json
    assert rows[planned.plan_id]["digest"] == planned_digest
    assert rows[running.plan_id]["plan_json"] == running_json
    assert rows[running.plan_id]["digest"] == running_digest
    assert rows["corrupt-legacy-plan"]["plan_json"] == corrupt_json
    assert rows["corrupt-legacy-plan"]["digest"] == "f" * 64
    assert (
        store.get_legacy_quarantine_reason(planned.plan_id)
        is quarantine_module.LegacyRecoveryReason.MISSING_MANIFEST_AUTHORITY
    )
    assert (
        store.get_legacy_quarantine_reason("corrupt-legacy-plan")
        is quarantine_module.LegacyRecoveryReason.CORRUPT_PLAN_JSON
    )
    with pytest.raises(PlanClaimError):
        QuarantineExecutor(store, paths, actor="test", clock=MutableClock()).execute(
            planned.plan_id,
            expected_digest=planned_digest,
        )
    assert target.read_text() == "legacy"


def test_schema_v5_succeeded_entry_has_explicit_digest_bound_restore(
    tmp_path: Path,
) -> None:
    paths, store, plan, entry, target = legacy_succeeded_fixture(tmp_path)
    executor = QuarantineExecutor(store, paths, actor="test", clock=MutableClock())

    with pytest.raises(QuarantineError, match="digest"):
        executor.restore_legacy(
            entry.entry_id,
            expected_entry_digest="0" * 64,
        )
    assert not target.exists()
    assert Path(entry.quarantine_path).exists()

    receipt = executor.restore_legacy(
        entry.entry_id,
        expected_entry_digest=entry.digest,
    )

    assert receipt.result is QuarantineResult.RESTORED
    assert target.read_bytes() == b"legacy quarantined material"
    assert not Path(entry.quarantine_path).exists()
    replay = executor.restore_legacy(
        entry.entry_id,
        expected_entry_digest=entry.digest,
    )
    assert replay.result is QuarantineResult.ALREADY_RESTORED
    assert (
        executor.restore_legacy(
            entry.entry_id,
            expected_entry_digest=entry.digest,
        ).receipt_id
        == replay.receipt_id
    )
    assert (
        store.get_legacy_quarantine_reason(
            plan.plan_id  # type: ignore[attr-defined]
        )
        is quarantine_module.LegacyRecoveryReason.MISSING_MANIFEST_AUTHORITY
    )


def test_schema_v5_explicit_restore_never_overwrites_destination(
    tmp_path: Path,
) -> None:
    paths, store, _, entry, target = legacy_succeeded_fixture(tmp_path)
    target.write_bytes(b"new owner material")

    receipt = QuarantineExecutor(
        store,
        paths,
        actor="test",
        clock=MutableClock(),
    ).restore_legacy(
        entry.entry_id,
        expected_entry_digest=entry.digest,
    )

    assert receipt.result is QuarantineResult.FAILED
    assert target.read_bytes() == b"new owner material"
    assert Path(entry.quarantine_path).read_bytes() == b"legacy quarantined material"


def test_schema_v5_explicit_restore_revalidates_graveyard_fingerprint(
    tmp_path: Path,
) -> None:
    paths, store, _, entry, target = legacy_succeeded_fixture(tmp_path)
    Path(entry.quarantine_path).write_bytes(b"changed in Graveyard")

    receipt = QuarantineExecutor(
        store,
        paths,
        actor="test",
        clock=MutableClock(),
    ).restore_legacy(
        entry.entry_id,
        expected_entry_digest=entry.digest,
    )

    assert receipt.result is QuarantineResult.FAILED
    assert not target.exists()
    assert Path(entry.quarantine_path).read_bytes() == b"changed in Graveyard"


def test_released_schema_v6_upgrades_to_v7_and_restores_legacy_entry(
    tmp_path: Path,
) -> None:
    paths, store, plan, entry, target = legacy_succeeded_fixture(
        tmp_path,
        database_factory=create_schema_v6_database,
    )

    assert store.get_workflow_plan("quarantine_restore", "missing-fixture-plan") is None
    with sqlite3.connect(store.database_path) as connection:
        connection.row_factory = sqlite3.Row
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        columns = {
            str(row["name"]) for row in connection.execute("PRAGMA table_info(quarantine_plans)")
        }
        preserved = connection.execute(
            "SELECT plan_json, digest FROM quarantine_plans WHERE plan_id = ?",
            (plan.plan_id,),  # type: ignore[attr-defined]
        ).fetchone()
    assert version == store.schema_version
    assert "legacy_recovery_reason" in columns
    with sqlite3.connect(store.database_path) as connection:
        connection.row_factory = sqlite3.Row
        SQLiteStateStore._apply_migration(connection, 7)
        SQLiteStateStore._apply_migration(connection, 7)
        assert (
            sum(
                row["name"] == "legacy_recovery_reason"
                for row in connection.execute("PRAGMA table_info(quarantine_plans)")
            )
            == 1
        )

    receipt = QuarantineExecutor(
        store,
        paths,
        actor="test",
        clock=MutableClock(),
    ).restore_legacy(
        entry.entry_id,
        expected_entry_digest=entry.digest,
    )

    assert receipt.result is QuarantineResult.RESTORED
    assert target.read_bytes() == b"legacy quarantined material"
    with sqlite3.connect(store.database_path) as connection:
        connection.row_factory = sqlite3.Row
        after = connection.execute(
            "SELECT plan_json, digest FROM quarantine_plans WHERE plan_id = ?",
            (plan.plan_id,),  # type: ignore[attr-defined]
        ).fetchone()
        journal = connection.execute(
            "SELECT status, state_json FROM quarantine_entries WHERE entry_id = ?",
            (entry.entry_id,),
        ).fetchone()
        receipt_count = connection.execute(
            "SELECT COUNT(*) FROM quarantine_receipts WHERE entry_id = ?",
            (entry.entry_id,),
        ).fetchone()[0]
    assert tuple(after) == tuple(preserved)
    assert journal[0] == QuarantineState.RESTORED.value
    assert json.loads(str(journal[1]))["state"] == QuarantineState.RESTORED.value
    assert receipt_count == 1


def test_restore_preflights_journal_schema_before_physical_move(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    paths, store, _, cleanup_plan, _, target = plan_file(tmp_path, clock=clock)
    executor = QuarantineExecutor(store, paths, actor="test", clock=clock)
    quarantined = executor.execute(
        cleanup_plan.plan_id,
        expected_digest=cleanup_plan.digest,
    )
    entry = store.get_quarantine_entry(quarantined.entry_id)
    assert entry is not None
    with sqlite3.connect(store.database_path) as connection:
        connection.execute("DROP TABLE quarantine_receipts")

    with pytest.raises(Exception, match="journal|table|schema"):
        executor.restore(entry.entry_id)

    assert not target.exists()
    assert Path(entry.quarantine_path).read_bytes() == b"owned test material"
    with sqlite3.connect(store.database_path) as connection:
        claim_owner = connection.execute(
            "SELECT restore_claim_owner FROM quarantine_entries WHERE entry_id = ?",
            (entry.entry_id,),
        ).fetchone()[0]
    assert claim_owner is None


@pytest.mark.parametrize(
    "damage_sql",
    [
        "DROP TABLE audit_events",
        (
            "ALTER TABLE audit_events RENAME TO preserved_audit_events;"
            "CREATE TABLE audit_events ("
            "event_id TEXT PRIMARY KEY, correlation_id TEXT NOT NULL, "
            "event_type TEXT NOT NULL, created_at TEXT NOT NULL)"
        ),
    ],
    ids=("missing-audit-table", "missing-audit-column"),
)
def test_restore_preflights_audit_journal_before_physical_move(
    tmp_path: Path,
    damage_sql: str,
) -> None:
    clock = MutableClock()
    paths, store, _, cleanup_plan, _, target = plan_file(tmp_path, clock=clock)
    executor = QuarantineExecutor(store, paths, actor="test", clock=clock)
    quarantined = executor.execute(
        cleanup_plan.plan_id,
        expected_digest=cleanup_plan.digest,
    )
    entry = store.get_quarantine_entry(quarantined.entry_id)
    assert entry is not None
    with sqlite3.connect(store.database_path) as connection:
        before_entry = connection.execute(
            "SELECT state_json, status, restore_claim_owner "
            "FROM quarantine_entries WHERE entry_id = ?",
            (entry.entry_id,),
        ).fetchone()
        before_receipts = connection.execute(
            "SELECT receipt_id, receipt_json FROM quarantine_receipts ORDER BY receipt_id"
        ).fetchall()
        connection.executescript(damage_sql)

    with pytest.raises(QuarantineError, match="journal.*preflight"):
        executor.restore(entry.entry_id)

    assert not target.exists()
    assert Path(entry.quarantine_path).read_bytes() == b"owned test material"
    with sqlite3.connect(store.database_path) as connection:
        after_entry = connection.execute(
            "SELECT state_json, status, restore_claim_owner "
            "FROM quarantine_entries WHERE entry_id = ?",
            (entry.entry_id,),
        ).fetchone()
        after_receipts = connection.execute(
            "SELECT receipt_id, receipt_json FROM quarantine_receipts ORDER BY receipt_id"
        ).fetchall()
    assert after_entry == before_entry
    assert after_receipts == before_receipts


def test_restore_reconciles_post_move_journal_failure_without_second_move(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = MutableClock()
    paths, store, _, cleanup_plan, _, target = plan_file(tmp_path, clock=clock)
    executor = QuarantineExecutor(store, paths, actor="test", clock=clock)
    quarantined = executor.execute(
        cleanup_plan.plan_id,
        expected_digest=cleanup_plan.digest,
    )
    entry = store.get_quarantine_entry(quarantined.entry_id)
    assert entry is not None
    save_receipt = store.save_quarantine_receipt
    move_attempts = 0

    def count_move(_entry: object) -> None:
        nonlocal move_attempts
        move_attempts += 1

    def fail_journal(*_args: object, **_kwargs: object) -> None:
        raise sqlite3.OperationalError("synthetic restore journal failure")

    executor._before_restore = count_move
    monkeypatch.setattr(store, "save_quarantine_receipt", fail_journal)
    with pytest.raises(sqlite3.OperationalError, match="synthetic restore journal"):
        executor.restore(entry.entry_id)
    assert target.read_bytes() == b"owned test material"
    assert not Path(entry.quarantine_path).exists()

    monkeypatch.setattr(store, "save_quarantine_receipt", save_receipt)
    recovered = executor.restore(entry.entry_id)

    assert recovered.result is QuarantineResult.RESTORED
    assert move_attempts == 1
    restored = store.get_quarantine_entry(entry.entry_id)
    assert restored is not None
    assert restored.state is QuarantineState.RESTORED
    with sqlite3.connect(store.database_path) as connection:
        receipt_count, claim_owner = connection.execute(
            "SELECT COUNT(r.receipt_id), e.restore_claim_owner "
            "FROM quarantine_entries AS e "
            "LEFT JOIN quarantine_receipts AS r ON r.entry_id = e.entry_id "
            "AND r.operation = 'restore' "
            "WHERE e.entry_id = ? GROUP BY e.entry_id",
            (entry.entry_id,),
        ).fetchone()
    assert receipt_count == 1
    assert claim_owner is None


def test_completed_replay_validates_expected_digest(tmp_path: Path) -> None:
    clock = MutableClock()
    paths, store, _, cleanup_plan, _, _ = plan_file(tmp_path, clock=clock)
    executor = QuarantineExecutor(store, paths, actor="test", clock=clock)
    executor.execute(cleanup_plan.plan_id, expected_digest=cleanup_plan.digest)

    with pytest.raises(PlanClaimError, match="digest"):
        executor.execute(cleanup_plan.plan_id, expected_digest="0" * 64)


def test_quarantine_phase_updates_are_claim_owner_bound(tmp_path: Path) -> None:
    clock = MutableClock()
    paths, owner_store, _, cleanup_plan, _, _ = plan_file(tmp_path, clock=clock)
    owner_store.claim_quarantine_plan(cleanup_plan.plan_id, expected_digest=cleanup_plan.digest)
    other_store = SQLiteStateStore(paths, clock=clock, session_id="other-session")
    other_store.initialize(now=clock())

    with pytest.raises(Exception, match="owner"):
        other_store.update_quarantine_plan_phase(cleanup_plan.plan_id, "validating")
    foreign_receipt = QuarantineExecutor(other_store, paths, actor="test", clock=clock)._receipt(
        plan=cleanup_plan,
        entry_id=None,
        operation="quarantine",
        result=QuarantineResult.FAILED,
        started_at=clock(),
        message="foreign session",
    )
    with pytest.raises(Exception, match="owner|running"):
        other_store.finish_quarantine_plan(
            cleanup_plan.plan_id,
            state=QuarantineState.FAILED,
            receipt=foreign_receipt,
            entry=None,
        )
    with pytest.raises(Exception, match="phase"):
        owner_store.update_quarantine_plan_phase(cleanup_plan.plan_id, "renamed")


def test_plan_b_receipt_cannot_finish_plan_a(tmp_path: Path) -> None:
    clock = MutableClock()
    paths, store, _, plan_a, root, _ = plan_file(tmp_path, clock=clock)
    second = root / "second.bin"
    second.write_bytes(b"second")
    plan_b = QuarantinePlanner((root,), clock=clock).create_plan(manifest(root, second))
    store.save_quarantine_plan(plan_b)
    store.claim_quarantine_plan(plan_a.plan_id, expected_digest=plan_a.digest)
    receipt_b = QuarantineExecutor(store, paths, actor="test", clock=clock)._receipt(
        plan=plan_b,
        entry_id=None,
        operation="quarantine",
        result=QuarantineResult.FAILED,
        started_at=clock(),
        message="test receipt",
    )

    with pytest.raises(Exception, match="receipt|plan"):
        store.finish_quarantine_plan(
            plan_a.plan_id,
            state=QuarantineState.FAILED,
            receipt=receipt_b,
            entry=None,
        )

    forged = (
        QuarantineExecutor(store, paths, actor="test", clock=clock)
        ._receipt(
            plan=plan_a,
            entry_id=None,
            operation="quarantine",
            result=QuarantineResult.FAILED,
            started_at=clock(),
            message="forged root binding",
        )
        .model_copy(update={"root_hash": "0" * 64})
    )
    with pytest.raises(Exception, match="receipt|plan"):
        store.finish_quarantine_plan(
            plan_a.plan_id,
            state=QuarantineState.FAILED,
            receipt=forged,
            entry=None,
        )


def test_existing_quarantine_entry_immutable_binding_cannot_be_overwritten(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    paths, store, _, cleanup_plan, _, _ = plan_file(tmp_path, clock=clock)
    claimed = store.claim_quarantine_plan(
        cleanup_plan.plan_id,
        expected_digest=cleanup_plan.digest,
    )
    executor = QuarantineExecutor(store, paths, actor="test", clock=clock)
    original = executor._entry_for_plan(claimed, "journal-entry", clock())
    store.save_quarantine_entry(original)
    payload = original.model_dump(mode="python")
    forged_path = os.fspath(tmp_path / "forged-location" / "artifact.txt")
    payload["quarantine_path"] = forged_path
    payload["quarantine_path_hash"] = hashlib.sha256(
        f"quarantine\0{os.path.normcase(os.path.abspath(forged_path))}".encode()
    ).hexdigest()
    canonical_payload = original.model_dump(mode="json")
    canonical_payload["quarantine_path"] = forged_path
    canonical_payload["quarantine_path_hash"] = payload["quarantine_path_hash"]
    immutable = {
        key: value
        for key, value in canonical_payload.items()
        if key
        not in {
            "digest",
            "state",
            "updated_at",
            "receipt_ids",
            "restored_at",
        }
    }
    payload["digest"] = hashlib.sha256(
        json.dumps(
            immutable,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    forged = type(original).model_validate(payload)

    with pytest.raises(Exception, match="immutable|journal"):
        store.save_quarantine_entry(forged)

    assert store.get_quarantine_entry(original.entry_id) == original


def test_restore_claim_is_owner_bound_across_sessions(tmp_path: Path) -> None:
    clock = MutableClock()
    paths, store, _, cleanup_plan, _, target = plan_file(tmp_path, clock=clock)
    receipt = QuarantineExecutor(store, paths, actor="test", clock=clock).execute(
        cleanup_plan.plan_id,
        expected_digest=cleanup_plan.digest,
    )
    entry = store.get_quarantine_entry(receipt.entry_id)
    assert entry is not None
    store.claim_quarantine_restore(entry.entry_id)
    other = SQLiteStateStore(paths, clock=clock, session_id="other-restore-session")
    other.initialize(now=clock())

    with pytest.raises(PlanClaimError, match="restore owner is alive"):
        QuarantineExecutor(other, paths, actor="test", clock=clock).restore(entry.entry_id)

    assert not target.exists()
    assert Path(entry.quarantine_path).exists()


def test_planner_rejects_resource_missing_from_authoritative_registry(
    tmp_path: Path,
) -> None:
    root = tmp_path / "approved"
    root.mkdir()
    target = root / "artifact.txt"
    target.write_text("test")
    cleanup_manifest = manifest(root, target)
    REGISTRY.clear()

    with pytest.raises(CleanupRejectedError, match="registration"):
        QuarantinePlanner((root,), clock=MutableClock()).create_plan(cleanup_manifest)


def test_missing_target_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "approved"
    root.mkdir()

    with pytest.raises(CleanupRejectedError):
        QuarantinePlanner((root,)).create_plan(manifest(root, root / "missing"))


def test_symlink_target_and_ancestor_are_rejected(tmp_path: Path) -> None:
    root = tmp_path / "approved"
    root.mkdir()
    real = root / "real"
    real.mkdir()
    file = real / "artifact.txt"
    file.write_text("test")
    target_link = root / "file-link"
    ancestor_link = root / "dir-link"
    try:
        target_link.symlink_to(file)
        ancestor_link.symlink_to(real, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"symlink creation unavailable: {error}")

    planner = QuarantinePlanner((root,))
    with pytest.raises(CleanupRejectedError):
        planner.create_plan(manifest(root, target_link))
    with pytest.raises(CleanupRejectedError):
        planner.create_plan(manifest(root, ancestor_link / file.name))


def test_injectable_reparse_check_rejects_junction_target_and_ancestor(
    tmp_path: Path,
) -> None:
    root = tmp_path / "approved"
    root.mkdir()
    directory = root / "junction"
    directory.mkdir()
    target = directory / "artifact.txt"
    target.write_text("test")

    planner = QuarantinePlanner((root,), reparse_checker=lambda path, _stat: path == directory)
    with pytest.raises(CleanupRejectedError):
        planner.create_plan(manifest(root, target))


@pytest.mark.skipif(os.name != "nt", reason="Windows junctions are platform-specific")
def test_graveyard_destination_junction_swap_is_rejected_before_move(tmp_path: Path) -> None:
    clock = MutableClock()
    paths, store, _, cleanup_plan, root, target = plan_file(tmp_path, clock=clock)
    outside = tmp_path / "outside"
    outside.mkdir()
    untouched = outside / "untouched.txt"
    untouched.write_bytes(b"outside-must-survive")
    parked = paths.graveyard_dir.with_name("parked-graveyard")

    def swap_graveyard(_plan: object) -> None:
        paths.graveyard_dir.rename(parked)
        created = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(paths.graveyard_dir), str(outside)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert created.returncode == 0, created.stderr

    receipt = QuarantineExecutor(
        store,
        paths,
        actor="test",
        clock=clock,
        before_move=swap_graveyard,
    ).execute(cleanup_plan.plan_id, expected_digest=cleanup_plan.digest)
    try:
        assert receipt.result is QuarantineResult.FAILED
        assert target.read_bytes() == b"owned test material"
        assert untouched.read_bytes() == b"outside-must-survive"
        assert not list(parked.rglob(target.name))
    finally:
        if os.path.lexists(paths.graveyard_dir) and quarantine_module._is_reparse_point(
            paths.graveyard_dir.lstat()
        ):
            paths.graveyard_dir.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows destination reparse check")
def test_destination_redirect_check_is_repeated_after_final_hook(tmp_path: Path) -> None:
    clock = MutableClock()
    paths, store, _, cleanup_plan, _, target = plan_file(tmp_path, clock=clock)
    destination_redirected = False

    def check(path: Path, path_stat: os.stat_result) -> bool:
        return quarantine_module._is_reparse_point(path_stat) or (
            destination_redirected and path == paths.graveyard_dir
        )

    def redirect(_plan: object) -> None:
        nonlocal destination_redirected
        destination_redirected = True

    receipt = QuarantineExecutor(
        store,
        paths,
        actor="test",
        clock=clock,
        before_move=redirect,
        reparse_checker=check,
    ).execute(cleanup_plan.plan_id, expected_digest=cleanup_plan.digest)

    assert receipt.result is QuarantineResult.FAILED
    assert target.read_bytes() == b"owned test material"


@pytest.mark.skipif(os.name != "nt", reason="Windows namespace pinning is platform-specific")
def test_graveyard_namespace_cannot_be_rebound_after_pinning(tmp_path: Path) -> None:
    clock = MutableClock()
    paths, store, _, cleanup_plan, _, target = plan_file(tmp_path, clock=clock)

    def rebind(_plan: object) -> None:
        entry = store.get_quarantine_entry_for_plan(cleanup_plan.plan_id)
        assert entry is not None
        namespace = Path(entry.quarantine_path).parent
        with pytest.raises(PermissionError):
            namespace.rename(namespace.with_name("rebound-namespace"))

    receipt = QuarantineExecutor(
        store,
        paths,
        actor="test",
        clock=clock,
        before_move=rebind,
    ).execute(cleanup_plan.plan_id, expected_digest=cleanup_plan.digest)

    assert receipt.result is QuarantineResult.QUARANTINED
    assert not target.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows junctions are platform-specific")
def test_windows_junction_ancestor_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "approved"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "artifact.txt"
    target.write_text("test")
    junction = root / "junction"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
        check=False,
        capture_output=True,
        text=True,
    )
    if created.returncode != 0:
        pytest.skip(f"junction creation privilege unavailable: {created.stderr.strip()}")

    with pytest.raises(CleanupRejectedError):
        QuarantinePlanner((root,)).create_plan(manifest(root, junction / target.name))


@pytest.mark.skipif(os.name != "nt", reason="Windows junctions are platform-specific")
def test_final_junction_ancestor_swap_never_touches_outside_target(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    paths = app_paths(tmp_path)
    store = initialized_store(paths, clock)
    root = tmp_path / "approved"
    root.mkdir()
    parent = root / "parent"
    parent.mkdir()
    target = parent / "artifact.txt"
    target.write_text("declared")
    outside = tmp_path / "outside"
    outside.mkdir()
    outside_target = outside / target.name
    outside_target.write_text("outside-must-survive")
    cleanup_plan = QuarantinePlanner((root,), clock=clock).create_plan(manifest(root, target))
    store.save_quarantine_plan(cleanup_plan)
    parked = root / "parked"

    def swap_to_junction(_plan: object) -> None:
        os.rename(parent, parked)
        created = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(parent), str(outside)],
            check=False,
            capture_output=True,
            text=True,
        )
        if created.returncode != 0:
            pytest.skip(f"junction creation privilege unavailable: {created.stderr.strip()}")

    receipt = QuarantineExecutor(
        store,
        paths,
        actor="test",
        clock=clock,
        before_move=swap_to_junction,
    ).execute(cleanup_plan.plan_id, expected_digest=cleanup_plan.digest)
    try:
        assert receipt.result is QuarantineResult.FAILED
        assert outside_target.read_text() == "outside-must-survive"
        surviving_target = parked / target.name if parked.exists() else target
        assert surviving_target.read_text() == "declared"
    finally:
        parent_stat = os.lstat(parent) if os.path.lexists(parent) else None
        if parent_stat is not None and getattr(parent_stat, "st_file_attributes", 0) & getattr(
            stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0
        ):
            subprocess.run(
                ["cmd", "/c", "rmdir", str(parent)],
                check=True,
                capture_output=True,
            )


@pytest.mark.skipif(os.name != "nt", reason="Windows junctions are platform-specific")
def test_final_child_junction_swap_is_blocked_before_directory_move(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    paths = app_paths(tmp_path)
    store = initialized_store(paths, clock)
    root = tmp_path / "approved"
    root.mkdir()
    target = root / "tree"
    child = target / "child"
    child.mkdir(parents=True)
    inside = child / "inside.txt"
    inside.write_text("inside-must-survive")
    outside = tmp_path / "outside"
    outside.mkdir()
    outside_file = outside / "outside.txt"
    outside_file.write_text("outside-must-survive")
    cleanup_plan = QuarantinePlanner((root,), clock=clock).create_plan(
        manifest(root, target, resource_type=ResourceType.DIRECTORY)
    )
    store.save_quarantine_plan(cleanup_plan)
    parked = target / "parked-child"
    swap_attempted = False
    junction_created = False

    def swap_child_to_junction(_plan: object) -> None:
        nonlocal swap_attempted, junction_created
        swap_attempted = True
        os.rename(child, parked)
        created = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(child), str(outside)],
            check=False,
            capture_output=True,
            text=True,
        )
        if created.returncode != 0:
            pytest.skip(f"junction creation privilege unavailable: {created.stderr.strip()}")
        junction_created = True

    receipt = QuarantineExecutor(
        store,
        paths,
        actor="test",
        clock=clock,
        before_move=swap_child_to_junction,
    ).execute(cleanup_plan.plan_id, expected_digest=cleanup_plan.digest)
    entry = store.get_quarantine_entry(receipt.entry_id)
    try:
        assert receipt.result is QuarantineResult.FAILED
        assert swap_attempted
        assert not junction_created
        assert target.is_dir()
        assert inside.read_text() == "inside-must-survive"
        assert outside_file.read_text() == "outside-must-survive"
        assert not parked.exists()
        assert entry is not None
        assert not Path(entry.quarantine_path).exists()
    finally:
        tree = target
        if entry is not None and Path(entry.quarantine_path).exists():
            tree = Path(entry.quarantine_path)
        possible_child = tree / "child"
        child_stat = os.lstat(possible_child) if os.path.lexists(possible_child) else None
        if child_stat is not None and getattr(child_stat, "st_file_attributes", 0) & getattr(
            stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0
        ):
            subprocess.run(
                ["cmd", "/c", "rmdir", str(possible_child)],
                check=True,
                capture_output=True,
            )
        possible_parked = tree / "parked-child"
        if possible_parked.exists() and not possible_child.exists():
            os.rename(possible_parked, possible_child)
        if tree != target and tree.exists() and not target.exists():
            os.rename(tree, target)


@pytest.mark.skipif(os.name != "nt", reason="Windows handles are platform-specific")
def test_directory_execution_pins_every_descendant_handle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = MutableClock()
    paths = app_paths(tmp_path)
    store = initialized_store(paths, clock)
    root = tmp_path / "approved"
    root.mkdir()
    target = root / "tree"
    nested = target / "nested"
    nested.mkdir(parents=True)
    leaf = nested / "leaf.txt"
    leaf.write_text("leaf")
    cleanup_plan = QuarantinePlanner((root,), clock=clock).create_plan(
        manifest(root, target, resource_type=ResourceType.DIRECTORY)
    )
    store.save_quarantine_plan(cleanup_plan)
    opened: list[str] = []
    open_relative = quarantine_module._windows_open_relative_handle

    def recording_open(parent_handle: int, name: str, *, is_directory: bool, share: int) -> int:
        opened.append(name)
        return open_relative(
            parent_handle,
            name,
            is_directory=is_directory,
            share=share,
        )

    monkeypatch.setattr(quarantine_module, "_windows_open_relative_handle", recording_open)

    def stop_before_move(_plan: object) -> None:
        raise PermissionError("stop after pinning")

    receipt = QuarantineExecutor(
        store,
        paths,
        actor="test",
        clock=clock,
        before_move=stop_before_move,
    ).execute(cleanup_plan.plan_id, expected_digest=cleanup_plan.digest)

    assert receipt.result is QuarantineResult.FAILED
    assert nested.name in opened
    assert leaf.name in opened


@pytest.mark.skipif(os.name != "nt", reason="Windows handles are platform-specific")
def test_windows_mutation_after_descendant_release_is_rolled_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = MutableClock()
    paths = app_paths(tmp_path)
    store = initialized_store(paths, clock)
    root = tmp_path / "approved"
    root.mkdir()
    target = root / "tree"
    nested = target / "nested"
    nested.mkdir(parents=True)
    leaf = nested / "leaf.txt"
    leaf.write_text("previewed")
    cleanup_plan = QuarantinePlanner((root,), clock=clock).create_plan(
        manifest(root, target, resource_type=ResourceType.DIRECTORY)
    )
    store.save_quarantine_plan(cleanup_plan)
    release_handles = quarantine_module._release_windows_descendant_handles
    mutation_ran = False

    def release_then_mutate(handles: list[int], descendants: tuple[int, ...]) -> None:
        nonlocal mutation_ran
        release_handles(handles, descendants)
        leaf.write_text("raced-after-release")
        mutation_ran = True

    monkeypatch.setattr(
        quarantine_module,
        "_release_windows_descendant_handles",
        release_then_mutate,
    )
    receipt = QuarantineExecutor(
        store,
        paths,
        actor="test",
        clock=clock,
    ).execute(cleanup_plan.plan_id, expected_digest=cleanup_plan.digest)
    entry = store.get_quarantine_entry(receipt.entry_id)

    assert mutation_ran
    assert receipt.result is QuarantineResult.INTERRUPTED
    assert target.is_dir()
    assert leaf.read_text() == "raced-after-release"
    assert entry is not None
    assert entry.state is QuarantineState.INTERRUPTED
    assert not Path(entry.quarantine_path).exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX rename behavior is platform-specific")
def test_posix_post_move_inventory_mismatch_stays_quarantined(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    paths = app_paths(tmp_path)
    store = initialized_store(paths, clock)
    root = tmp_path / "approved"
    root.mkdir()
    target = root / "tree"
    target.mkdir()
    nested = target / "nested.txt"
    nested.write_text("previewed")
    cleanup_plan = QuarantinePlanner((root,), clock=clock).create_plan(
        manifest(root, target, resource_type=ResourceType.DIRECTORY)
    )
    store.save_quarantine_plan(cleanup_plan)

    def mutate_after_move(_plan: object, destination: Path) -> None:
        (destination / "nested.txt").write_text("concurrent-change")

    receipt = QuarantineExecutor(
        store,
        paths,
        actor="test",
        clock=clock,
        after_move=mutate_after_move,
    ).execute(cleanup_plan.plan_id, expected_digest=cleanup_plan.digest)
    entry = store.get_quarantine_entry(receipt.entry_id)

    assert receipt.result is QuarantineResult.INTERRUPTED
    assert not target.exists()
    assert entry is not None
    assert entry.state is QuarantineState.INTERRUPTED
    assert (Path(entry.quarantine_path) / "nested.txt").read_text() == ("concurrent-change")
    with pytest.raises(PlanClaimError, match="not restoreable"):
        QuarantineExecutor(
            store,
            paths,
            actor="test",
            clock=clock,
        ).restore(entry.entry_id)
    assert not target.exists()
    assert store.get_quarantine_entry(entry.entry_id) == entry
    assert (Path(entry.quarantine_path) / "nested.txt").read_text() == "concurrent-change"


@pytest.mark.skipif(os.name == "nt", reason="POSIX rename behavior is platform-specific")
def test_posix_post_move_link_replacement_never_enters_approved_root(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    paths = app_paths(tmp_path)
    store = initialized_store(paths, clock)
    root = tmp_path / "approved"
    root.mkdir()
    target = root / "tree"
    target.mkdir()
    nested = target / "nested.txt"
    nested.write_text("previewed")
    outside = tmp_path / "outside.txt"
    outside.write_text("outside-must-survive")
    cleanup_plan = QuarantinePlanner((root,), clock=clock).create_plan(
        manifest(root, target, resource_type=ResourceType.DIRECTORY)
    )
    store.save_quarantine_plan(cleanup_plan)

    def replace_with_link(_plan: object, destination: Path) -> None:
        moved_child = destination / "nested.txt"
        moved_child.unlink()
        moved_child.symlink_to(outside)

    receipt = QuarantineExecutor(
        store,
        paths,
        actor="test",
        clock=clock,
        after_move=replace_with_link,
    ).execute(cleanup_plan.plan_id, expected_digest=cleanup_plan.digest)
    entry = store.get_quarantine_entry(receipt.entry_id)

    assert receipt.result is QuarantineResult.INTERRUPTED
    assert not target.exists()
    assert outside.read_text() == "outside-must-survive"
    assert entry is not None
    assert entry.state is QuarantineState.INTERRUPTED
    assert (Path(entry.quarantine_path) / "nested.txt").is_symlink()


@pytest.mark.skipif(os.name == "nt", reason="POSIX rename behavior is platform-specific")
def test_posix_rollback_refuses_rebound_destination_name(tmp_path: Path) -> None:
    clock = MutableClock()
    paths = app_paths(tmp_path)
    store = initialized_store(paths, clock)
    root = tmp_path / "approved"
    root.mkdir()
    target = root / "tree"
    target.mkdir()
    (target / "nested.txt").write_text("previewed")
    cleanup_plan = QuarantinePlanner((root,), clock=clock).create_plan(
        manifest(root, target, resource_type=ResourceType.DIRECTORY)
    )
    store.save_quarantine_plan(cleanup_plan)
    parked: Path | None = None

    def rebind_after_move(_plan: object, destination: Path) -> None:
        nonlocal parked
        (destination / "nested.txt").write_text("changed")
        parked = destination.with_name("parked-original")
        destination.rename(parked)
        destination.mkdir()
        (destination / "replacement.txt").write_text("must-not-move")

    receipt = QuarantineExecutor(
        store,
        paths,
        actor="test",
        clock=clock,
        after_move=rebind_after_move,
    ).execute(cleanup_plan.plan_id, expected_digest=cleanup_plan.digest)
    entry = store.get_quarantine_entry(receipt.entry_id)

    assert receipt.result is QuarantineResult.INTERRUPTED
    assert not target.exists()
    assert entry is not None
    destination = Path(entry.quarantine_path)
    assert (destination / "replacement.txt").read_text() == "must-not-move"
    assert parked is not None
    assert (parked / "nested.txt").read_text() == "changed"


@pytest.mark.skipif(os.name == "nt", reason="POSIX rename behavior is platform-specific")
def test_posix_restore_mutation_is_interrupted_without_unsafe_rollback(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    paths = app_paths(tmp_path)
    store = initialized_store(paths, clock)
    root = tmp_path / "approved"
    root.mkdir()
    target = root / "tree"
    target.mkdir()
    nested = target / "nested.txt"
    nested.write_text("previewed")
    cleanup_plan = QuarantinePlanner((root,), clock=clock).create_plan(
        manifest(root, target, resource_type=ResourceType.DIRECTORY)
    )
    store.save_quarantine_plan(cleanup_plan)
    executor = QuarantineExecutor(store, paths, actor="test", clock=clock)
    quarantined = executor.execute(
        cleanup_plan.plan_id,
        expected_digest=cleanup_plan.digest,
    )
    entry = store.get_quarantine_entry(quarantined.entry_id)
    assert entry is not None

    def mutate_after_restore(_entry: object, destination: Path) -> None:
        (destination / "nested.txt").write_text("changed-during-restore")

    restore = QuarantineExecutor(
        store,
        paths,
        actor="test",
        clock=clock,
        after_restore=mutate_after_restore,
    ).restore(entry.entry_id)
    current = store.get_quarantine_entry(entry.entry_id)

    assert restore.result is QuarantineResult.INTERRUPTED
    assert target.is_dir()
    assert target.joinpath("nested.txt").read_text() == "changed-during-restore"
    assert not Path(entry.quarantine_path).exists()
    assert current is not None
    assert current.state is QuarantineState.INTERRUPTED


def test_hard_link_is_conservatively_rejected(tmp_path: Path) -> None:
    root = tmp_path / "approved"
    root.mkdir()
    target = root / "artifact.txt"
    target.write_text("test")
    alias = root / "alias.txt"
    try:
        os.link(target, alias)
    except OSError as error:
        pytest.skip(f"hard-link creation unavailable: {error}")

    with pytest.raises(CleanupRejectedError):
        QuarantinePlanner((root,)).create_plan(manifest(root, target))


@pytest.mark.parametrize("mutation", ("content", "replacement", "missing"))
def test_execution_rejects_changed_target_after_preview(tmp_path: Path, mutation: str) -> None:
    clock = MutableClock()
    paths, store, _, cleanup_plan, _, target = plan_file(tmp_path, clock=clock)
    if mutation == "content":
        target.write_bytes(b"changed size and hash")
    elif mutation == "replacement":
        target.unlink()
        target.write_bytes(b"replacement")
    else:
        target.unlink()

    receipt = QuarantineExecutor(store, paths, actor="test", clock=clock).execute(
        cleanup_plan.plan_id,
        expected_digest=cleanup_plan.digest,
    )

    assert receipt.result is QuarantineResult.FAILED
    assert not list(paths.graveyard_dir.rglob("artifact.bin"))


def test_execution_rechecks_after_race_hook(tmp_path: Path) -> None:
    clock = MutableClock()
    paths, store, _, cleanup_plan, _, target = plan_file(tmp_path, clock=clock)

    def replace_after_validation(_plan: object) -> None:
        target.unlink()
        target.write_bytes(b"raced replacement")

    receipt = QuarantineExecutor(
        store,
        paths,
        actor="test",
        clock=clock,
        before_move=replace_after_validation,
    ).execute(cleanup_plan.plan_id, expected_digest=cleanup_plan.digest)

    assert receipt.result is QuarantineResult.FAILED
    assert target.read_bytes() == (
        b"owned test material" if os.name == "nt" else b"raced replacement"
    )


def test_execution_rehashes_same_inode_file_at_mutation_boundary(tmp_path: Path) -> None:
    clock = MutableClock()
    paths, store, _, cleanup_plan, _, target = plan_file(tmp_path, content=b"original", clock=clock)

    def mutate_in_place(_plan: object) -> None:
        target.write_bytes(b"modified")

    receipt = QuarantineExecutor(
        store,
        paths,
        actor="test",
        clock=clock,
        before_move=mutate_in_place,
    ).execute(cleanup_plan.plan_id, expected_digest=cleanup_plan.digest)

    assert receipt.result is QuarantineResult.FAILED
    assert target.read_bytes() == (b"original" if os.name == "nt" else b"modified")
    assert not list(paths.graveyard_dir.rglob("artifact.bin"))


def test_execution_revalidates_managed_resource_registration(tmp_path: Path) -> None:
    clock = MutableClock()
    paths, store, _, cleanup_plan, _, target = plan_file(tmp_path, clock=clock)
    REGISTRY.clear()

    receipt = QuarantineExecutor(
        store,
        paths,
        actor="test",
        clock=clock,
    ).execute(cleanup_plan.plan_id, expected_digest=cleanup_plan.digest)

    assert receipt.result is QuarantineResult.FAILED
    assert target.exists()


def test_registration_is_rechecked_at_final_mutation_boundary(tmp_path: Path) -> None:
    clock = MutableClock()
    paths, store, cleanup_manifest, cleanup_plan, _, target = plan_file(tmp_path, clock=clock)

    def revoke_during_wait(_plan: object) -> None:
        REGISTRY.unregister(cleanup_manifest)

    receipt = QuarantineExecutor(
        store,
        paths,
        actor="test",
        clock=clock,
        before_move=revoke_during_wait,
    ).execute(cleanup_plan.plan_id, expected_digest=cleanup_plan.digest)

    assert receipt.result is QuarantineResult.FAILED
    assert target.exists()


def test_plan_expiry_is_rechecked_inside_final_mutation_section(tmp_path: Path) -> None:
    clock = MutableClock()
    paths, store, _, cleanup_plan, _, target = plan_file(tmp_path, clock=clock)

    def expire_after_wait(_plan: object) -> None:
        clock.value = cleanup_plan.expires_at

    receipt = QuarantineExecutor(
        store,
        paths,
        actor="test",
        clock=clock,
        before_move=expire_after_wait,
    ).execute(cleanup_plan.plan_id, expected_digest=cleanup_plan.digest)

    assert receipt.result is QuarantineResult.FAILED
    assert target.exists()


def test_plan_expiry_is_rechecked_after_final_journal_wait(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = MutableClock()
    paths, store, _, cleanup_plan, _, target = plan_file(tmp_path, clock=clock)
    update_phase = store.update_quarantine_plan_phase

    def wait_while_journaling(plan_id: str, phase: str) -> None:
        update_phase(plan_id, phase)
        if phase == "rename_issuing":
            clock.value = cleanup_plan.expires_at

    monkeypatch.setattr(store, "update_quarantine_plan_phase", wait_while_journaling)
    receipt = QuarantineExecutor(
        store,
        paths,
        actor="test",
        clock=clock,
    ).execute(cleanup_plan.plan_id, expected_digest=cleanup_plan.digest)

    assert receipt.result is QuarantineResult.FAILED
    assert target.exists()


def test_cross_volume_quarantine_fails_without_copy_or_delete(tmp_path: Path) -> None:
    clock = MutableClock()
    paths, store, _, cleanup_plan, _, target = plan_file(tmp_path, clock=clock)

    def devices(path: Path) -> int:
        return 2 if paths.graveyard_dir in (path, *path.parents) else 1

    receipt = QuarantineExecutor(
        store,
        paths,
        actor="test",
        clock=clock,
        device_resolver=devices,
    ).execute(cleanup_plan.plan_id, expected_digest=cleanup_plan.digest)

    assert receipt.result is QuarantineResult.FAILED
    assert target.exists()


def test_locked_or_read_only_move_failure_leaves_material_in_place(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    paths, store, _, cleanup_plan, _, target = plan_file(tmp_path, clock=clock)

    def locked(_plan: object) -> None:
        raise PermissionError("synthetic lock")

    receipt = QuarantineExecutor(
        store,
        paths,
        actor="test",
        clock=clock,
        before_move=locked,
    ).execute(cleanup_plan.plan_id, expected_digest=cleanup_plan.digest)

    assert receipt.result is QuarantineResult.FAILED
    assert target.exists()


def test_directory_inventory_is_bounded_and_rejects_redirected_child(
    tmp_path: Path,
) -> None:
    root = tmp_path / "approved"
    root.mkdir()
    target = root / "tree"
    target.mkdir()
    (target / "one.txt").write_text("one")
    (target / "two.txt").write_text("two")
    planner = QuarantinePlanner((root,), max_entries=1, clock=MutableClock())

    with pytest.raises(CleanupRejectedError):
        planner.create_plan(manifest(root, target, resource_type=ResourceType.DIRECTORY))

    redirected = target / "redirected"
    redirected.mkdir()
    planner = QuarantinePlanner(
        (root,),
        reparse_checker=lambda path, _stat: path == redirected,
        clock=MutableClock(),
    )
    with pytest.raises(CleanupRejectedError):
        planner.create_plan(manifest(root, target, resource_type=ResourceType.DIRECTORY))


def test_directory_inventory_enforces_byte_and_depth_bounds(tmp_path: Path) -> None:
    root = tmp_path / "approved"
    root.mkdir()
    target = root / "tree"
    deep = target / "one" / "two"
    deep.mkdir(parents=True)
    (deep / "payload.bin").write_bytes(b"12345")

    with pytest.raises(CleanupRejectedError, match="depth"):
        QuarantinePlanner((root,), max_depth=1, clock=MutableClock()).create_plan(
            manifest(root, target, resource_type=ResourceType.DIRECTORY)
        )
    with pytest.raises(CleanupRejectedError, match="byte quota"):
        QuarantinePlanner((root,), max_bytes=4, clock=MutableClock()).create_plan(
            manifest(root, target, resource_type=ResourceType.DIRECTORY)
        )


@pytest.mark.skipif(os.name == "nt", reason="POSIX FIFO behavior is platform-specific")
def test_directory_inventory_rejects_fifo_without_blocking(tmp_path: Path) -> None:
    root = tmp_path / "approved"
    root.mkdir()
    target = root / "tree"
    target.mkdir()
    os.mkfifo(target / "pipe")

    with pytest.raises(CleanupRejectedError, match="special"):
        QuarantinePlanner((root,), clock=MutableClock()).create_plan(
            manifest(root, target, resource_type=ResourceType.DIRECTORY)
        )


@pytest.mark.skipif(os.name == "nt", reason="openat2 is Linux-specific")
def test_linux_aarch64_uses_the_openat2_syscall_number(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []

    class FakeLibC:
        def syscall(self, number: int, *_args: object) -> int:
            calls.append(number)
            return 123

    monkeypatch.setattr(quarantine_module.platform, "machine", lambda: "aarch64")
    monkeypatch.setattr(quarantine_module.ctypes, "CDLL", lambda *_a, **_k: FakeLibC())

    result = quarantine_module._open_posix_child(
        5,
        "child",
        os.O_RDONLY,
        no_xdev=True,
    )

    assert result == 123
    assert calls == [437]


@pytest.mark.skipif(
    os.name == "nt" or not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="Linux bind-mount probe requires root",
)
def test_directory_inventory_rejects_bind_mount_child(tmp_path: Path) -> None:
    if not os.uname().sysname.casefold().startswith("linux"):
        pytest.skip("openat2 mount-boundary probe is Linux-specific")
    root = tmp_path / "approved"
    target = root / "tree"
    mounted = target / "mounted"
    outside = tmp_path / "outside"
    mounted.mkdir(parents=True)
    outside.mkdir()
    (outside / "outside.txt").write_text("must remain outside")
    attempt = subprocess.run(
        ["mount", "--bind", os.fspath(outside), os.fspath(mounted)],
        check=False,
        capture_output=True,
        text=True,
    )
    if attempt.returncode != 0:
        pytest.skip(f"bind mount unavailable: {attempt.stderr.strip()}")
    try:
        with pytest.raises(CleanupRejectedError, match="mount|filesystem"):
            QuarantinePlanner((root,), clock=MutableClock()).create_plan(
                manifest(root, target, resource_type=ResourceType.DIRECTORY)
            )
    finally:
        subprocess.run(["umount", os.fspath(mounted)], check=True)
    assert (outside / "outside.txt").read_text() == "must remain outside"


@pytest.mark.skipif(
    os.name == "nt" or not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="Linux bind-mount probe requires root",
)
def test_planner_rejects_bind_mount_target_ancestor(tmp_path: Path) -> None:
    if not os.uname().sysname.casefold().startswith("linux"):
        pytest.skip("openat2 mount-boundary probe is Linux-specific")
    root = tmp_path / "approved"
    mounted = root / "mounted"
    outside = tmp_path / "outside"
    mounted.mkdir(parents=True)
    outside.mkdir()
    outside_target = outside / "artifact.txt"
    outside_target.write_text("must remain outside")
    attempt = subprocess.run(
        ["mount", "--bind", os.fspath(outside), os.fspath(mounted)],
        check=False,
        capture_output=True,
        text=True,
    )
    if attempt.returncode != 0:
        pytest.skip(f"bind mount unavailable: {attempt.stderr.strip()}")
    try:
        with pytest.raises(CleanupRejectedError, match="mount|filesystem"):
            QuarantinePlanner((root,), clock=MutableClock()).create_plan(
                manifest(root, mounted / outside_target.name)
            )
    finally:
        subprocess.run(["umount", os.fspath(mounted)], check=True)
    assert outside_target.read_text() == "must remain outside"


@pytest.mark.skipif(os.name != "nt", reason="Windows handle counts are platform-specific")
def test_repeated_directory_preview_and_failed_execution_do_not_leak_handles(
    tmp_path: Path,
) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    kernel32.GetProcessHandleCount.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_ulong),
    )

    def handle_count() -> int:
        count = ctypes.c_ulong()
        if not kernel32.GetProcessHandleCount(kernel32.GetCurrentProcess(), ctypes.byref(count)):
            raise ctypes.WinError(ctypes.get_last_error())
        return int(count.value)

    clock = MutableClock()
    paths = app_paths(tmp_path)
    store = initialized_store(paths, clock)
    root = tmp_path / "approved"
    root.mkdir()
    target = root / "tree"
    nested = target / "nested"
    nested.mkdir(parents=True)
    (nested / "leaf.txt").write_text("leaf")
    before = handle_count()

    def stop_before_move(_plan: object) -> None:
        raise PermissionError("synthetic stop")

    for _ in range(12):
        cleanup_plan = QuarantinePlanner((root,), clock=clock).create_plan(
            manifest(root, target, resource_type=ResourceType.DIRECTORY)
        )
        store.save_quarantine_plan(cleanup_plan)
        receipt = QuarantineExecutor(
            store,
            paths,
            actor="test",
            clock=clock,
            before_move=stop_before_move,
        ).execute(cleanup_plan.plan_id, expected_digest=cleanup_plan.digest)
        assert receipt.result is QuarantineResult.FAILED

    assert handle_count() <= before + 2


def test_file_size_is_enforced_by_preview_quota(tmp_path: Path) -> None:
    root = tmp_path / "approved"
    root.mkdir()
    target = root / "artifact.bin"
    target.write_bytes(b"12345")

    with pytest.raises(CleanupRejectedError, match="byte quota"):
        QuarantinePlanner((root,), max_bytes=4, clock=MutableClock()).create_plan(
            manifest(root, target)
        )


def test_directory_quarantine_and_restore_is_atomic(tmp_path: Path) -> None:
    clock = MutableClock()
    paths = app_paths(tmp_path)
    store = initialized_store(paths, clock)
    root = tmp_path / "approved"
    root.mkdir()
    target = root / "tree"
    target.mkdir()
    (target / "nested").mkdir()
    (target / "nested" / "artifact.txt").write_text("test")
    cleanup_plan = QuarantinePlanner((root,), clock=clock).create_plan(
        manifest(root, target, resource_type=ResourceType.DIRECTORY)
    )
    store.save_quarantine_plan(cleanup_plan)
    executor = QuarantineExecutor(store, paths, actor="test", clock=clock)

    receipt = executor.execute(cleanup_plan.plan_id, expected_digest=cleanup_plan.digest)
    entry = store.get_quarantine_entry(receipt.entry_id)
    assert entry is not None
    assert receipt.result is QuarantineResult.QUARANTINED
    assert target.exists() is False

    assert executor.restore(entry.entry_id).result is QuarantineResult.RESTORED
    assert (target / "nested" / "artifact.txt").read_text() == "test"


def test_restore_never_overwrites_existing_destination(tmp_path: Path) -> None:
    clock = MutableClock()
    paths, store, _, cleanup_plan, _, target = plan_file(tmp_path, clock=clock)
    executor = QuarantineExecutor(store, paths, actor="test", clock=clock)
    receipt = executor.execute(cleanup_plan.plan_id, expected_digest=cleanup_plan.digest)
    target.write_bytes(b"new owner material")

    restore = executor.restore(receipt.entry_id)
    repeated = executor.restore(receipt.entry_id)

    assert restore.result is QuarantineResult.FAILED
    assert repeated.receipt_id == restore.receipt_id
    assert target.read_bytes() == b"new owner material"
    entry = store.get_quarantine_entry(receipt.entry_id)
    assert entry is not None
    assert Path(entry.quarantine_path).exists()


def test_restore_rejects_changed_graveyard_entry(tmp_path: Path) -> None:
    clock = MutableClock()
    paths, store, _, cleanup_plan, _, _ = plan_file(tmp_path, clock=clock)
    executor = QuarantineExecutor(store, paths, actor="test", clock=clock)
    receipt = executor.execute(cleanup_plan.plan_id, expected_digest=cleanup_plan.digest)
    entry = store.get_quarantine_entry(receipt.entry_id)
    assert entry is not None
    quarantine_path = Path(entry.quarantine_path)
    quarantine_path.write_bytes(b"tampered")

    assert executor.restore(entry.entry_id).result is QuarantineResult.FAILED
    assert quarantine_path.read_bytes() == b"tampered"


def test_restore_rejects_tampered_entry_path_and_digest(tmp_path: Path) -> None:
    clock = MutableClock()
    paths, store, _, cleanup_plan, _, _ = plan_file(tmp_path, clock=clock)
    receipt = QuarantineExecutor(store, paths, actor="test", clock=clock).execute(
        cleanup_plan.plan_id, expected_digest=cleanup_plan.digest
    )
    entry = store.get_quarantine_entry(receipt.entry_id)
    assert entry is not None
    assert entry.verify_digest()
    with sqlite3.connect(store.database_path) as connection:
        row = connection.execute(
            "SELECT state_json FROM quarantine_entries WHERE entry_id = ?",
            (entry.entry_id,),
        ).fetchone()
        assert row is not None
        payload = json.loads(str(row[0]))
        payload["original_path"] = str(tmp_path / "outside.txt")
        connection.execute(
            "UPDATE quarantine_entries SET state_json = ? WHERE entry_id = ?",
            (json.dumps(payload), entry.entry_id),
        )

    with pytest.raises(ValueError, match="digest"):
        QuarantineExecutor(store, paths, actor="test", clock=clock).restore(entry.entry_id)


def test_restore_rechecks_destination_after_race_hook(tmp_path: Path) -> None:
    clock = MutableClock()
    paths, store, _, cleanup_plan, _, target = plan_file(tmp_path, clock=clock)
    first = QuarantineExecutor(store, paths, actor="test", clock=clock)
    receipt = first.execute(cleanup_plan.plan_id, expected_digest=cleanup_plan.digest)

    def occupy_destination(_entry: object) -> None:
        target.write_bytes(b"raced destination")

    restore = QuarantineExecutor(
        store,
        paths,
        actor="test",
        clock=clock,
        before_restore=occupy_destination,
    ).restore(receipt.entry_id)

    assert restore.result is QuarantineResult.FAILED
    assert target.read_bytes() == b"raced destination"


def test_expired_plan_is_not_executed(tmp_path: Path) -> None:
    clock = MutableClock()
    paths, store, _, cleanup_plan, _, target = plan_file(tmp_path, clock=clock)
    clock.value = NOW + timedelta(minutes=1)

    with pytest.raises(Exception, match="expired"):
        QuarantineExecutor(store, paths, actor="test", clock=clock).execute(
            cleanup_plan.plan_id,
            expected_digest=cleanup_plan.digest,
        )
    assert target.exists()


def test_execution_cannot_outlive_original_manifest_authority(
    tmp_path: Path,
) -> None:
    clock = MutableClock(NOW + timedelta(seconds=29))
    paths, store, _, cleanup_plan, _, target = plan_file(tmp_path, clock=clock)
    clock.value = NOW + timedelta(seconds=30)

    receipt = QuarantineExecutor(store, paths, actor="test", clock=clock).execute(
        cleanup_plan.plan_id,
        expected_digest=cleanup_plan.digest,
    )

    assert receipt.result is QuarantineResult.FAILED
    assert target.exists()


def test_move_then_exception_is_reconciled_without_material_loss_or_second_move(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    paths, store, _, cleanup_plan, _, target = plan_file(tmp_path, clock=clock)
    moves = 0

    def moved_then_interrupted(_plan: object, _destination: Path) -> None:
        nonlocal moves
        moves += 1
        raise OSError("synthetic interruption after rename")

    executor = QuarantineExecutor(
        store,
        paths,
        actor="test",
        clock=clock,
        after_move=moved_then_interrupted,
    )
    first = executor.execute(cleanup_plan.plan_id, expected_digest=cleanup_plan.digest)
    second = executor.execute(cleanup_plan.plan_id, expected_digest=cleanup_plan.digest)

    assert first.result is QuarantineResult.QUARANTINED
    assert second.receipt_id == first.receipt_id
    assert moves == 1
    assert target.exists() is False


def test_retry_reconciles_crash_after_atomic_move_without_second_move(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    paths, store, _, cleanup_plan, _, target = plan_file(tmp_path, clock=clock)
    moves = 0

    def crash_after_move(_plan: object, _destination: Path) -> None:
        nonlocal moves
        moves += 1
        raise SystemExit("synthetic process crash")

    with pytest.raises(SystemExit, match="synthetic process crash"):
        QuarantineExecutor(
            store,
            paths,
            actor="test",
            clock=clock,
            after_move=crash_after_move,
        ).execute(cleanup_plan.plan_id, expected_digest=cleanup_plan.digest)

    dead_owner_store = SQLiteStateStore(
        paths,
        clock=clock,
        session_id="recovery-session",
        is_session_alive=lambda _owner: False,
    )
    dead_owner_store.initialize(now=clock())
    recovered = QuarantineExecutor(dead_owner_store, paths, actor="test", clock=clock).execute(
        cleanup_plan.plan_id, expected_digest=cleanup_plan.digest
    )

    assert recovered.result is QuarantineResult.QUARANTINED
    assert moves == 1
    assert target.exists() is False


def test_dead_owner_crash_before_rename_is_retryable(tmp_path: Path) -> None:
    clock = MutableClock()
    paths, store, _, cleanup_plan, _, target = plan_file(tmp_path, clock=clock)

    def crash_before_move(_plan: object) -> None:
        raise SystemExit("synthetic pre-rename crash")

    with pytest.raises(SystemExit, match="pre-rename"):
        QuarantineExecutor(
            store,
            paths,
            actor="test",
            clock=clock,
            before_move=crash_before_move,
        ).execute(cleanup_plan.plan_id, expected_digest=cleanup_plan.digest)

    dead_owner_store = SQLiteStateStore(
        paths,
        clock=clock,
        session_id="recovery-session",
        is_session_alive=lambda _owner: False,
    )
    dead_owner_store.initialize(now=clock())
    recovered = QuarantineExecutor(dead_owner_store, paths, actor="test", clock=clock).execute(
        cleanup_plan.plan_id, expected_digest=cleanup_plan.digest
    )

    assert recovered.result is QuarantineResult.QUARANTINED
    assert target.exists() is False


def test_live_owner_running_plan_is_not_reconciled(tmp_path: Path) -> None:
    clock = MutableClock()
    paths, store, _, cleanup_plan, _, target = plan_file(tmp_path, clock=clock)

    def crash_before_move(_plan: object) -> None:
        raise SystemExit("synthetic live-owner pause")

    with pytest.raises(SystemExit):
        QuarantineExecutor(
            store,
            paths,
            actor="test",
            clock=clock,
            before_move=crash_before_move,
        ).execute(cleanup_plan.plan_id, expected_digest=cleanup_plan.digest)

    live_owner_store = SQLiteStateStore(
        paths,
        clock=clock,
        session_id="other-session",
        is_session_alive=lambda _owner: True,
    )
    live_owner_store.initialize(now=clock())
    with pytest.raises(PlanClaimError, match="running owner is alive"):
        QuarantineExecutor(live_owner_store, paths, actor="test", clock=clock).execute(
            cleanup_plan.plan_id, expected_digest=cleanup_plan.digest
        )
    assert target.exists()


def test_reused_session_id_recovers_dead_owner_process(tmp_path: Path) -> None:
    clock = MutableClock()
    paths, owner_store, _, cleanup_plan, _, _ = plan_file(tmp_path, clock=clock)
    owner_store.claim_quarantine_plan(
        cleanup_plan.plan_id,
        expected_digest=cleanup_plan.digest,
    )
    with sqlite3.connect(owner_store.database_path) as connection:
        connection.execute(
            "UPDATE quarantine_plans SET claim_owner_pid = ?, "
            "claim_owner_create_time = ? WHERE plan_id = ?",
            (999_999_999, 1.0, cleanup_plan.plan_id),
        )
    restarted = SQLiteStateStore(
        paths,
        clock=clock,
        session_id=owner_store.session_id,
    )
    restarted.initialize(now=clock())

    recovery = restarted.get_quarantine_recovery(
        cleanup_plan.plan_id,
        expected_digest=cleanup_plan.digest,
    )

    assert recovery is not None
    assert recovery[0].plan_id == cleanup_plan.plan_id


def test_pinned_handle_blocks_post_move_mutation_and_keeps_original_material(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    paths, store, _, cleanup_plan, _, target = plan_file(tmp_path, clock=clock)

    def moved_then_changed(_plan: object, destination: Path) -> None:
        destination.write_bytes(b"changed only after atomic move")

    receipt = QuarantineExecutor(
        store,
        paths,
        actor="test",
        clock=clock,
        after_move=moved_then_changed,
    ).execute(cleanup_plan.plan_id, expected_digest=cleanup_plan.digest)

    expected_result = (
        QuarantineResult.QUARANTINED if os.name == "nt" else QuarantineResult.INTERRUPTED
    )
    assert receipt.result is expected_result
    entry = store.get_quarantine_entry(receipt.entry_id)
    assert entry is not None
    if os.name == "nt":
        assert target.exists() is False
        assert entry.state is QuarantineState.SUCCEEDED
        assert Path(entry.quarantine_path).read_bytes() == b"owned test material"
    else:
        assert entry.state is QuarantineState.INTERRUPTED
        assert not target.exists()
        assert Path(entry.quarantine_path).read_bytes() == (b"changed only after atomic move")


def test_restore_changed_after_move_is_interrupted_not_failed_before_issue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = MutableClock()
    paths, store, _, cleanup_plan, _, target = plan_file(tmp_path, clock=clock)
    executor = QuarantineExecutor(store, paths, actor="test", clock=clock)
    quarantined = executor.execute(cleanup_plan.plan_id, expected_digest=cleanup_plan.digest)
    entry = store.get_quarantine_entry(quarantined.entry_id)
    assert entry is not None
    fingerprint = executor._fingerprint_plan_target
    changed = False

    def change_before_final_verification(plan: object, candidate: Path) -> object:
        nonlocal changed
        if candidate == target and target.exists() and not changed:
            target.write_bytes(b"concurrent bytes after restore rename")
            changed = True
        return fingerprint(plan, candidate)

    monkeypatch.setattr(executor, "_fingerprint_plan_target", change_before_final_verification)

    receipt = executor.restore(entry.entry_id)

    assert receipt.result is QuarantineResult.INTERRUPTED
    assert target.read_bytes() == b"concurrent bytes after restore rename"
    assert not Path(entry.quarantine_path).exists()
    journaled = store.get_quarantine_entry(entry.entry_id)
    assert journaled is not None and journaled.state is QuarantineState.INTERRUPTED


def test_already_restored_receipt_reports_no_fresh_action(tmp_path: Path) -> None:
    from zombie_killer_engine.cleanup_workflow import _receipt_result

    clock = MutableClock()
    paths, store, _, cleanup_plan, _, _ = plan_file(tmp_path, clock=clock)
    executor = QuarantineExecutor(store, paths, actor="test", clock=clock)
    quarantined = executor.execute(cleanup_plan.plan_id, expected_digest=cleanup_plan.digest)
    assert quarantined.entry_id is not None
    executor.restore(quarantined.entry_id)

    repeated = _receipt_result(executor.restore(quarantined.entry_id))

    assert repeated["outcome"] == "already_restored"
    assert repeated["certainty"] == "verified"
    assert repeated["action_issued"] is False


def test_audit_receipt_contains_hashes_but_not_raw_paths(tmp_path: Path) -> None:
    clock = MutableClock()
    paths, store, _, cleanup_plan, root, target = plan_file(tmp_path, clock=clock)
    receipt = QuarantineExecutor(store, paths, actor="test", clock=clock).execute(
        cleanup_plan.plan_id, expected_digest=cleanup_plan.digest
    )

    event = store.get_audit_event(receipt.audit_event_id)
    rendered = str(event)
    assert str(root) not in rendered
    assert str(target) not in rendered
    assert cleanup_plan.root_hash in rendered
    assert cleanup_plan.target_hash in rendered
