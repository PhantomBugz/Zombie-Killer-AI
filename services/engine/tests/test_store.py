from __future__ import annotations

import ctypes
import json
import os
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import TracebackType

import psutil  # type: ignore[import-untyped]
import pytest
from pydantic import ValidationError

from zombie_killer_engine.actions import (
    ActionMode,
    ActionPlan,
    ActionReceipt,
    ActionResult,
    PlanStatus,
)
from zombie_killer_engine.memory import (
    FileIdentity,
    MemoryError,
    MemoryReceipt,
    MutationKind,
    MutationOperation,
    Snapshot,
    VaultCapabilities,
    VaultFormat,
    VaultSource,
)
from zombie_killer_engine.memory.base import new_plan, path_binding, sha256_bytes
from zombie_killer_engine.memory.base import source_id as vault_source_id
from zombie_killer_engine.models import ProcessIdentity
from zombie_killer_engine.paths import AppPaths
from zombie_killer_engine.store import (
    AuditEventDetails,
    ExpiredPlanError,
    PlanClaimError,
    SQLiteStateStore,
    StoreError,
    StorePathError,
)

NOW = datetime(2026, 8, 12, 12, 0, tzinfo=UTC)
IDENTITY = ProcessIdentity(
    boot_id="synthetic-boot",
    pid=4242,
    create_time=1_765_000_000.25,
    executable="/synthetic/python",
    user="synthetic-user",
)


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


def plan(*, created_at: datetime = NOW) -> ActionPlan:
    return ActionPlan.create(
        identity=IDENTITY,
        mode=ActionMode.TERMINATE,
        agent_id="synthetic-agent",
        managed=True,
        warnings=("Synthetic warning.",),
        consequences=("The exact process instance will be terminated.",),
        created_at=created_at,
        platform_name="linux",
    )


def receipt(action_plan: ActionPlan) -> ActionReceipt:
    return ActionReceipt.create(
        plan=action_plan,
        actor="synthetic-user",
        session_id="synthetic-session",
        result=ActionResult.COMPLETED,
        action_issued=True,
        before="running",
        after="not_found",
        started_at=NOW + timedelta(seconds=1),
        finished_at=NOW + timedelta(seconds=2),
    )


def test_empty_database_migrates_idempotently_and_enables_safety_pragmas(
    tmp_path: Path,
) -> None:
    store = SQLiteStateStore(app_paths(tmp_path), busy_timeout_ms=3210)

    store.initialize()
    store.initialize()

    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        assert connection.execute("PRAGMA user_version").fetchone()[0] == store.schema_version
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        assert {
            "schema_versions",
            "action_plans",
            "receipts",
            "audit_events",
            "settings",
            "quarantine_entries",
            "vault_entries",
            "snapshots",
            "vault_sources",
            "memory_mutation_plans",
            "memory_restore_plans",
            "memory_sessions",
            "memory_snapshots",
            "memory_receipts",
        } <= tables
    assert store.connection_pragmas() == {
        "foreign_keys": 1,
        "busy_timeout": 3210,
        "journal_mode": "wal",
    }


def test_typed_memory_journal_never_persists_mutation_content(tmp_path: Path) -> None:
    paths = app_paths(tmp_path)
    store = SQLiteStateStore(paths, clock=lambda: NOW)
    store.initialize(now=NOW)
    source_path = tmp_path / "selected-memory.json"
    source_path.write_text("[]", encoding="utf-8")
    source = VaultSource(
        source_id=vault_source_id(source_path),
        path=str(source_path),
        format=VaultFormat.JSON,
        capabilities=VaultCapabilities(
            readable=True, queryable=True, editable=True, snapshot=True, restore=True
        ),
        revision="1" * 64,
    )
    operation = MutationOperation(
        kind=MutationKind.UPDATE_CONTENT,
        record_id="record-1",
        value="never-store-this-sensitive-content",
    )
    mutation = new_plan(
        source=source_path,
        revision="1" * 64,
        identity=FileIdentity(device=1, inode=2, size=2, mtime_ns=3, ctime_ns=4, mode=0o100600),
        operation=operation,
        record_hash="7" * 64,
        field_name="content",
        old_hash="2" * 64,
        old_store_hash="1" * 64,
        new_hash="3" * 64,
        new_store_hash="4" * 64,
        now=NOW,
    )
    snapshot = Snapshot(
        snapshot_id="snapshot-test",
        source_id=source.source_id,
        source_path_binding="5" * 64,
        source_revision="1" * 64,
        source_identity=FileIdentity(
            device=1, inode=2, size=2, mtime_ns=3, ctime_ns=4, mode=0o100600
        ),
        digest="6" * 64,
        size=2,
        backup_identity=FileIdentity(
            device=1, inode=3, size=2, mtime_ns=4, ctime_ns=5, mode=0o100600
        ),
        backup_path=str(paths.backups_dir / "snapshot-test"),
        created_at=NOW,
    )
    receipt = MemoryReceipt(
        receipt_id="receipt-test",
        plan_id=mutation.plan_id,
        snapshot_id=snapshot.snapshot_id,
        source_id=source.source_id,
        operation="update_content",
        field_names=("content",),
        before_revision="1" * 64,
        after_revision="4" * 64,
        created_at=NOW,
    )

    store.register_vault_source(source)
    store.save_memory_plan(mutation)
    authority = store.claim_memory_plan(
        mutation.plan_id,
        expected_digest=mutation.digest,
    )
    assert authority.proposed_value_hash == mutation.proposed_value_hash
    assert authority.record_hash == mutation.record_hash
    with pytest.raises(PlanClaimError, match="claim|replay|running"):
        store.claim_memory_plan(
            mutation.plan_id,
            expected_digest=mutation.digest,
        )
    store.save_memory_snapshot(snapshot)
    store.update_memory_plan_phase(
        mutation.plan_id, "snapshot_verified", snapshot_id=snapshot.snapshot_id
    )
    store.finish_memory_plan(receipt)

    assert store.get_memory_receipt_for_plan(mutation.plan_id) == receipt
    assert store.get_memory_receipt_for_plan("missing-fixture-plan") is None
    assert [
        item.snapshot_id for item in store.list_memory_snapshots(source.source_id, limit=1)
    ] == ["snapshot-test"]
    with pytest.raises(ValueError):
        store.list_memory_snapshots(source.source_id, limit=501)

    raw_database = store.database_path.read_bytes()
    assert b"never-store-this-sensitive-content" not in raw_database
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM vault_sources").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM memory_mutation_plans").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM memory_snapshots").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM memory_receipts").fetchone()[0] == 1
        status, phase = connection.execute(
            "SELECT status, phase FROM memory_mutation_plans WHERE plan_id = ?",
            (mutation.plan_id,),
        ).fetchone()
        assert (status, phase) == ("succeeded", "completed")


def test_legacy_json_snapshot_is_rebound_only_when_physical_authority_matches(
    tmp_path: Path,
) -> None:
    paths = app_paths(tmp_path)
    store = SQLiteStateStore(paths)
    store.initialize(now=NOW)
    source = tmp_path / "selected-memory.json"
    source.write_text("[]", encoding="utf-8")
    paths.backups_dir.mkdir(mode=0o700)
    backup = paths.backups_dir / "legacy.snapshot"
    backup.write_bytes(source.read_bytes())
    revision = sha256_bytes(source.read_bytes())
    source_authority = VaultSource(
        source_id=vault_source_id(source),
        path=str(source),
        format=VaultFormat.JSON,
        capabilities=VaultCapabilities(readable=True, restore=True),
        revision=revision,
    )
    store.register_vault_source(source_authority)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "INSERT INTO memory_snapshots(snapshot_id, source_id, "
            "source_path_binding, source_revision, digest, size, backup_path, status, "
            "retention_until, created_at, source_identity_json, backup_identity_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 'legacy_unbound', ?, ?, NULL, NULL)",
            (
                "legacy-snapshot",
                source_authority.source_id,
                path_binding(source),
                revision,
                revision,
                source.stat().st_size,
                str(backup),
                (NOW + timedelta(days=30)).isoformat(),
                NOW.isoformat(),
            ),
        )

    recovered = store.get_memory_snapshot("legacy-snapshot")

    assert recovered is not None
    assert recovered.status.value == "verified"
    assert recovered.backup_identity.size == source.stat().st_size


def test_v9_memory_plan_without_complete_authority_is_fail_closed(tmp_path: Path) -> None:
    paths = app_paths(tmp_path)
    store = SQLiteStateStore(paths, clock=lambda: NOW)
    store.initialize(now=NOW)
    source = tmp_path / "selected-memory.json"
    source.write_text("[]", encoding="utf-8")
    source_authority = VaultSource(
        source_id=vault_source_id(source),
        path=str(source),
        format=VaultFormat.JSON,
        capabilities=VaultCapabilities(readable=True, editable=True),
        revision="1" * 64,
    )
    mutation = new_plan(
        source=source,
        revision="1" * 64,
        identity=FileIdentity(device=1, inode=2, size=2, mtime_ns=3, ctime_ns=4, mode=0o100600),
        operation=MutationOperation(
            kind=MutationKind.UPDATE_CONTENT,
            record_id="record-1",
            value="new",
        ),
        record_hash="7" * 64,
        field_name="content",
        old_hash="2" * 64,
        old_store_hash="1" * 64,
        new_hash="3" * 64,
        new_store_hash="4" * 64,
        now=NOW,
    )
    store.register_vault_source(source_authority)
    store.save_memory_plan(mutation)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE memory_mutation_plans SET status='running', "
            "phase='write_issuing', source_identity_json=NULL WHERE plan_id=?",
            (mutation.plan_id,),
        )
        connection.execute("DELETE FROM schema_versions WHERE version>=10")
        connection.execute("PRAGMA user_version=9")

    store.initialize(now=NOW + timedelta(seconds=1))

    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "SELECT status, phase FROM memory_mutation_plans WHERE plan_id=?",
            (mutation.plan_id,),
        ).fetchone() == ("failed", "legacy_incompatible")


def test_memory_journal_reopens_inflight_write_as_interrupted(tmp_path: Path) -> None:
    paths = app_paths(tmp_path)
    store = SQLiteStateStore(paths)
    store.initialize(now=NOW)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "INSERT INTO vault_sources(source_id, source_path, format, capabilities_json, "
            "revision, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                "vault-crash",
                str(tmp_path / "memory.json"),
                "json",
                "{}",
                "1" * 64,
                NOW.isoformat(),
                NOW.isoformat(),
            ),
        )
        connection.execute(
            "INSERT INTO memory_mutation_plans("
            "plan_id, source_id, digest, source_revision, operation, record_id, "
            "field_names_json, expected_old_hash, new_store_hash, status, created_at, "
            "expires_at, phase) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "crashed-plan",
                "vault-crash",
                "2" * 64,
                "1" * 64,
                "update_content",
                "record-1",
                '["content"]',
                "3" * 64,
                "4" * 64,
                "running",
                NOW.isoformat(),
                (NOW + timedelta(seconds=30)).isoformat(),
                "write_issuing",
            ),
        )

    store.initialize(now=NOW + timedelta(seconds=1))

    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "SELECT status, phase FROM memory_mutation_plans WHERE plan_id = 'crashed-plan'"
        ).fetchone() == ("interrupted", "reconcile_required")


def test_close_unregisters_memory_session_and_preserves_stale_recovery(
    tmp_path: Path,
) -> None:
    paths = app_paths(tmp_path)
    store = SQLiteStateStore(paths, clock=lambda: NOW)
    store.initialize(now=NOW)
    assert callable(getattr(store, "close", None))
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "INSERT INTO vault_sources(source_id, source_path, format, capabilities_json, "
            "revision, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                "vault-closed-session",
                str(tmp_path / "memory.json"),
                "json",
                "{}",
                "1" * 64,
                NOW.isoformat(),
                NOW.isoformat(),
            ),
        )
        connection.execute(
            "INSERT INTO memory_mutation_plans("
            "plan_id, source_id, digest, source_revision, operation, record_id, "
            "field_names_json, expected_old_hash, new_store_hash, status, created_at, "
            "expires_at, phase, claim_owner, claim_owner_pid, claim_owner_create_time) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "closed-session-plan",
                "vault-closed-session",
                "2" * 64,
                "1" * 64,
                "update_content",
                "record-1",
                '["content"]',
                "3" * 64,
                "4" * 64,
                "running",
                NOW.isoformat(),
                (NOW + timedelta(seconds=30)).isoformat(),
                "write_issuing",
                store._memory_session_nonce,
                store._owner_pid,
                store._owner_create_time,
            ),
        )

    store.close()
    assert store._memory_session_finalizer.alive is False
    with sqlite3.connect(store.database_path) as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM memory_sessions WHERE session_nonce = ?",
                (store._memory_session_nonce,),
            ).fetchone()[0]
            == 0
        )

    observer = SQLiteStateStore(paths, clock=lambda: NOW + timedelta(seconds=1))
    observer.initialize(now=NOW + timedelta(seconds=1))
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "SELECT status, phase FROM memory_mutation_plans WHERE plan_id = 'closed-session-plan'"
        ).fetchone() == ("interrupted", "reconcile_required")
    observer.close()


def test_memory_journal_preserves_a_live_exact_process_owner(tmp_path: Path) -> None:
    paths = app_paths(tmp_path)
    store = SQLiteStateStore(paths, clock=lambda: NOW)
    store.initialize(now=NOW)
    source_path = tmp_path / "memory.json"
    source_path.write_text("[]", encoding="utf-8")
    source = VaultSource(
        source_id=vault_source_id(source_path),
        path=str(source_path),
        format=VaultFormat.JSON,
        capabilities=VaultCapabilities(readable=True, editable=True),
        revision="1" * 64,
    )
    mutation = new_plan(
        source=source_path,
        revision="1" * 64,
        identity=FileIdentity(device=1, inode=2, size=2, mtime_ns=3, ctime_ns=4, mode=0o100600),
        operation=MutationOperation(
            kind=MutationKind.UPDATE_CONTENT,
            record_id="record-1",
            value="new",
        ),
        record_hash="7" * 64,
        field_name="content",
        old_hash="2" * 64,
        old_store_hash="1" * 64,
        new_hash="3" * 64,
        new_store_hash="4" * 64,
        now=NOW,
    )
    store.register_vault_source(source)
    store.save_memory_plan(mutation)
    store.claim_memory_plan(mutation.plan_id, expected_digest=mutation.digest)
    store.update_memory_plan_phase(mutation.plan_id, "write_issuing")

    SQLiteStateStore(
        paths,
        clock=lambda: NOW + timedelta(seconds=1),
        is_session_alive=lambda _owner: True,
    ).initialize(now=NOW + timedelta(seconds=1))

    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "SELECT status, phase FROM memory_mutation_plans WHERE plan_id = ?",
            (mutation.plan_id,),
        ).fetchone() == ("running", "write_issuing")


def test_memory_journal_sqlite_error_is_not_misclassified_or_abandoned(
    tmp_path: Path,
) -> None:
    store = SQLiteStateStore(app_paths(tmp_path))
    store.initialize(now=NOW)

    def missing_table(connection: sqlite3.Connection) -> None:
        connection.execute("UPDATE definitely_missing_table SET value=1")

    with pytest.raises(sqlite3.OperationalError) as failure:
        store._memory_journal_write(missing_table)

    assert failure.value.sqlite_errorcode & 0xFF == sqlite3.SQLITE_ERROR
    assert store._memory_session_finalizer.alive is True


def test_memory_journal_real_busy_is_retried_redacted_and_abandoned(
    tmp_path: Path,
) -> None:
    store = SQLiteStateStore(app_paths(tmp_path))
    store.initialize(now=NOW)
    blocker = sqlite3.connect(store.database_path, isolation_level=None, timeout=0.01)
    blocker.execute("PRAGMA busy_timeout=10")
    blocker.execute("BEGIN EXCLUSIVE")

    def blocked_write(connection: sqlite3.Connection) -> None:
        connection.execute(
            "UPDATE memory_sessions SET heartbeat_at=heartbeat_at WHERE session_nonce=?",
            (store._memory_session_nonce,),
        )

    try:
        with pytest.raises(MemoryError, match="journal|reconcil") as failure:
            store._memory_journal_write(blocked_write)
    finally:
        blocker.rollback()
        blocker.close()

    assert failure.value.__cause__ is None
    assert store._memory_session_finalizer.alive is False


def test_memory_journal_real_notadb_is_redacted_and_abandons(tmp_path: Path) -> None:
    store = SQLiteStateStore(app_paths(tmp_path))
    store.initialize(now=NOW)
    invalid = tmp_path / "sensitive-invalid-journal.sqlite3"
    invalid.write_bytes(b"not a sqlite database")

    def unusable_store(connection: sqlite3.Connection) -> None:
        connection.execute("ATTACH DATABASE ? AS invalid_store", (str(invalid),))
        connection.execute("SELECT * FROM invalid_store.sqlite_master").fetchall()

    with pytest.raises(MemoryError, match="journal|reconcil") as failure:
        store._memory_journal_write(unusable_store)

    assert str(invalid) not in str(failure.value)
    assert failure.value.__cause__ is None
    assert store._memory_session_finalizer.alive is False


@pytest.mark.parametrize(
    "error_code",
    [sqlite3.SQLITE_PERM, sqlite3.SQLITE_AUTH],
    ids=["perm", "auth"],
)
def test_memory_journal_security_codes_are_redacted_and_abandon(
    tmp_path: Path, error_code: int
) -> None:
    store = SQLiteStateStore(app_paths(tmp_path))
    store.initialize(now=NOW)
    attempts = 0

    def security_failure(_connection: sqlite3.Connection) -> None:
        nonlocal attempts
        attempts += 1
        error = sqlite3.OperationalError("C:/sensitive/security-policy")
        error.sqlite_errorcode = error_code
        raise error

    with pytest.raises(MemoryError, match="journal|reconcil") as failure:
        store._memory_journal_write(security_failure)

    assert attempts == 3
    assert "sensitive" not in str(failure.value)
    assert failure.value.__cause__ is None
    assert store._memory_session_finalizer.alive is False


def test_memory_claim_samples_expiry_after_waiting_for_write_lock(tmp_path: Path) -> None:
    paths = app_paths(tmp_path)
    clock = MutableClock(NOW)
    store = SQLiteStateStore(paths, clock=clock, busy_timeout_ms=2_000)
    store.initialize(now=NOW)
    source_path = tmp_path / "selected-memory.json"
    source_path.write_text("[]", encoding="utf-8")
    source = VaultSource(
        source_id=vault_source_id(source_path),
        path=str(source_path),
        format=VaultFormat.JSON,
        capabilities=VaultCapabilities(readable=True, editable=True),
        revision="1" * 64,
    )
    mutation = new_plan(
        source=source_path,
        revision="1" * 64,
        identity=FileIdentity(device=1, inode=2, size=2, mtime_ns=3, ctime_ns=4, mode=0o100600),
        operation=MutationOperation(
            kind=MutationKind.UPDATE_CONTENT,
            record_id="record-1",
            value="new",
        ),
        record_hash="7" * 64,
        field_name="content",
        old_hash="2" * 64,
        old_store_hash="1" * 64,
        new_hash="3" * 64,
        new_store_hash="4" * 64,
        now=NOW,
    )
    store.register_vault_source(source)
    store.save_memory_plan(mutation)
    blocker = sqlite3.connect(store.database_path, isolation_level=None)
    blocker.execute("BEGIN IMMEDIATE")
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            claim = pool.submit(
                store.claim_memory_plan,
                mutation.plan_id,
                expected_digest=mutation.digest,
            )
            time.sleep(0.05)
            clock.value = mutation.expires_at + timedelta(milliseconds=1)
            blocker.commit()
            with pytest.raises(ExpiredPlanError):
                claim.result(timeout=2)
    finally:
        if blocker.in_transaction:
            blocker.rollback()
        blocker.close()


def test_supported_v1_schema_migrates_without_losing_settings(tmp_path: Path) -> None:
    paths = app_paths(tmp_path)
    paths.state_dir.mkdir(parents=True)
    database = paths.state_dir / "zombie-killer.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE schema_versions (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            );
            INSERT INTO schema_versions(version, applied_at)
            VALUES (1, '2026-08-12T00:00:00.000000Z');
            PRAGMA user_version = 1;
            CREATE TABLE settings (
                key TEXT PRIMARY KEY,
                value_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            INSERT INTO settings(key, value_json, updated_at)
            VALUES ('theme', '"dark"', '2026-08-12T00:00:00.000000Z');
            """
        )

    store = SQLiteStateStore(paths)
    store.initialize()

    assert store.get_setting("theme") == "dark"
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == store.schema_version
        assert (
            connection.execute("SELECT COUNT(*) FROM schema_versions WHERE version = 2").fetchone()[
                0
            ]
            == 1
        )


def test_failed_migration_rolls_back_schema_changes_atomically(tmp_path: Path) -> None:
    paths = app_paths(tmp_path)
    paths.state_dir.mkdir(parents=True)
    database = paths.state_dir / "zombie-killer.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE schema_versions (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            );
            INSERT INTO schema_versions(version, applied_at)
            VALUES (1, '2026-08-12T00:00:00.000000Z');
            PRAGMA user_version = 1;
            CREATE TABLE settings (
                key TEXT PRIMARY KEY,
                value_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )

    class FailingConnection:
        def __init__(self, connection: sqlite3.Connection) -> None:
            self.connection = connection

        def __enter__(self) -> FailingConnection:
            self.connection.__enter__()
            return self

        def __exit__(
            self,
            exc_type: type[BaseException] | None,
            exc_value: BaseException | None,
            traceback: TracebackType | None,
        ) -> bool:
            return self.connection.__exit__(exc_type, exc_value, traceback)

        def __getattr__(self, name: str) -> object:
            return getattr(self.connection, name)

        def execute(self, statement: str, parameters: tuple[object, ...] = ()) -> sqlite3.Cursor:
            if "CREATE TABLE IF NOT EXISTS audit_events" in statement:
                raise sqlite3.OperationalError("synthetic migration interruption")
            return self.connection.execute(statement, parameters)

        def executescript(self, script: str) -> sqlite3.Cursor:
            self.connection.executescript(script)
            raise sqlite3.OperationalError("synthetic migration interruption")

    class FailingStore(SQLiteStateStore):
        def _connect(self, *, allow_missing: bool = False) -> sqlite3.Connection:
            return FailingConnection(  # type: ignore[return-value]
                super()._connect(allow_missing=allow_missing)
            )

    with pytest.raises(sqlite3.OperationalError):
        FailingStore(paths).initialize(now=NOW)

    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
        assert (
            connection.execute("SELECT COUNT(*) FROM schema_versions WHERE version = 2").fetchone()[
                0
            ]
            == 0
        )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'receipts'"
            ).fetchone()[0]
            == 0
        )


def test_plan_receipt_and_settings_round_trip_with_explicit_utc(tmp_path: Path) -> None:
    store = SQLiteStateStore(
        app_paths(tmp_path),
        clock=lambda: NOW + timedelta(seconds=1),
        session_id="synthetic-session",
    )
    store.initialize()
    action_plan = plan()

    store.save_plan(action_plan)
    claimed = store.claim_plan(
        action_plan.plan_id,
        expected_digest=action_plan.digest,
    )
    store.update_plan_phase(action_plan.plan_id, "validated")
    store.update_plan_phase(action_plan.plan_id, "action_issuing")
    store.update_plan_phase(action_plan.plan_id, "action_issued")
    store.update_plan_phase(action_plan.plan_id, "verifying")
    action_receipt = receipt(claimed)
    store.finish_plan(action_receipt)
    store.set_setting("ui", {"theme": "dark", "count": 3}, now=NOW)

    loaded = store.get_plan(action_plan.plan_id)
    assert loaded is not None
    assert loaded.status is PlanStatus.SUCCEEDED
    assert loaded.created_at.tzinfo is UTC
    assert loaded.expires_at.tzinfo is UTC
    assert store.list_receipts(action_plan.plan_id) == (action_receipt,)
    assert store.get_setting("ui") == {"theme": "dark", "count": 3}


def test_settings_compare_and_swap_is_persisted_across_store_instances(
    tmp_path: Path,
) -> None:
    paths = app_paths(tmp_path)
    first = SQLiteStateStore(paths)
    second = SQLiteStateStore(paths)
    first.initialize(now=NOW)
    second.initialize(now=NOW)
    assert callable(getattr(first, "get_settings", None))
    assert callable(getattr(first, "update_settings", None))

    initial, initial_revision = first.get_settings()
    assert initial == {}
    assert initial_revision == 0
    updated, updated_revision = first.update_settings(
        {
            "scan_interval_seconds": 45,
            "heartbeat_grace_seconds": 180,
            "retention_days": 60,
            "include_unmanaged_candidates": False,
            "appearance": "dark",
            "reduced_motion": True,
        },
        expected_revision=initial_revision,
        now=NOW,
    )

    assert updated_revision == 1
    assert updated["appearance"] == "dark"
    with pytest.raises(StoreError, match="settings revision"):
        second.update_settings(
            {"appearance": "light"},
            expected_revision=initial_revision,
            now=NOW + timedelta(seconds=1),
        )
    observed, observed_revision = second.get_settings()
    assert observed == updated
    assert observed_revision == updated_revision


def test_settings_multi_key_failure_rolls_back_values_and_revision(tmp_path: Path) -> None:
    store = SQLiteStateStore(app_paths(tmp_path))
    store.initialize(now=NOW)
    assert callable(getattr(store, "get_settings", None))
    assert callable(getattr(store, "update_settings", None))
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "CREATE TRIGGER fail_second_setting BEFORE INSERT ON settings "
            "WHEN NEW.key = 'reduced_motion' BEGIN "
            "SELECT RAISE(ABORT, 'synthetic second-key failure'); END"
        )

    with pytest.raises(sqlite3.IntegrityError, match="second-key failure"):
        store.update_settings(
            {"appearance": "dark", "reduced_motion": True},
            expected_revision=0,
            now=NOW,
        )

    settings, revision = store.get_settings()
    assert settings == {}
    assert revision == 0


def test_plan_storage_is_canonical_and_contains_only_hashed_display_identity(
    tmp_path: Path,
) -> None:
    store = SQLiteStateStore(app_paths(tmp_path), clock=lambda: NOW)
    store.initialize()
    raw_executable = "/private/customer-alpha/runtime/python"
    raw_user = "private-customer-alpha-user"
    raw_warning_secret = "synthetic-warning-secret"
    action_plan = ActionPlan.create(
        identity=IDENTITY.model_copy(update={"executable": raw_executable, "user": raw_user}),
        mode=ActionMode.TERMINATE,
        agent_id="synthetic-agent",
        managed=True,
        warnings=(f"tool --api-key {raw_warning_secret} ready",),
        consequences=("Synthetic consequence.",),
        created_at=NOW,
        platform_name="linux",
    )

    store.save_plan(action_plan)

    with sqlite3.connect(store.database_path) as connection:
        stored_json = str(
            connection.execute(
                "SELECT plan_json FROM action_plans WHERE plan_id = ?",
                (action_plan.plan_id,),
            ).fetchone()[0]
        )
    assert raw_executable not in stored_json
    assert raw_user not in stored_json
    assert raw_warning_secret not in stored_json
    assert action_plan.identity.executable_hash is not None
    assert action_plan.identity.user_hash is not None
    assert store.get_plan(action_plan.plan_id) == action_plan


@pytest.mark.parametrize(
    "corrupt_json",
    [
        "not-json",
        '{"plan_id":"synthetic-corrupt-plan"}',
    ],
)
def test_corrupt_stored_plan_is_never_claimed_or_transitioned(
    tmp_path: Path,
    corrupt_json: str,
) -> None:
    store = SQLiteStateStore(app_paths(tmp_path), clock=lambda: NOW)
    store.initialize()
    action_plan = plan()
    store.save_plan(action_plan)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE action_plans SET plan_json = ? WHERE plan_id = ?",
            (corrupt_json, action_plan.plan_id),
        )

    with pytest.raises(PlanClaimError, match="stored plan"):
        store.claim_plan(
            action_plan.plan_id,
            expected_digest=action_plan.digest,
        )

    with sqlite3.connect(store.database_path) as connection:
        status = connection.execute(
            "SELECT status FROM action_plans WHERE plan_id = ?",
            (action_plan.plan_id,),
        ).fetchone()[0]
    assert status == PlanStatus.PLANNED.value


def test_digest_tampered_stored_plan_is_never_claimed(tmp_path: Path) -> None:
    store = SQLiteStateStore(app_paths(tmp_path), clock=lambda: NOW)
    store.initialize()
    action_plan = plan()
    store.save_plan(action_plan)
    with sqlite3.connect(store.database_path) as connection:
        stored_json = str(
            connection.execute(
                "SELECT plan_json FROM action_plans WHERE plan_id = ?",
                (action_plan.plan_id,),
            ).fetchone()[0]
        )
        tampered = json.loads(stored_json)
        tampered["identity"]["pid"] += 1
        connection.execute(
            "UPDATE action_plans SET plan_json = ? WHERE plan_id = ?",
            (json.dumps(tampered), action_plan.plan_id),
        )

    with pytest.raises(PlanClaimError, match="stored plan"):
        store.claim_plan(
            action_plan.plan_id,
            expected_digest=action_plan.digest,
        )

    with sqlite3.connect(store.database_path) as connection:
        status = connection.execute(
            "SELECT status FROM action_plans WHERE plan_id = ?",
            (action_plan.plan_id,),
        ).fetchone()[0]
    assert status == PlanStatus.PLANNED.value


def test_expired_plan_is_refused_and_marked_terminal(tmp_path: Path) -> None:
    store = SQLiteStateStore(app_paths(tmp_path), clock=lambda: NOW)
    store.initialize()
    expired = plan(created_at=NOW - timedelta(seconds=31))
    store.save_plan(expired)

    with pytest.raises(ExpiredPlanError):
        store.claim_plan(
            expired.plan_id,
            expected_digest=expired.digest,
        )

    loaded = store.get_plan(expired.plan_id)
    assert loaded is not None
    assert loaded.status is PlanStatus.EXPIRED


def test_claim_samples_clock_only_after_obtaining_write_lock(tmp_path: Path) -> None:
    clock = MutableClock(NOW)
    store = SQLiteStateStore(
        app_paths(tmp_path),
        clock=clock,
        session_id="claim-session-a",
        busy_timeout_ms=5_000,
    )
    store.initialize(now=NOW)
    action_plan = plan()
    store.save_plan(action_plan)
    lock = sqlite3.connect(store.database_path, isolation_level=None)
    lock.execute("BEGIN IMMEDIATE")
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(
                store.claim_plan,
                action_plan.plan_id,
                expected_digest=action_plan.digest,
            )
            time.sleep(0.05)
            assert future.done() is False
            clock.value = action_plan.expires_at
            lock.commit()
            with pytest.raises(ExpiredPlanError):
                future.result(timeout=3)
    finally:
        if lock.in_transaction:
            lock.rollback()
        lock.close()

    loaded = store.get_plan(action_plan.plan_id)
    assert loaded is not None
    assert loaded.status is PlanStatus.EXPIRED


def test_plan_claim_is_digest_checked_and_exactly_once(tmp_path: Path) -> None:
    store = SQLiteStateStore(app_paths(tmp_path), clock=lambda: NOW)
    store.initialize()
    action_plan = plan()
    store.save_plan(action_plan)

    with pytest.raises(PlanClaimError, match="digest"):
        store.claim_plan(action_plan.plan_id, expected_digest="0" * 64)

    claimed = store.claim_plan(
        action_plan.plan_id,
        expected_digest=action_plan.digest,
    )
    assert claimed.status is PlanStatus.RUNNING
    with pytest.raises(PlanClaimError, match="PLANNED"):
        store.claim_plan(
            action_plan.plan_id,
            expected_digest=action_plan.digest,
        )


def test_receipt_must_match_the_claimed_plan_identity_and_action(tmp_path: Path) -> None:
    store = SQLiteStateStore(
        app_paths(tmp_path),
        clock=lambda: NOW,
        session_id="synthetic-session",
    )
    store.initialize()
    action_plan = plan()
    store.save_plan(action_plan)
    claimed = store.claim_plan(
        action_plan.plan_id,
        expected_digest=action_plan.digest,
    )
    mismatched = receipt(claimed).model_copy(
        update={"target": IDENTITY.model_copy(update={"pid": IDENTITY.pid + 1})}
    )

    with pytest.raises(StoreError, match="does not match"):
        store.finish_plan(mismatched)

    assert store.list_receipts(action_plan.plan_id) == ()
    loaded = store.get_plan(action_plan.plan_id)
    assert loaded is not None
    assert loaded.status is PlanStatus.RUNNING


def test_receipt_result_derives_terminal_status_and_validates_claim_time(
    tmp_path: Path,
) -> None:
    clock = MutableClock(NOW)
    store = SQLiteStateStore(
        app_paths(tmp_path),
        clock=clock,
        session_id="claim-session-a",
    )
    store.initialize(now=NOW)
    action_plan = plan()
    store.save_plan(action_plan)
    claimed = store.claim_plan(
        action_plan.plan_id,
        expected_digest=action_plan.digest,
    )
    before_claim = ActionReceipt.create(
        plan=claimed,
        actor="synthetic-user",
        session_id=store.session_id,
        result=ActionResult.FAILED,
        before="running",
        after="failed",
        started_at=NOW - timedelta(seconds=1),
        finished_at=NOW + timedelta(seconds=1),
    )

    with pytest.raises(StoreError, match="claim"):
        store.finish_plan(before_claim)

    failed = before_claim.model_copy(
        update={
            "receipt_id": "failed-receipt",
            "started_at": NOW,
        }
    )
    store.finish_plan(failed)

    loaded = store.get_plan(action_plan.plan_id)
    assert loaded is not None
    assert loaded.status is PlanStatus.FAILED


def test_receipt_text_and_actor_session_are_secret_free_before_persistence(
    tmp_path: Path,
) -> None:
    secret = "synthetic" + "-credential-value"
    userinfo_tail = "fixture-userinfo-tail"
    jwt = ".".join(("a" * 12, "b" * 12, "c" * 12))
    store = SQLiteStateStore(
        app_paths(tmp_path),
        clock=lambda: NOW,
        session_id="https://alice:" + secret + "@" + userinfo_tail + "@example.test/session",
    )
    store.initialize(now=NOW)
    action_plan = plan()
    store.save_plan(action_plan)
    claimed = store.claim_plan(
        action_plan.plan_id,
        expected_digest=action_plan.digest,
    )
    action_receipt = ActionReceipt.create(
        plan=claimed,
        actor="Bearer " + secret,
        session_id=store.session_id,
        result=ActionResult.FAILED,
        before="api_" + "key=" + secret,
        after="https://alice:" + secret + "@" + userinfo_tail + "@example.test/result",
        started_at=NOW,
        finished_at=NOW + timedelta(seconds=1),
        partial_failures=(jwt, "password=" + secret),
        restore_reference="token=" + secret,
    )

    serialized_receipt = action_receipt.model_dump_json()
    assert secret not in serialized_receipt
    assert jwt not in serialized_receipt
    action_receipt = action_receipt.model_copy(update={"after": "Bearer " + secret})
    store.finish_plan(action_receipt)
    store.record_audit_event(
        correlation_id=jwt,
        event_type="api_" + "key=" + secret,
        details={
            "result": "Bearer " + secret,
            "resource_ids": (
                "https://alice:" + secret + "@" + userinfo_tail + "@example.test/resource",
            ),
        },
        now=NOW + timedelta(seconds=2),
    )
    with sqlite3.connect(store.database_path) as connection:
        database_dump = "\n".join(connection.iterdump())
    assert secret not in database_dump
    assert userinfo_tail not in database_dump
    assert jwt not in database_dump


def test_startup_reconciles_stale_running_plans_as_interrupted(tmp_path: Path) -> None:
    paths = app_paths(tmp_path)
    first = SQLiteStateStore(
        paths,
        clock=lambda: NOW,
        session_id="claim-session-a",
    )
    first.initialize()
    action_plan = plan()
    first.save_plan(action_plan)
    first.claim_plan(action_plan.plan_id, expected_digest=action_plan.digest)
    first.update_plan_phase(action_plan.plan_id, "validated")
    first.update_plan_phase(action_plan.plan_id, "action_issuing")
    first.update_plan_phase(action_plan.plan_id, "action_issued")
    first.update_plan_phase(action_plan.plan_id, "verifying")
    with sqlite3.connect(first.database_path) as connection:
        claim_owner = str(
            connection.execute(
                "SELECT claim_owner FROM action_plans WHERE plan_id = ?",
                (action_plan.plan_id,),
            ).fetchone()[0]
        )

    second = SQLiteStateStore(
        paths,
        session_id="claim-session-b",
        is_session_alive=lambda _owner: False,
    )
    second.initialize(now=NOW + timedelta(minutes=1))

    loaded = second.get_plan(action_plan.plan_id)
    assert loaded is not None
    assert loaded.status is PlanStatus.INTERRUPTED
    receipts = second.list_receipts(action_plan.plan_id)
    assert len(receipts) == 1
    assert receipts[0].result is ActionResult.INTERRUPTED
    assert receipts[0].action_issued is None
    assert receipts[0].session_id == claim_owner


def test_startup_interrupts_dead_owner_before_plan_expiry(tmp_path: Path) -> None:
    paths = app_paths(tmp_path)
    first = SQLiteStateStore(
        paths,
        clock=lambda: NOW,
        session_id="claim-session-a",
    )
    first.initialize()
    action_plan = plan()
    first.save_plan(action_plan)
    first.claim_plan(action_plan.plan_id, expected_digest=action_plan.digest)

    second = SQLiteStateStore(
        paths,
        clock=lambda: NOW + timedelta(seconds=2),
        session_id="claim-session-b",
        is_session_alive=lambda _owner: False,
    )
    second.initialize(now=NOW + timedelta(seconds=2))

    loaded = first.get_plan(action_plan.plan_id)
    assert loaded is not None
    assert loaded.status is PlanStatus.INTERRUPTED
    receipts = second.list_receipts(action_plan.plan_id)
    assert len(receipts) == 1
    assert receipts[0].result is ActionResult.INTERRUPTED


def test_lazy_reconciliation_interrupts_running_claim_after_expiry(
    tmp_path: Path,
) -> None:
    paths = app_paths(tmp_path)
    clock = MutableClock(NOW)
    first = SQLiteStateStore(
        paths,
        clock=clock,
        session_id="claim-session-a",
    )
    first.initialize(now=NOW)
    action_plan = plan()
    first.save_plan(action_plan)
    first.claim_plan(action_plan.plan_id, expected_digest=action_plan.digest)
    second = SQLiteStateStore(
        paths,
        clock=clock,
        session_id="claim-session-b",
        is_session_alive=lambda _owner: True,
    )
    second.initialize(now=NOW + timedelta(seconds=1))
    clock.value = action_plan.expires_at

    loaded = second.get_plan(action_plan.plan_id)

    assert loaded is not None
    assert loaded.status is PlanStatus.INTERRUPTED
    assert len(second.list_receipts(action_plan.plan_id)) == 1


def test_json_is_bounded_and_audit_rejects_unknown_sensitive_fields(tmp_path: Path) -> None:
    store = SQLiteStateStore(app_paths(tmp_path), max_json_bytes=1024)
    store.initialize()

    with pytest.raises(ValueError, match="JSON payload"):
        store.set_setting("oversized", "x" * 4096, now=NOW)

    with pytest.raises(ValidationError, match="extra_forbidden"):
        store.record_audit_event(
            correlation_id="synthetic-correlation",
            event_type="synthetic-event",
            details={
                "result": "completed",
                "memory_contents": "synthetic raw memory contents",
                "credential_blob": {"nested": "synthetic credential"},
            },
            now=NOW,
        )

    with pytest.raises(ValidationError):
        store.record_audit_event(
            correlation_id="",
            event_type="synthetic-event",
            details={"result": "completed"},
            now=NOW,
        )

    event_id = store.record_audit_event(
        correlation_id="synthetic-correlation",
        event_type="synthetic-event",
        details=AuditEventDetails(
            result="completed",
            target_hash="a" * 64,
            resource_ids=("synthetic-resource",),
        ),
        now=NOW,
    )
    event = store.get_audit_event(event_id)
    details = event["details"]
    assert isinstance(details, dict)
    assert details == {
        "metadata_hashes": [],
        "resource_ids": ["synthetic-resource"],
        "result": "completed",
        "target_hash": "a" * 64,
    }


def test_database_is_created_only_under_injected_state_directory(tmp_path: Path) -> None:
    paths = app_paths(tmp_path)
    store = SQLiteStateStore(paths)

    store.initialize()

    assert store.database_path.parent == paths.state_dir
    assert store.database_path.is_file()
    if os.name != "nt":
        assert store.database_path.stat().st_mode & 0o077 == 0


@pytest.mark.skipif(os.name != "nt", reason="Windows DACL verification")
def test_windows_database_file_has_protected_dacl(tmp_path: Path) -> None:
    store = SQLiteStateStore(app_paths(tmp_path))
    store.initialize()
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32.CreateFileW.restype = ctypes.c_void_p
    handle = kernel32.CreateFileW(
        str(store.database_path),
        0x00020000,
        0x00000007,
        None,
        3,
        0x00200000,
        None,
    )
    assert handle != ctypes.c_void_p(-1).value
    try:
        required = ctypes.c_ulong()
        advapi32.GetKernelObjectSecurity(
            handle,
            0x00000004,
            None,
            0,
            ctypes.byref(required),
        )
        descriptor = ctypes.create_string_buffer(required.value)
        assert advapi32.GetKernelObjectSecurity(
            handle,
            0x00000004,
            descriptor,
            required.value,
            ctypes.byref(required),
        )
        control = ctypes.c_ushort()
        revision = ctypes.c_ulong()
        assert advapi32.GetSecurityDescriptorControl(
            descriptor,
            ctypes.byref(control),
            ctypes.byref(revision),
        )
        assert control.value & 0x1000
    finally:
        kernel32.CloseHandle(handle)


def test_permission_backend_failure_aborts_initialization(tmp_path: Path) -> None:
    class RejectingSecurityBackend:
        def prepare_state_directory(self, path: Path) -> None:
            raise PermissionError("synthetic permission failure")

        def secure_database(self, path: Path, *, allow_missing: bool) -> None:
            raise AssertionError("database security must not run")

    store = SQLiteStateStore(
        app_paths(tmp_path),
        security_backend=RejectingSecurityBackend(),
    )

    with pytest.raises(PermissionError, match="synthetic permission failure"):
        store.initialize()
    assert not store.database_path.exists()


def test_existing_nonregular_database_target_is_rejected(tmp_path: Path) -> None:
    app = app_paths(tmp_path)
    app.state_dir.mkdir(parents=True)
    (app.state_dir / "zombie-killer.sqlite3").mkdir()

    with pytest.raises(StorePathError, match="regular"):
        SQLiteStateStore(app).initialize()


def test_database_symlink_is_rejected_before_target_is_opened(tmp_path: Path) -> None:
    app = app_paths(tmp_path)
    app.state_dir.mkdir(parents=True)
    target = tmp_path / "outside-target.sqlite3"
    target.write_bytes(b"must remain unchanged")
    link = app.state_dir / "zombie-killer.sqlite3"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(StorePathError, match="link|reparse"):
        SQLiteStateStore(app).initialize()

    assert target.read_bytes() == b"must remain unchanged"


def test_startup_does_not_interrupt_another_live_executor_session(
    tmp_path: Path,
) -> None:
    paths = app_paths(tmp_path)
    first = SQLiteStateStore(paths, clock=MutableClock(), session_id="live-session-a")
    first.initialize(now=NOW)
    action_plan = plan()
    first.save_plan(action_plan)
    first.claim_plan(action_plan.plan_id, expected_digest=action_plan.digest)

    second = SQLiteStateStore(paths, clock=MutableClock(), session_id="live-session-b")
    second.initialize(now=NOW + timedelta(seconds=1))

    persisted = second.get_plan(action_plan.plan_id)
    assert persisted is not None
    assert persisted.status is PlanStatus.RUNNING
    assert second.list_receipts(action_plan.plan_id) == ()


def test_startup_does_not_interrupt_owner_when_liveness_is_access_denied(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = app_paths(tmp_path)
    first = SQLiteStateStore(paths, clock=MutableClock(), session_id="elevated-owner")
    first.initialize(now=NOW)
    action_plan = plan()
    first.save_plan(action_plan)
    first.claim_plan(action_plan.plan_id, expected_digest=action_plan.digest)
    second = SQLiteStateStore(paths, clock=MutableClock(), session_id="observer")

    def access_denied(_pid: int) -> object:
        raise psutil.AccessDenied(_pid)

    monkeypatch.setattr(
        "zombie_killer_engine.store.psutil.Process",
        access_denied,
    )
    second.initialize(now=NOW + timedelta(seconds=1))

    persisted = second.get_plan(action_plan.plan_id)
    assert persisted is not None
    assert persisted.status is PlanStatus.RUNNING


def test_finish_rejects_success_before_an_action_was_issued(tmp_path: Path) -> None:
    store = SQLiteStateStore(
        app_paths(tmp_path),
        clock=MutableClock(),
        session_id="receipt-integrity-session",
    )
    store.initialize(now=NOW)
    action_plan = plan()
    store.save_plan(action_plan)
    claimed = store.claim_plan(
        action_plan.plan_id,
        expected_digest=action_plan.digest,
    )
    forged = ActionReceipt.create(
        plan=claimed,
        actor="local-user",
        session_id=store.session_id,
        result=ActionResult.COMPLETED,
        action_issued=False,
        before="running",
        after="original_instance_ended",
        started_at=NOW + timedelta(seconds=1),
        finished_at=NOW + timedelta(seconds=2),
    )

    with pytest.raises(StoreError, match="phase|outcome"):
        store.finish_plan(forged)

    persisted = store.get_plan(action_plan.plan_id)
    assert persisted is not None
    assert persisted.status is PlanStatus.RUNNING

    store.update_plan_phase(action_plan.plan_id, "validated")
    store.update_plan_phase(action_plan.plan_id, "action_issuing")
    store.update_plan_phase(action_plan.plan_id, "action_issued")
    issued_only = forged.model_copy(
        update={
            "receipt_id": "issued-only-receipt",
            "action_issued": True,
        }
    )
    with pytest.raises(StoreError, match="phase"):
        store.finish_plan(issued_only)

    store.update_plan_phase(action_plan.plan_id, "verifying")
    wrong_mode = issued_only.model_copy(
        update={
            "receipt_id": "wrong-mode-receipt",
            "result": ActionResult.REQUESTED,
        }
    )
    with pytest.raises(StoreError, match="phase"):
        store.finish_plan(wrong_mode)


def test_action_phase_transitions_cannot_skip_the_side_effect_boundary(
    tmp_path: Path,
) -> None:
    store = SQLiteStateStore(
        app_paths(tmp_path),
        clock=MutableClock(),
        session_id="phase-session",
    )
    store.initialize(now=NOW)
    action_plan = plan()
    store.save_plan(action_plan)
    store.claim_plan(action_plan.plan_id, expected_digest=action_plan.digest)

    with pytest.raises(StoreError, match="phase"):
        store.update_plan_phase(action_plan.plan_id, "action_issued")

    store.update_plan_phase(action_plan.plan_id, "validated")
    store.update_plan_phase(action_plan.plan_id, "action_issuing")
    store.update_plan_phase(action_plan.plan_id, "action_issued")
    store.update_plan_phase(action_plan.plan_id, "verifying")


def test_receipt_effect_state_cannot_contradict_action_issuing_phase(
    tmp_path: Path,
) -> None:
    store = SQLiteStateStore(
        app_paths(tmp_path),
        clock=MutableClock(),
        session_id="effect-integrity-session",
    )
    store.initialize(now=NOW)
    action_plan = plan()
    store.save_plan(action_plan)
    claimed = store.claim_plan(
        action_plan.plan_id,
        expected_digest=action_plan.digest,
    )
    store.update_plan_phase(action_plan.plan_id, "validated")
    store.update_plan_phase(action_plan.plan_id, "action_issuing")
    uncertain_but_failed = ActionReceipt.create(
        plan=claimed,
        actor="local-user",
        session_id=store.session_id,
        result=ActionResult.FAILED,
        action_issued=None,
        before="running",
        after="failed",
        started_at=NOW + timedelta(seconds=1),
        finished_at=NOW + timedelta(seconds=2),
    )
    definite_but_interrupted = uncertain_but_failed.model_copy(
        update={
            "receipt_id": "contradictory-effect-receipt",
            "result": ActionResult.INTERRUPTED,
            "action_issued": False,
        }
    )

    with pytest.raises(StoreError, match="effect|phase"):
        store.finish_plan(uncertain_but_failed)
    with pytest.raises(StoreError, match="effect|phase"):
        store.finish_plan(definite_but_interrupted)
