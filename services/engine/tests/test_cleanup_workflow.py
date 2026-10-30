from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from zombie_killer.lease import current_process_identity, validate_temp_resource
from zombie_killer_engine.actions import process_instance_id
from zombie_killer_engine.models import ProcessIdentity
from zombie_killer_engine.paths import AppPaths, PosixPermissionBackend, WindowsPermissionBackend
from zombie_killer_engine.quarantine import CleanupRejectedError
from zombie_killer_engine.store import PlanClaimError, SQLiteStateStore

NOW = datetime(2026, 10, 2, 12, 0, tzinfo=UTC)


def fixture(
    tmp_path: Path, *, directory: bool = False
) -> tuple[
    AppPaths,
    Path,
    Path,
    dict[str, object],
    str,
]:
    paths = AppPaths(
        data_dir=tmp_path / "data",
        state_dir=tmp_path / "state",
        runtime_dir=tmp_path / "runtime",
        backups_dir=tmp_path / "backups",
        graveyard_dir=tmp_path / "graveyard",
    )
    assert not paths.ensure()
    root = tmp_path / "approved"
    root.mkdir(mode=0o700)
    backend = WindowsPermissionBackend() if os.name == "nt" else PosixPermissionBackend()
    backend.restrict(root)
    target = root / ("tree" if directory else "artifact.bin")
    if directory:
        (target / "nested").mkdir(parents=True)
        (target / "nested" / "artifact.bin").write_bytes(b"declared nested bytes")
    else:
        target.write_bytes(b"declared file bytes")
    identity = current_process_identity()
    lease = {
        "protocol_version": 1,
        "agent_id": "fixture-agent",
        "registration_nonce": "fixture-registration-generation-1",
        "identity": identity.as_dict(),
        "heartbeat_at": NOW.isoformat(),
        "heartbeat_timeout_seconds": 120.0,
        "resources": [validate_temp_resource(target, root=root)],
    }
    (paths.leases_dir / "fixture-agent.json").write_text(json.dumps(lease), encoding="utf-8")
    assert identity.user is not None
    return paths, root, target, lease, identity.user


def workflow(paths: AppPaths, user: str) -> object:
    from zombie_killer_engine.cleanup_workflow import CleanupWorkflow

    store = SQLiteStateStore(paths, clock=lambda: NOW)
    store.initialize(now=NOW)
    return CleanupWorkflow(store, paths, current_user=user, clock=lambda: NOW)


def reviewed_plan(candidate: object) -> dict[str, object]:
    declaration = candidate.list_resources("fixture-agent")["resources"][0]
    return candidate.plan(
        "fixture-agent", 0, expected_declaration_digest=declaration["declaration_digest"]
    )


@pytest.mark.parametrize("changed", ["nonce", "identity", "resource"])
def test_stale_resource_selection_cannot_plan_a_new_declaration(
    tmp_path: Path, changed: str
) -> None:
    paths, root, target, lease, user = fixture(tmp_path)
    candidate = workflow(paths, user)
    reviewed = candidate.list_resources("fixture-agent")["resources"][0]
    assert reviewed.get("declaration_digest") is not None
    if changed == "nonce":
        lease["registration_nonce"] = "new-registration-same-process"
    elif changed == "identity":
        lease["identity"]["create_time"] += 1.0
    else:
        replacement = root / "different-declaration.bin"
        replacement.write_bytes(b"same process declared different resource")
        lease["resources"] = [validate_temp_resource(replacement, root=root)]
    (paths.leases_dir / "fixture-agent.json").write_text(json.dumps(lease), encoding="utf-8")
    refreshed = candidate.list_resources("fixture-agent")["resources"][0]
    assert refreshed["declaration_digest"] != reviewed["declaration_digest"]

    with pytest.raises(CleanupRejectedError, match="declaration"):
        candidate.plan(
            "fixture-agent", 0, expected_declaration_digest=reviewed["declaration_digest"]
        )

    assert target.read_bytes() == b"declared file bytes"
    assert candidate._store.list_quarantine_entries() == ()


@pytest.mark.parametrize("wrong", ["pid", "instance", "missing_pid", "missing_instance"])
def test_resource_selection_checks_expected_process_pair(tmp_path: Path, wrong: str) -> None:
    paths, _, _, lease, user = fixture(tmp_path)
    candidate = workflow(paths, user)
    identity = ProcessIdentity.model_validate(lease["identity"])
    instance_id = process_instance_id(identity)
    digest = candidate.list_resources(
        "fixture-agent", expected_pid=identity.pid, expected_process_instance_id=instance_id
    )["resources"][0]["declaration_digest"]
    expected_pid = None if wrong == "missing_pid" else identity.pid + (wrong == "pid")
    expected_instance = (
        None if wrong == "missing_instance" else ("0" * 64 if wrong == "instance" else instance_id)
    )
    with pytest.raises(CleanupRejectedError, match="process"):
        candidate.list_resources(
            "fixture-agent",
            expected_pid=expected_pid,
            expected_process_instance_id=expected_instance,
        )
    with pytest.raises(CleanupRejectedError, match="process"):
        candidate.plan(
            "fixture-agent",
            0,
            expected_declaration_digest=digest,
            expected_pid=expected_pid,
            expected_process_instance_id=expected_instance,
        )


def test_resource_declaration_digest_excludes_heartbeat_and_presentation_status(
    tmp_path: Path,
) -> None:
    paths, _, _, lease, user = fixture(tmp_path)
    candidate = workflow(paths, user)
    digest = candidate.list_resources("fixture-agent")["resources"][0].get("declaration_digest")
    assert isinstance(digest, str) and len(digest) == 64
    lease["heartbeat_at"] = (NOW + timedelta(seconds=1)).isoformat()
    lease["status"] = "busy"
    (paths.leases_dir / "fixture-agent.json").write_text(json.dumps(lease), encoding="utf-8")
    assert candidate.list_resources("fixture-agent")["resources"][0]["declaration_digest"] == digest
    assert candidate.plan("fixture-agent", 0, expected_declaration_digest=digest)["plan_id"]


@pytest.mark.parametrize("directory", [False, True])
def test_separate_instances_quarantine_and_restore_declared_bytes(
    tmp_path: Path,
    directory: bool,
) -> None:
    paths, _, target, _, user = fixture(tmp_path, directory=directory)
    first = workflow(paths, user)
    listed = first.list_resources("fixture-agent")
    assert listed["returned"] == 1
    assert listed["resources"][0]["resource_index"] == 0
    assert listed["resources"][0]["cleanup_available"] is True
    assert "path" not in listed["resources"][0]
    plan = first.plan(
        "fixture-agent", 0, expected_declaration_digest=listed["resources"][0]["declaration_digest"]
    )

    second = workflow(paths, user)
    receipt = second.execute(plan["plan_id"], plan["digest"])
    assert receipt["outcome"] == "quarantined"
    assert receipt["kind"] == "quarantine"
    assert not target.exists()
    assert second.execute(plan["plan_id"], plan["digest"])["receipt_id"] == receipt["receipt_id"]
    # Restoration remains possible after the creating registration ended.
    (paths.leases_dir / "fixture-agent.json").unlink()
    entry = second._store.list_quarantine_entries()[0].entry
    restore = workflow(paths, user).restore_plan(entry.entry_id)
    restored = workflow(paths, user).restore_execute(restore["plan_id"], restore["digest"])
    assert restored["outcome"] == "restored"
    assert restored["kind"] == "quarantine"
    assert restored["plan_id"] == restore["plan_id"]
    actual = (target / "nested" / "artifact.bin").read_bytes() if directory else target.read_bytes()
    assert actual == (b"declared nested bytes" if directory else b"declared file bytes")
    assert workflow(paths, user).restore_execute(restore["plan_id"], restore["digest"]) == restored


def test_legacy_declaration_is_visible_without_cleanup_authority(tmp_path: Path) -> None:
    paths, _, target, lease, user = fixture(tmp_path)
    lease["resources"] = [{"kind": "temporary", "path": str(target)}]
    (paths.leases_dir / "fixture-agent.json").write_text(json.dumps(lease), encoding="utf-8")
    candidate = workflow(paths, user)
    listed = candidate.list_resources("fixture-agent")
    assert listed["returned"] == 1
    assert listed["resources"][0]["cleanup_available"] is False
    assert listed["resources"][0]["resource_type"] == "unknown"
    assert listed["resources"][0]["declaration_digest"] is None
    with pytest.raises(CleanupRejectedError):
        candidate.plan("fixture-agent", 0, expected_declaration_digest="0" * 64)
    assert target.read_bytes() == b"declared file bytes"


@pytest.mark.parametrize("changed", ["nonce", "identity", "root", "fingerprint"])
def test_changed_registration_rejects_reviewed_cleanup(tmp_path: Path, changed: str) -> None:
    paths, root, target, lease, user = fixture(tmp_path)
    plan = reviewed_plan(workflow(paths, user))
    if changed == "nonce":
        lease["registration_nonce"] = "different-registration"
    elif changed == "identity":
        lease["identity"]["create_time"] += 1.0
    elif changed == "root":
        lease["resources"][0]["approved_root"] = str(root.parent)
    else:
        target.write_bytes(b"changed file bytes")
    (paths.leases_dir / "fixture-agent.json").write_text(json.dumps(lease), encoding="utf-8")

    result = workflow(paths, user).execute(plan["plan_id"], plan["digest"])

    assert result["outcome"] == "failed"
    assert target.exists()


def test_modified_resource_is_rejected_before_plan(tmp_path: Path) -> None:
    paths, _, target, _, user = fixture(tmp_path, directory=True)
    candidate = workflow(paths, user)
    digest = candidate.list_resources("fixture-agent")["resources"][0]["declaration_digest"]
    (target / "nested" / "artifact.bin").write_bytes(b"changed before review")
    assert candidate.list_resources("fixture-agent")["resources"][0]["cleanup_available"] is False
    assert candidate.list_resources("fixture-agent")["resources"][0]["declaration_digest"] is None
    with pytest.raises(CleanupRejectedError):
        candidate.plan("fixture-agent", 0, expected_declaration_digest=digest)


def test_restore_conflict_preserves_both_versions(tmp_path: Path) -> None:
    paths, _, target, _, user = fixture(tmp_path)
    candidate = workflow(paths, user)
    plan = reviewed_plan(candidate)
    candidate.execute(plan["plan_id"], plan["digest"])
    entry = candidate._store.list_quarantine_entries()[0].entry
    restore = candidate.restore_plan(entry.entry_id)
    target.write_bytes(b"new destination version")

    result = workflow(paths, user).restore_execute(restore["plan_id"], restore["digest"])

    assert result["outcome"] == "failed"
    assert target.read_bytes() == b"new destination version"
    assert Path(entry.quarantine_path).read_bytes() == b"declared file bytes"


def test_restore_plan_digest_and_expiry_are_enforced(tmp_path: Path) -> None:
    from zombie_killer_engine.cleanup_workflow import CleanupWorkflow

    paths, _, _, _, user = fixture(tmp_path)
    candidate = workflow(paths, user)
    plan = reviewed_plan(candidate)
    candidate.execute(plan["plan_id"], plan["digest"])
    entry = candidate._store.list_quarantine_entries()[0].entry
    restore = candidate.restore_plan(entry.entry_id)
    with pytest.raises(PlanClaimError):
        workflow(paths, user).restore_execute(restore["plan_id"], "0" * 64)
    later = NOW + timedelta(seconds=31)
    store = SQLiteStateStore(paths, clock=lambda: later)
    store.initialize(now=later)
    with pytest.raises(PlanClaimError):
        CleanupWorkflow(store, paths, current_user=user, clock=lambda: later).restore_execute(
            restore["plan_id"],
            restore["digest"],
        )


def test_actual_dead_process_recovery_preserves_one_quarantined_copy(tmp_path: Path) -> None:
    paths, _, target, _, user = fixture(tmp_path)
    plan = reviewed_plan(workflow(paths, user))
    payload = {
        "paths": {
            name: str(getattr(paths, name))
            for name in (
                "data_dir",
                "state_dir",
                "runtime_dir",
                "backups_dir",
                "graveyard_dir",
            )
        },
        "plan_id": plan["plan_id"],
        "digest": plan["digest"],
        "user": user,
    }
    child_code = """
import json, os, sys
from datetime import datetime
from pathlib import Path
from zombie_killer_engine.paths import AppPaths
from zombie_killer_engine.store import SQLiteStateStore
from zombie_killer_engine.cleanup_workflow import CleanupWorkflow
from zombie_killer_engine.quarantine import QuarantineExecutor
arguments = json.loads(sys.argv[1])
paths = AppPaths(**{key: Path(value) for key, value in arguments['paths'].items()})
now = datetime.fromisoformat('2026-10-02T12:00:00+00:00')
store = SQLiteStateStore(paths, clock=lambda: now)
store.initialize(now=now)
workflow = CleanupWorkflow(store, paths, current_user=arguments['user'], clock=lambda: now)
executor = QuarantineExecutor(store, paths, actor='synthetic-child', clock=lambda: now,
    registration_resolver=workflow._resolve, after_move=lambda *_: os._exit(29))
executor.execute(arguments['plan_id'], expected_digest=arguments['digest'])
"""

    child = subprocess.run(
        [sys.executable, "-c", child_code, json.dumps(payload)],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert child.returncode == 29, child.stderr
    assert not target.exists()

    recovered = workflow(paths, user).execute(plan["plan_id"], plan["digest"])

    assert recovered["outcome"] == "quarantined"
    copies = list(paths.graveyard_dir.rglob(target.name))
    assert len(copies) == 1
    assert copies[0].read_bytes() == b"declared file bytes"


def test_restore_rechecks_expiry_at_the_native_move_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import zombie_killer_engine.cleanup_workflow as cleanup_module
    from zombie_killer_engine.quarantine import QuarantineExecutor

    paths, _, target, _, user = fixture(tmp_path)
    candidate = workflow(paths, user)
    plan = reviewed_plan(candidate)
    candidate.execute(plan["plan_id"], plan["digest"])
    entry = candidate._store.list_quarantine_entries()[0].entry
    restore = candidate.restore_plan(entry.entry_id)
    now = [NOW]
    candidate._clock = lambda: now[0]

    def native_executor(*args: object, **kwargs: object) -> QuarantineExecutor:
        def advance_before_restore(_entry: object) -> None:
            now[0] = NOW + timedelta(seconds=31)

        kwargs["before_restore"] = advance_before_restore
        return QuarantineExecutor(*args, **kwargs)

    monkeypatch.setattr(cleanup_module, "QuarantineExecutor", native_executor)

    result = candidate.restore_execute(restore["plan_id"], restore["digest"])

    assert result["outcome"] == "failed"
    assert result["action_issued"] is False
    assert not target.exists()
    assert Path(entry.quarantine_path).read_bytes() == b"declared file bytes"


def test_restore_crash_after_rename_reconciles_after_preview_expiry(tmp_path: Path) -> None:
    from zombie_killer_engine.cleanup_workflow import CleanupWorkflow

    paths, _, target, _, user = fixture(tmp_path)
    candidate = workflow(paths, user)
    plan = reviewed_plan(candidate)
    candidate.execute(plan["plan_id"], plan["digest"])
    entry = candidate._store.list_quarantine_entries()[0].entry
    restore = candidate.restore_plan(entry.entry_id)
    arguments = {
        "paths": {
            name: str(getattr(paths, name))
            for name in (
                "data_dir",
                "state_dir",
                "runtime_dir",
                "backups_dir",
                "graveyard_dir",
            )
        },
        "user": user,
        "plan_id": restore["plan_id"],
        "digest": restore["digest"],
    }
    child_code = """
import json, os, sys
from datetime import datetime
from pathlib import Path
import zombie_killer_engine.cleanup_workflow as cleanup
from zombie_killer_engine.paths import AppPaths
from zombie_killer_engine.store import SQLiteStateStore
from zombie_killer_engine.quarantine import QuarantineExecutor
arguments = json.loads(sys.argv[1])
paths = AppPaths(**{key: Path(value) for key, value in arguments['paths'].items()})
now = datetime.fromisoformat('2026-10-02T12:00:00+00:00')
store = SQLiteStateStore(paths, clock=lambda: now)
store.initialize(now=now)
original = QuarantineExecutor
def executor(*args, **kwargs):
    kwargs['after_restore'] = lambda *_: os._exit(31)
    return original(*args, **kwargs)
cleanup.QuarantineExecutor = executor
workflow = cleanup.CleanupWorkflow(store, paths, current_user=arguments['user'], clock=lambda: now)
workflow.restore_execute(arguments['plan_id'], arguments['digest'])
"""
    child = subprocess.run(
        [sys.executable, "-c", child_code, json.dumps(arguments)],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert child.returncode == 31, child.stderr
    assert target.read_bytes() == b"declared file bytes"
    later = NOW + timedelta(seconds=31)
    store = SQLiteStateStore(paths, clock=lambda: later)
    store.initialize(now=later)

    recovered = CleanupWorkflow(
        store, paths, current_user=user, clock=lambda: later
    ).restore_execute(
        restore["plan_id"],
        restore["digest"],
    )

    assert recovered["outcome"] == "restored"
    assert recovered["certainty"] == "verified"
    assert target.read_bytes() == b"declared file bytes"
    assert not Path(entry.quarantine_path).exists()


def test_verified_legacy_entry_is_restorable_without_current_cleanup_authority(
    tmp_path: Path,
) -> None:
    from test_quarantine import MutableClock, legacy_succeeded_fixture

    from zombie_killer_engine.cleanup_workflow import CleanupWorkflow

    paths, store, _, entry, target = legacy_succeeded_fixture(tmp_path)
    clock = MutableClock()
    candidate = CleanupWorkflow(store, paths, current_user="test-user", clock=clock)
    restore = candidate.restore_plan(entry.entry_id)

    result = candidate.restore_execute(restore["plan_id"], restore["digest"])

    assert result["outcome"] == "restored"
    assert result["plan_id"] == restore["plan_id"]
    assert target.read_bytes() == b"legacy quarantined material"
    assert not Path(entry.quarantine_path).exists()


def test_legacy_restore_expiry_is_rechecked_at_native_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from test_quarantine import MutableClock, legacy_succeeded_fixture

    import zombie_killer_engine.cleanup_workflow as cleanup_module
    from zombie_killer_engine.quarantine import QuarantineExecutor

    paths, store, _, entry, target = legacy_succeeded_fixture(tmp_path)
    clock = MutableClock()
    candidate = cleanup_module.CleanupWorkflow(store, paths, current_user="test-user", clock=clock)
    restore = candidate.restore_plan(entry.entry_id)

    def native_executor(*args: object, **kwargs: object) -> QuarantineExecutor:
        def expire_before_restore(_entry: object) -> None:
            clock.value += timedelta(seconds=31)

        kwargs["before_restore"] = expire_before_restore
        return QuarantineExecutor(*args, **kwargs)

    monkeypatch.setattr(cleanup_module, "QuarantineExecutor", native_executor)

    result = candidate.restore_execute(restore["plan_id"], restore["digest"])

    assert result["outcome"] == "failed"
    assert not target.exists()
    assert Path(entry.quarantine_path).read_bytes() == b"legacy quarantined material"
