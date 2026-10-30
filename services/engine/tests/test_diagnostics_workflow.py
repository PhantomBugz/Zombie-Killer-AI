from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

import zombie_killer_engine.diagnostics_workflow as module
from zombie_killer_engine.diagnostics_workflow import DiagnosticsWorkflow
from zombie_killer_engine.paths import AppPaths, WindowsPermissionBackend
from zombie_killer_engine.store import PlanClaimError, SQLiteStateStore


class Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 10, 2, 12, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.value


@pytest.fixture
def environment(tmp_path: Path) -> tuple[AppPaths, Path, Clock]:
    paths = AppPaths(
        data_dir=tmp_path / "data",
        state_dir=tmp_path / "state",
        runtime_dir=tmp_path / "runtime",
        backups_dir=tmp_path / "data" / "backups",
        graveyard_dir=tmp_path / "data" / "graveyard",
    )
    assert not paths.ensure()
    output = tmp_path / "exports"
    output.mkdir(mode=0o700)
    if os.name == "nt":
        WindowsPermissionBackend().restrict(output)
    return paths, output / "diagnostics.json", Clock()


def information() -> dict[str, object]:
    return {
        "engine_version": "0.1.0-alpha.1",
        "protocol_version": "1.0",
        "platform": "fixture",
        "local_only": True,
        "network_listener": False,
        "doctor": {"healthy": True, "checks": [{"name": "fixture", "ok": True}]},
        "settings": {"revision": 2, "theme": "dark", "api_key": "private-marker"},
        "receipts": [
            {
                "receipt_id": "fixture-receipt",
                "plan_id": "fixture-plan",
                "outcome": "completed",
                "certainty": "verified",
                "action_issued": True,
                "partial_failures": [" ".join(("Bearer", "synthetic-private-token-value"))],
                "created_at": "2026-10-02T12:00:00Z",
                "prompt": "private-marker",
                "path": "C:\\private\\marker",
            }
        ],
        "memory_contents": "private-marker",
        "command_lines": "private-marker",
        "private_executable_draft": "private-marker",
    }


def store_for(paths: AppPaths, clock: Clock) -> SQLiteStateStore:
    store = SQLiteStateStore(paths, clock=clock)
    store.initialize()
    return store


def test_export_survives_separate_engine_instances_and_excludes_private_fields(
    environment: tuple[AppPaths, Path, Clock],
) -> None:
    paths, destination, clock = environment
    first = store_for(paths, clock)
    plan = DiagnosticsWorkflow(first, clock=clock).plan(str(destination), diagnostics=information())
    first.close()
    second = store_for(paths, clock)
    workflow = DiagnosticsWorkflow(second, clock=clock)
    receipt = workflow.execute(str(plan["plan_id"]), str(plan["digest"]))
    assert receipt["certainty"] == "verified"
    assert receipt["action_issued"] is True
    assert receipt["kind"] == "diagnostics"
    contents = destination.read_text(encoding="utf-8")
    document = json.loads(contents)
    assert document["settings"] == {"revision": 2, "theme": "dark"}
    assert "private-marker" not in contents
    assert "synthetic-private-token-value" not in contents
    assert "C:\\private" not in contents
    assert workflow.execute(str(plan["plan_id"]), str(plan["digest"])) == receipt
    second.close()


def test_existing_destination_is_never_overwritten(
    environment: tuple[AppPaths, Path, Clock],
) -> None:
    paths, destination, clock = environment
    store = store_for(paths, clock)
    workflow = DiagnosticsWorkflow(store, clock=clock)
    destination.write_bytes(b"existing")
    with pytest.raises(ValueError):
        workflow.plan(str(destination), diagnostics=information())
    destination.unlink()
    plan = workflow.plan(str(destination), diagnostics=information())
    destination.write_bytes(b"arrived-after-review")
    receipt = workflow.execute(str(plan["plan_id"]), str(plan["digest"]))
    assert receipt["certainty"] == "failed_before_issue"
    assert receipt["action_issued"] is False
    assert destination.read_bytes() == b"arrived-after-review"
    store.close()


@pytest.mark.parametrize("change", ["digest", "expiry"])
def test_export_rejects_changed_or_expired_authority(
    environment: tuple[AppPaths, Path, Clock],
    change: str,
) -> None:
    paths, destination, clock = environment
    store = store_for(paths, clock)
    workflow = DiagnosticsWorkflow(store, clock=clock)
    plan = workflow.plan(str(destination), diagnostics=information())
    if change == "expiry":
        clock.value += timedelta(seconds=31)
    with pytest.raises(PlanClaimError):
        workflow.execute(
            str(plan["plan_id"]), "0" * 64 if change == "digest" else str(plan["digest"])
        )
    assert not destination.exists()
    store.close()


def test_export_detects_replaced_parent_without_touching_replacement(
    environment: tuple[AppPaths, Path, Clock],
) -> None:
    paths, destination, clock = environment
    store = store_for(paths, clock)
    workflow = DiagnosticsWorkflow(store, clock=clock)
    plan = workflow.plan(str(destination), diagnostics=information())
    parent = destination.parent
    parent.rename(parent.with_name("reviewed-old-parent"))
    parent.mkdir(mode=0o700)
    if os.name == "nt":
        WindowsPermissionBackend().restrict(parent)
    receipt = workflow.execute(str(plan["plan_id"]), str(plan["digest"]))
    assert receipt["certainty"] == "failed_before_issue"
    assert not destination.exists()
    store.close()


def test_post_creation_failure_is_uncertain_and_preserves_evidence(
    environment: tuple[AppPaths, Path, Clock],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths, destination, clock = environment
    store = store_for(paths, clock)
    workflow = DiagnosticsWorkflow(store, clock=clock)
    plan = workflow.plan(str(destination), diagnostics=information())

    def interrupted_write(descriptor: int, contents: bytes) -> None:
        os.write(descriptor, contents[:5])
        raise OSError("synthetic post-creation failure")

    monkeypatch.setattr(module, "_write_export", interrupted_write)
    receipt = workflow.execute(str(plan["plan_id"]), str(plan["digest"]))
    assert receipt["certainty"] == "uncertain"
    assert receipt["action_issued"] is None
    assert destination.exists()
    assert workflow.execute(str(plan["plan_id"]), str(plan["digest"])) == receipt
    store.close()


def test_export_settings_and_receipts_can_be_omitted(
    environment: tuple[AppPaths, Path, Clock],
) -> None:
    paths, destination, clock = environment
    store = store_for(paths, clock)
    workflow = DiagnosticsWorkflow(store, clock=clock)
    plan = workflow.plan(
        str(destination),
        diagnostics=information(),
        include_receipts=False,
        include_settings=False,
    )
    workflow.execute(str(plan["plan_id"]), str(plan["digest"]))
    document = json.loads(destination.read_bytes())
    assert "settings" not in document
    assert "receipts" not in document
    store.close()


def test_export_bounds_contents_before_creating_plan(
    environment: tuple[AppPaths, Path, Clock],
) -> None:
    paths, destination, clock = environment
    store = store_for(paths, clock)
    workflow = DiagnosticsWorkflow(store, clock=clock)
    raw = information()
    raw["receipts"] = [{"receipt_id": "x" * 100_000}] * 5_000
    plan = workflow.plan(str(destination), diagnostics=raw)
    workflow.execute(str(plan["plan_id"]), str(plan["digest"]))
    document: dict[str, Any] = json.loads(destination.read_bytes())
    assert len(document["receipts"]) <= 20
    assert destination.stat().st_size <= 32_768
    store.close()


@pytest.mark.parametrize("mode", ["complete", "partial", "before_create"])
@pytest.mark.parametrize("elapsed", [1, 31])
def test_dead_owner_export_reconciles_without_overwrite_or_new_expired_write(
    environment: tuple[AppPaths, Path, Clock],
    mode: str,
    elapsed: int,
) -> None:
    paths, destination, clock = environment
    first = store_for(paths, clock)
    plan = DiagnosticsWorkflow(first, clock=clock).plan(str(destination), diagnostics=information())
    first.close()
    script = r"""
import os, sys
from datetime import datetime
from pathlib import Path
import zombie_killer_engine.diagnostics_workflow as module
from zombie_killer_engine.paths import AppPaths
from zombie_killer_engine.store import SQLiteStateStore
root, plan_id, digest, now, mode = sys.argv[1:]
root = Path(root)
paths = AppPaths(data_dir=root/'data', state_dir=root/'state', runtime_dir=root/'runtime',
                 backups_dir=root/'data'/'backups', graveyard_dir=root/'data'/'graveyard')
store = SQLiteStateStore(paths, clock=lambda: datetime.fromisoformat(now))
store.initialize()
original = module._write_export
def abrupt(descriptor, contents):
    if mode == 'complete':
        original(descriptor, contents)
    else:
        os.write(descriptor, contents[:5])
        os.fsync(descriptor)
    os._exit(73)
module._write_export = abrupt
if mode == 'before_create':
    store.claim_workflow_plan('diagnostics_export', plan_id, expected_digest=digest)
    os._exit(73)
workflow = module.DiagnosticsWorkflow(store, clock=lambda: datetime.fromisoformat(now))
workflow.execute(plan_id, digest)
"""
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            script,
            str(paths.state_dir.parent),
            str(plan["plan_id"]),
            str(plan["digest"]),
            clock.value.isoformat(),
            mode,
        ],
        capture_output=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 73, result.stderr.decode(errors="replace")
    before = destination.read_bytes() if destination.exists() else None
    clock.value += timedelta(seconds=elapsed)
    second = store_for(paths, clock)
    receipt = DiagnosticsWorkflow(second, clock=clock).execute(
        str(plan["plan_id"]), str(plan["digest"])
    )
    if mode == "complete":
        assert receipt["certainty"] == "verified"
        assert receipt["action_issued"] is False
        assert receipt["outcome"] == "already_exported"
    else:
        assert receipt["certainty"] == "uncertain"
        assert receipt["action_issued"] is None
    assert (destination.read_bytes() if destination.exists() else None) == before
    second.close()


def test_expiry_at_creation_boundary_cannot_create_export(
    environment: tuple[AppPaths, Path, Clock],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths, destination, clock = environment
    store = store_for(paths, clock)
    workflow = DiagnosticsWorkflow(store, clock=clock)
    plan = workflow.plan(str(destination), diagnostics=information())
    original = module._pin_parent

    @contextmanager
    def expire_before_creation(parent: Path, expected: object) -> Iterator[int | None]:
        with original(parent, expected) as descriptor:
            clock.value += timedelta(seconds=31)
            yield descriptor

    monkeypatch.setattr(module, "_pin_parent", expire_before_creation)
    receipt = workflow.execute(str(plan["plan_id"]), str(plan["digest"]))
    assert receipt["certainty"] == "failed_before_issue"
    assert receipt["action_issued"] is False
    assert not destination.exists()
    store.close()
