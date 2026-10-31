from __future__ import annotations

import json
import os
import sqlite3
import struct
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from zombie_killer.lease import current_process_identity, validate_temp_resource
from zombie_killer_engine.memory.base import MemoryReceipt
from zombie_killer_engine.memory_workflow import MemoryWorkflow
from zombie_killer_engine.paths import AppPaths, PosixPermissionBackend, WindowsPermissionBackend
from zombie_killer_engine.service import (
    Capability,
    RequestContext,
    RequestEnvelope,
    build_default_service,
)


def paths_for(tmp_path: Path) -> AppPaths:
    return AppPaths(
        data_dir=tmp_path / "data",
        state_dir=tmp_path / "state",
        runtime_dir=tmp_path / "runtime",
        backups_dir=tmp_path / "backups",
        graveyard_dir=tmp_path / "graveyard",
    )


def call(paths: AppPaths, method: str, payload: dict[str, object]) -> dict[str, object]:
    with build_default_service(paths=paths) as service:
        response = service.dispatch(
            RequestEnvelope(
                protocol_version="1.0", request_id=uuid4(), method=method, payload=payload
            ),
            context=RequestContext(capability=Capability.EXECUTION, local_control=True),
        )
    assert response.ok, response.error
    assert response.result is not None
    return response.result.model_dump(mode="json")


@pytest.mark.parametrize("suffix", [".json", ".jsonl"])
def test_memory_plan_execute_snapshot_restore_survives_service_restart(
    tmp_path: Path, suffix: str
) -> None:
    paths = paths_for(tmp_path)
    source = tmp_path / ("memory" + suffix)
    source.write_text(
        json.dumps([{"id": "one", "content": "before", "metadata": {"flag": False}}])
        if suffix == ".json"
        else json.dumps({"id": "one", "content": "before", "metadata": {"flag": False}}) + "\n"
    )
    call(paths, "vault.register", {"path": str(source)})
    inventory = call(paths, "vault.list", {})
    selected = inventory["sources"][0]
    record = call(paths, "vault.get", {"source_id": selected["source_id"], "record_id": "one"})[
        "record"
    ]
    assert any(field["kind"] == "update_content" for field in record["editable_fields"])
    plan = call(
        paths,
        "vault.mutation.plan",
        {
            "source_id": selected["source_id"],
            "expected_revision": record["source_revision"],
            "record_id": "one",
            "operation": "update_content",
            "value": "after",
        },
    )
    assert plan["backup_verified"] is False
    assert plan["diff"][0]["old_preview"] == "[REDACTED]"
    receipt = call(
        paths, "vault.mutation.execute", {"plan_id": plan["plan_id"], "digest": plan["digest"]}
    )
    assert receipt["kind"] == "memory"
    assert receipt["certainty"] == "verified"
    assert (
        call(paths, "vault.get", {"source_id": selected["source_id"], "record_id": "one"})[
            "record"
        ]["content"]
        == "after"
    )
    fetched = call(paths, "receipt.get", {"receipt_id": receipt["receipt_id"]})
    assert fetched["receipt_id"] == receipt["receipt_id"]
    with build_default_service(paths=paths) as service:
        replay = service.dispatch(
            RequestEnvelope(
                protocol_version="1.0",
                request_id=uuid4(),
                method="vault.mutation.execute",
                payload={"plan_id": plan["plan_id"], "digest": plan["digest"]},
            ),
            context=RequestContext(capability=Capability.EXECUTION, local_control=True),
        )
    assert not replay.ok
    assert replay.error is not None and replay.error.code.value == "conflict"
    snapshots = call(paths, "vault.snapshot.list", {"source_id": selected["source_id"]})[
        "snapshots"
    ]
    snapshot = next(item for item in snapshots if item["snapshot_id"] == receipt["snapshot_id"])
    restore = call(
        paths,
        "vault.restore.plan",
        {
            "source_id": selected["source_id"],
            "snapshot_id": snapshot["snapshot_id"],
            "snapshot_digest": snapshot["digest"],
            "expected_revision": receipt["after_revision"],
        },
    )
    restored = call(
        paths, "vault.restore.execute", {"plan_id": restore["plan_id"], "digest": restore["digest"]}
    )
    assert restored["snapshot_id"] == snapshot["snapshot_id"]
    assert (
        call(paths, "vault.get", {"source_id": selected["source_id"], "record_id": "one"})[
            "record"
        ]["content"]
        == "before"
    )


def test_diagnostics_export_and_receipt_lookup_survive_service_restart(tmp_path: Path) -> None:
    paths = paths_for(tmp_path)
    if os.name == "nt":
        WindowsPermissionBackend().restrict(tmp_path)
    destination = tmp_path / "diagnostics.json"
    plan = call(paths, "diagnostics.export-plan", {"destination": str(destination)})
    receipt = call(
        paths, "diagnostics.export-execute", {"plan_id": plan["plan_id"], "digest": plan["digest"]}
    )
    assert receipt["kind"] == "diagnostics"
    assert receipt["certainty"] == "verified"
    assert json.loads(destination.read_text())["local_only"] is True
    fetched = call(paths, "receipt.get", {"receipt_id": receipt["receipt_id"]})
    assert fetched["receipt_id"] == receipt["receipt_id"]


@pytest.mark.skipif(os.name != "nt", reason="Windows ACLs are platform-specific")
def test_diagnostics_export_rejects_untrusted_parent_then_accepts_secured_parent(
    tmp_path: Path,
) -> None:
    paths = paths_for(tmp_path)
    export_dir = tmp_path / "exports"
    export_dir.mkdir()
    WindowsPermissionBackend().restrict(export_dir)
    destination = export_dir / "diagnostics.json"
    granted = subprocess.run(
        ["icacls", str(export_dir), "/grant", "*S-1-1-0:(OI)(CI)M"],
        capture_output=True,
        text=True,
        check=False,
    )
    if granted.returncode != 0:
        pytest.skip(f"ACL modification unavailable: {granted.stderr.strip()}")
    try:
        with build_default_service(paths=paths) as service:
            response = service.dispatch(
                RequestEnvelope(
                    protocol_version="1.0",
                    request_id=uuid4(),
                    method="diagnostics.export-plan",
                    payload={"destination": str(destination)},
                ),
                context=RequestContext(capability=Capability.EXECUTION, local_control=True),
            )
        assert not response.ok
        assert response.error is not None and response.error.code.value == "invalid_request"
        assert not destination.exists()
    finally:
        WindowsPermissionBackend().restrict(export_dir)

    plan = call(paths, "diagnostics.export-plan", {"destination": str(destination)})
    assert plan["plan_id"]


def test_sqlite_scalar_edit_and_restore_with_nonstandard_extension(tmp_path: Path) -> None:
    paths = paths_for(tmp_path)
    source = tmp_path / "memory.bin"
    with sqlite3.connect(source) as database:
        database.execute("CREATE TABLE notes(id INTEGER PRIMARY KEY, content TEXT, score INTEGER)")
        database.execute("INSERT INTO notes VALUES(1, 'original', 3)")
    registered = call(paths, "vault.register", {"path": str(source)})
    assert registered["format"] == "sqlite"
    selected = call(paths, "vault.list", {})["sources"][0]
    record = call(paths, "vault.query", {"source_id": selected["source_id"]})["records"][0]
    score = next(field for field in record["editable_fields"] if field["field"] == "score")
    assert score["value"] == 3
    assert score["value_type"] == "number"
    plan = call(
        paths,
        "vault.mutation.plan",
        {
            "source_id": selected["source_id"],
            "record_id": record["record_id"],
            "expected_revision": record["source_revision"],
            "operation": "update_field",
            "field": "score",
            "value": 8,
        },
    )
    receipt = call(
        paths, "vault.mutation.execute", {"plan_id": plan["plan_id"], "digest": plan["digest"]}
    )
    assert receipt["certainty"] == "verified"
    assert (
        call(
            paths,
            "vault.get",
            {"source_id": selected["source_id"], "record_id": record["record_id"]},
        )["record"]["metadata"]["score"]
        == 8
    )
    snapshot = next(
        item
        for item in call(paths, "vault.snapshot.list", {"source_id": selected["source_id"]})[
            "snapshots"
        ]
        if item["snapshot_id"] == receipt["snapshot_id"]
    )
    restore = call(
        paths,
        "vault.restore.plan",
        {
            "source_id": selected["source_id"],
            "snapshot_id": snapshot["snapshot_id"],
            "snapshot_digest": snapshot["digest"],
            "expected_revision": receipt["after_revision"],
        },
    )
    restored = call(
        paths, "vault.restore.execute", {"plan_id": restore["plan_id"], "digest": restore["digest"]}
    )
    assert restored["certainty"] == "verified"
    assert restored["snapshot_id"] == snapshot["snapshot_id"]
    assert (
        call(
            paths,
            "vault.get",
            {"source_id": selected["source_id"], "record_id": record["record_id"]},
        )["record"]["metadata"]["score"]
        == 3
    )


def test_faiss_registration_is_header_inventory_only(tmp_path: Path) -> None:
    paths = paths_for(tmp_path)
    source = tmp_path / "index.dat"
    source.write_bytes(b"IxF2" + struct.pack("<iqQQ?iQ", 2, 0, 1 << 20, 1 << 20, True, 1, 0))
    original = source.read_bytes()
    probe = call(paths, "vault.probe", {"path": str(source)})
    assert probe["format"] == "faiss"
    assert probe["capabilities"]["queryable"] is False
    call(paths, "vault.register", {"path": str(source)})
    selected = call(paths, "vault.list", {})["sources"][0]
    with build_default_service(paths=paths) as service:
        result = service.dispatch(
            RequestEnvelope(
                protocol_version="1.0",
                request_id=uuid4(),
                method="vault.query",
                payload={"source_id": selected["source_id"]},
            ),
            context=RequestContext(),
        )
    assert not result.ok
    assert result.error is not None and result.error.code.value == "unsupported"
    assert source.read_bytes() == original


def test_missing_source_after_review_finishes_known_preissue_receipt(tmp_path: Path) -> None:
    paths = paths_for(tmp_path)
    source = tmp_path / "memory.json"
    source.write_text('[{"id":"one","content":"before"}]')
    call(paths, "vault.register", {"path": str(source)})
    selected = call(paths, "vault.list", {})["sources"][0]
    plan = call(
        paths,
        "vault.mutation.plan",
        {
            "source_id": selected["source_id"],
            "expected_revision": selected["revision"],
            "record_id": "one",
            "operation": "update_content",
            "value": "after",
        },
    )
    source.unlink()
    receipt = call(
        paths, "vault.mutation.execute", {"plan_id": plan["plan_id"], "digest": plan["digest"]}
    )
    assert receipt["certainty"] == "failed_before_issue"
    assert receipt["action_issued"] is False
    assert (
        call(paths, "receipt.get", {"receipt_id": receipt["receipt_id"]})["receipt_id"]
        == receipt["receipt_id"]
    )
    assert not source.exists()


def test_registered_format_change_after_review_finishes_preissue_receipt(tmp_path: Path) -> None:
    paths = paths_for(tmp_path)
    source = tmp_path / "memory.json"
    source.write_text('[{"id":"one","content":"before"}]')
    call(paths, "vault.register", {"path": str(source)})
    selected = call(paths, "vault.list", {})["sources"][0]
    plan = call(
        paths,
        "vault.mutation.plan",
        {
            "source_id": selected["source_id"],
            "expected_revision": selected["revision"],
            "record_id": "one",
            "operation": "update_content",
            "value": "after",
        },
    )
    source.write_bytes(b"IxF2" + struct.pack("<iqQQ?iQ", 2, 0, 1 << 20, 1 << 20, True, 1, 0))
    original = source.read_bytes()
    call(paths, "vault.register", {"path": str(source)})
    receipt = call(
        paths, "vault.mutation.execute", {"plan_id": plan["plan_id"], "digest": plan["digest"]}
    )
    assert receipt["certainty"] == "failed_before_issue"
    assert receipt["action_issued"] is False
    assert source.read_bytes() == original


def test_reconciled_rollback_does_not_claim_action_was_never_issued() -> None:
    receipt = MemoryReceipt(
        receipt_id="fixture-receipt",
        plan_id="fixture-plan",
        snapshot_id="fixture-snapshot",
        source_id="fixture-source",
        operation="reconciled_rollback",
        before_revision="a" * 64,
        after_revision="a" * 64,
        created_at=datetime.now(UTC),
    )
    result = MemoryWorkflow._receipt("fixture-plan", {"source_id": "fixture-source"}, receipt)
    assert result["certainty"] == "uncertain"
    assert result["action_issued"] is None


@pytest.mark.parametrize("directory", [False, True])
def test_declared_cleanup_and_exact_restore_through_separate_service_instances(
    tmp_path: Path, directory: bool
) -> None:
    paths = paths_for(tmp_path)
    assert not paths.ensure()
    root = tmp_path / "approved"
    root.mkdir(mode=0o700)
    (WindowsPermissionBackend() if os.name == "nt" else PosixPermissionBackend()).restrict(root)
    target = root / ("tree" if directory else "artifact.bin")
    if directory:
        target.mkdir()
        (target / "artifact.bin").write_bytes(b"declared bytes")
    else:
        target.write_bytes(b"declared bytes")
    identity = current_process_identity()
    registration = {
        "protocol_version": 1,
        "agent_id": "fixture-agent",
        "registration_nonce": "fixture-generation",
        "identity": identity.as_dict(),
        "heartbeat_at": datetime.now(UTC).isoformat(),
        "heartbeat_timeout_seconds": 120.0,
        "resources": [validate_temp_resource(target, root=root)],
    }
    (paths.leases_dir / "fixture-agent.json").write_text(json.dumps(registration))
    resources = call(paths, "quarantine.resource-list", {"agent_id": "fixture-agent"})
    selected = resources["resources"][0]
    assert selected["cleanup_available"] is True
    assert selected["declaration_digest"] is not None
    plan = call(
        paths,
        "quarantine.plan",
        {
            "agent_id": "fixture-agent",
            "resource_index": 0,
            "expected_declaration_digest": selected["declaration_digest"],
        },
    )
    receipt = call(
        paths, "quarantine.execute", {"plan_id": plan["plan_id"], "digest": plan["digest"]}
    )
    assert receipt["certainty"] == "verified"
    assert receipt["kind"] == "quarantine"
    assert not target.exists()
    entry = call(paths, "quarantine.list", {})["entries"][0]
    assert entry["restorable"] is True
    restore = call(paths, "quarantine.restore-plan", {"entry_id": entry["entry_id"]})
    restored = call(
        paths,
        "quarantine.restore-execute",
        {"plan_id": restore["plan_id"], "digest": restore["digest"]},
    )
    assert restored["certainty"] == "verified"
    assert restored["kind"] == "quarantine"
    assert (
        call(paths, "receipt.get", {"receipt_id": restored["receipt_id"]})["kind"] == "quarantine"
    )
    assert (target / "artifact.bin" if directory else target).read_bytes() == b"declared bytes"
    receipts = call(paths, "activity.list", {})["receipts"]
    assert all(item["kind"] == "quarantine" for item in receipts)
    assert {item["receipt_id"] for item in receipts} >= {
        receipt["receipt_id"],
        restored["receipt_id"],
    }
