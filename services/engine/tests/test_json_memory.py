from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from zombie_killer_engine.memory import (
    JsonMemoryAdapter,
    MemoryError,
    MutationKind,
    MutationOperation,
    QueryFilter,
)
from zombie_killer_engine.memory import base as base_module
from zombie_killer_engine.memory import json_store as json_store_module
from zombie_killer_engine.memory.base import (
    capture_file_security,
    exclusive_file_lock,
    read_pinned,
    read_prefix_pinned,
)
from zombie_killer_engine.memory_workflow import MemoryWorkflow
from zombie_killer_engine.paths import AppPaths
from zombie_killer_engine.store import PlanClaimError, SQLiteStateStore, StorePathError


def _adapter(source: Path, tmp_path: Path) -> JsonMemoryAdapter:
    backups = tmp_path / "backups"
    backups.mkdir(mode=0o700, exist_ok=True)
    return JsonMemoryAdapter(source, backups_dir=backups, state_store=_state_store(tmp_path))


def _state_store(tmp_path: Path, *, owner_alive: bool | None = None) -> SQLiteStateStore:
    store = SQLiteStateStore(
        AppPaths(
            data_dir=tmp_path / "app-data",
            state_dir=tmp_path / "app-state",
            runtime_dir=tmp_path / "app-runtime",
            backups_dir=tmp_path / "backups",
            graveyard_dir=tmp_path / "graveyard",
        ),
        is_session_alive=((lambda _owner: owner_alive) if owner_alive is not None else None),
    )
    store.initialize()
    return store


def _set_windows_pai(path: Path) -> str:
    subprocess.run(
        ["icacls", str(path), "/inheritancelevel:d"],
        check=True,
        capture_output=True,
        text=True,
    )
    sddl = capture_file_security(path).windows_sddl or ""
    assert "D:PAI" in sddl
    return sddl


def test_json_array_is_validated_and_queried_without_copying_embeddings(
    tmp_path: Path,
) -> None:
    source = tmp_path / "memory.json"
    source.write_text(
        json.dumps(
            [
                {
                    "id": "a",
                    "namespace": "work",
                    "content": "alpha note",
                    "metadata": {"tags": ["red", "safe"]},
                    "embedding": [0.1, 0.2],
                },
                {"id": "b", "content": "beta", "metadata": {"score": 2}},
            ]
        ),
        encoding="utf-8",
    )
    adapter = _adapter(source, tmp_path).open(read_only=True)

    page = adapter.query(limit=1, filter=QueryFilter(text="alpha", tags=("red",)))

    assert page.next_cursor is None
    assert [record.record_id for record in page.records] == ["a"]
    assert page.records[0].embedding_present is True
    assert "embedding" not in page.records[0].metadata
    assert adapter.list_namespaces() == ("default", "work")


def test_json_explicit_read_only_open_rejects_mutation_planning(tmp_path: Path) -> None:
    source = tmp_path / "memory.json"
    source.write_text('[{"id":"a","content":"old"}]', encoding="utf-8")
    adapter = _adapter(source, tmp_path).open(read_only=True)

    with pytest.raises(MemoryError, match="read-only"):
        adapter.plan_mutation(
            MutationOperation(
                kind=MutationKind.UPDATE_CONTENT,
                record_id="a",
                value="new",
            ),
            expected_revision=adapter.current_revision(),
        )


def test_dict_records_have_stable_ids_and_jsonl_reports_invalid_line(
    tmp_path: Path,
) -> None:
    source = tmp_path / "memory.json"
    source.write_text('{"stable-key":{"content":"hello"}}', encoding="utf-8")
    assert _adapter(source, tmp_path).get("stable-key").record_id == "stable-key"

    broken = tmp_path / "broken.jsonl"
    broken.write_text('{"id":"ok","content":"yes"}\n{broken}\n', encoding="utf-8")
    with pytest.raises(MemoryError, match="line 2"):
        _adapter(broken, tmp_path).query()

    blank = tmp_path / "blank-lines.jsonl"
    blank.write_text('\n{"content":"physical line identity"}\n', encoding="utf-8")
    assert _adapter(blank, tmp_path).query().records[0].record_id.startswith("record-")


def test_whole_store_validation_rejects_duplicate_deep_and_oversize_input(
    tmp_path: Path,
) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        '[{"id":"same","content":"one"},{"id":"same","content":"two"}]',
        encoding="utf-8",
    )
    with pytest.raises(MemoryError, match="duplicate"):
        _adapter(duplicate, tmp_path).query(limit=1)

    deep = tmp_path / "deep.json"
    value: object = "end"
    for _ in range(20):
        value = {"nested": value}
    deep.write_text(json.dumps([{"id": "x", "content": "x", "metadata": value}]))
    with pytest.raises(MemoryError, match="depth"):
        _adapter(deep, tmp_path).query()

    huge = tmp_path / "huge.json"
    huge.write_text(json.dumps([{"id": "x", "content": "x" * 300}]))
    with pytest.raises(MemoryError, match="string"):
        JsonMemoryAdapter(
            huge,
            backups_dir=tmp_path / "backups",
            state_store=_state_store(tmp_path),
            max_string_chars=128,
        ).query()

    pathological = tmp_path / "pathological.json"
    pathological.write_text(
        '[{"id":"x","content":"x","metadata":' + "[" * 1500 + "0" + "]" * 1500 + "}]",
        encoding="utf-8",
    )
    with pytest.raises(MemoryError, match="malformed|depth"):
        _adapter(pathological, tmp_path).query()


def test_jsonl_pathological_nesting_is_rejected_without_recursion_crash(
    tmp_path: Path,
) -> None:
    pathological = tmp_path / "pathological.jsonl"
    pathological.write_text(
        '{"id":"x","content":"x","metadata":' + "[" * 1500 + "0" + "]" * 1500 + "}\n",
        encoding="utf-8",
    )

    with pytest.raises(MemoryError, match="invalid JSONL record|depth"):
        _adapter(pathological, tmp_path).query()


def test_json_plan_backup_apply_and_restore_are_revision_bound(tmp_path: Path) -> None:
    source = tmp_path / "memory.json"
    source.write_text('[{"id":"a","content":"old","metadata":{}}]', encoding="utf-8")
    adapter = _adapter(source, tmp_path)
    revision = adapter.current_revision()
    plan = adapter.plan_mutation(
        MutationOperation(
            kind=MutationKind.UPDATE_CONTENT,
            record_id="a",
            value="new secret value",
        ),
        expected_revision=revision,
    )
    assert "new secret value" not in plan.model_dump_json()

    receipt = adapter.apply(plan)

    assert receipt.before_revision == revision
    assert adapter.get("a").content == "new secret value"
    snapshot = adapter.snapshot(receipt.snapshot_id)
    restored = adapter.restore(
        snapshot.snapshot_id,
        expected_snapshot_digest=snapshot.digest,
        expected_revision=receipt.after_revision,
    )
    assert restored.operation == "restore"
    assert adapter.get("a").content == "old"


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode preservation")
def test_json_replacement_preserves_selected_source_mode(tmp_path: Path) -> None:
    source = tmp_path / "memory.json"
    source.write_text('[{"id":"a","content":"old"}]', encoding="utf-8")
    source.chmod(0o640)
    adapter = _adapter(source, tmp_path)
    plan = adapter.plan_mutation(
        MutationOperation(kind=MutationKind.UPDATE_CONTENT, record_id="a", value="new"),
        expected_revision=adapter.current_revision(),
    )

    adapter.apply(plan)

    assert source.stat().st_mode & 0o777 == 0o640


@pytest.mark.skipif(os.name != "nt", reason="Windows DACL control semantics")
def test_json_replacement_preserves_exact_pai_descriptor(tmp_path: Path) -> None:
    source = tmp_path / "memory.json"
    source.write_text('[{"id":"a","content":"old"}]', encoding="utf-8")
    expected_sddl = _set_windows_pai(source)
    adapter = _adapter(source, tmp_path)
    plan = adapter.plan_mutation(
        MutationOperation(kind=MutationKind.UPDATE_CONTENT, record_id="a", value="new"),
        expected_revision=adapter.current_revision(),
    )

    adapter.apply(plan)

    assert capture_file_security(source).windows_sddl == expected_sddl


def test_json_temp_permission_error_is_bounded_and_redacted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "memory.json"
    source.write_text('[{"id":"a","content":"old"}]', encoding="utf-8")
    adapter = _adapter(source, tmp_path)
    plan = adapter.plan_mutation(
        MutationOperation(kind=MutationKind.UPDATE_CONTENT, record_id="a", value="new"),
        expected_revision=adapter.current_revision(),
    )

    def denied(*_args: object, **_kwargs: object) -> tuple[int, str]:
        raise PermissionError("C:/private/secret-memory-value.tmp")

    monkeypatch.setattr("zombie_killer_engine.memory.json_store.tempfile.mkstemp", denied)
    with pytest.raises(MemoryError, match="replacement|permission|write") as failure:
        adapter.apply(plan)

    assert "private" not in str(failure.value)
    assert "secret-memory-value" not in str(failure.value)


def test_json_replace_fsync_and_reopen_permission_errors_are_redacted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "memory.json"
    source.write_text('[{"id":"a","content":"old"}]', encoding="utf-8")
    adapter = _adapter(source, tmp_path)
    original_replace = json_store_module.os.replace

    def denied_replace(_source: object, _target: object) -> None:
        raise PermissionError("C:/private/replace-secret.tmp")

    monkeypatch.setattr(json_store_module.os, "replace", denied_replace)
    with pytest.raises(MemoryError) as replace_failure:
        adapter._replace(b'[{"id":"a","content":"new"}]')
    assert "private" not in str(replace_failure.value)
    monkeypatch.setattr(json_store_module.os, "replace", original_replace)

    def denied_fsync(_descriptor: int) -> None:
        raise PermissionError("C:/private/fsync-secret.tmp")

    monkeypatch.setattr(json_store_module.os, "fsync", denied_fsync)
    with pytest.raises(MemoryError) as fsync_failure:
        adapter.backup(expected_revision=adapter.current_revision())
    assert "private" not in str(fsync_failure.value)
    monkeypatch.undo()

    original_read = json_store_module.read_pinned

    def denied_reopen(path: Path, *, max_bytes: int) -> tuple[bytes, object]:
        if path.suffix == ".tmp":
            raise PermissionError("C:/private/reopen-secret.tmp")
        return original_read(path, max_bytes=max_bytes)

    monkeypatch.setattr(json_store_module, "read_pinned", denied_reopen)
    with pytest.raises(MemoryError) as reopen_failure:
        adapter._replace(b'[{"id":"a","content":"new"}]')
    assert "private" not in str(reopen_failure.value)


def test_json_apply_rejects_source_swap_expiry_replay_and_tampered_snapshot(
    tmp_path: Path,
) -> None:
    source = tmp_path / "memory.json"
    source.write_text('[{"id":"a","content":"old"}]', encoding="utf-8")
    adapter = _adapter(source, tmp_path)
    plan = adapter.plan_mutation(
        MutationOperation(kind=MutationKind.UPDATE_CONTENT, record_id="a", value="new"),
        expected_revision=adapter.current_revision(),
    )
    source.write_text('[{"id":"a","content":"changed"}]', encoding="utf-8")
    with pytest.raises(MemoryError, match="revision"):
        adapter.apply(plan)

    source.write_text('[{"id":"a","content":"old"}]', encoding="utf-8")
    fresh = _adapter(source, tmp_path)
    plan = fresh.plan_mutation(
        MutationOperation(kind=MutationKind.EXCLUDE, record_id="a"),
        expected_revision=fresh.current_revision(),
    )
    receipt = fresh.apply(plan)
    assert fresh.query().records == ()
    assert fresh.get("a").metadata["excluded_from_retrieval"] is True
    with pytest.raises(MemoryError, match="replay"):
        fresh.apply(plan)
    snapshot = fresh.snapshot(receipt.snapshot_id)
    Path(snapshot.backup_path).write_bytes(b"tampered")
    with pytest.raises(MemoryError, match="snapshot"):
        fresh.restore(
            snapshot.snapshot_id,
            expected_snapshot_digest=snapshot.digest,
            expected_revision=receipt.after_revision,
        )

    expired = plan.model_copy(update={"expires_at": datetime.now(UTC) - timedelta(seconds=1)})
    with pytest.raises(MemoryError, match="expired|tampered"):
        _adapter(source, tmp_path).apply(expired)


def test_json_update_field_must_already_be_a_supported_scalar(tmp_path: Path) -> None:
    source = tmp_path / "memory.json"
    source.write_text('[{"id":"a","content":"old","nested":{}}]', encoding="utf-8")
    adapter = _adapter(source, tmp_path)

    for field in ("new_field", "nested"):
        with pytest.raises(MemoryError, match="editable|scalar|allowlist"):
            adapter.plan_mutation(
                MutationOperation(
                    kind=MutationKind.UPDATE_FIELD,
                    record_id="a",
                    field=field,
                    value="value",
                ),
                expected_revision=adapter.current_revision(),
            )


def test_plan_digest_binds_exact_field_and_proposed_value_type(tmp_path: Path) -> None:
    source = tmp_path / "memory.json"
    source.write_text(
        '[{"id":"a","content":"old","title":"same","name":"same"}]',
        encoding="utf-8",
    )
    adapter = _adapter(source, tmp_path)
    plan = adapter.plan_mutation(
        MutationOperation(
            kind=MutationKind.UPDATE_FIELD,
            record_id="a",
            field="title",
            value="new",
        ),
        expected_revision=adapter.current_revision(),
    )
    swapped = plan.model_copy(
        update={
            "operation": MutationOperation(
                kind=MutationKind.UPDATE_FIELD,
                record_id="a",
                field="name",
                value="new",
            )
        }
    )

    with pytest.raises(MemoryError, match="tampered"):
        adapter.apply(swapped)


def test_json_rejects_duplicate_object_keys_at_every_depth(tmp_path: Path) -> None:
    source = tmp_path / "memory.json"
    source.write_text(
        '[{"id":"a","content":"one","metadata":{"tag":"x","tag":"y"}}]',
        encoding="utf-8",
    )

    with pytest.raises(MemoryError, match="duplicate.*key"):
        _adapter(source, tmp_path).query()


def test_jsonl_fallback_ids_survive_unrelated_line_insertion(tmp_path: Path) -> None:
    source = tmp_path / "memory.jsonl"
    source.write_text(
        '{"content":"same"}\n{"content":"same"}\n{"content":"other"}\n',
        encoding="utf-8",
    )
    before = [record.record_id for record in _adapter(source, tmp_path).query().records]
    source.write_text(
        '{"content":"inserted"}\n{"content":"same"}\n{"content":"same"}\n{"content":"other"}\n',
        encoding="utf-8",
    )
    after = [record.record_id for record in _adapter(source, tmp_path).query().records]

    assert before == after[1:]
    assert before[0] != before[1]


def test_jsonl_mutation_does_not_materialize_a_hidden_identifier(tmp_path: Path) -> None:
    source = tmp_path / "memory.jsonl"
    source.write_text('{"content":"old","metadata":{"tag":"safe"}}\n', encoding="utf-8")
    adapter = _adapter(source, tmp_path)
    record_id = adapter.query().records[0].record_id
    plan = adapter.plan_mutation(
        MutationOperation(
            kind=MutationKind.UPDATE_CONTENT,
            record_id=record_id,
            value="new",
        ),
        expected_revision=adapter.current_revision(),
    )

    adapter.apply(plan)

    persisted = json.loads(source.read_text(encoding="utf-8"))
    assert persisted == {"content": "new", "metadata": {"tag": "safe"}}


def test_corrupt_persisted_memory_authority_is_never_claimed(tmp_path: Path) -> None:
    source = tmp_path / "memory.json"
    source.write_text('[{"id":"a","content":"old"}]', encoding="utf-8")
    store = _state_store(tmp_path)
    adapter = JsonMemoryAdapter(source, backups_dir=tmp_path / "backups", state_store=store)
    plan = adapter.plan_mutation(
        MutationOperation(kind=MutationKind.UPDATE_CONTENT, record_id="a", value="new"),
        expected_revision=adapter.current_revision(),
    )
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE memory_mutation_plans SET record_hash=? WHERE plan_id=?",
            ("f" * 64, plan.plan_id),
        )

    with pytest.raises(PlanClaimError, match="authority|invalid"):
        store.claim_memory_plan(plan.plan_id, expected_digest=plan.digest)

    with sqlite3.connect(store.database_path) as connection:
        assert (
            connection.execute(
                "SELECT status FROM memory_mutation_plans WHERE plan_id=?", (plan.plan_id,)
            ).fetchone()[0]
            == "planned"
        )


def test_json_restore_receipt_loss_is_reconciled_and_replay_is_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "memory.json"
    source.write_text('[{"id":"a","content":"old"}]', encoding="utf-8")
    store = _state_store(tmp_path)
    adapter = JsonMemoryAdapter(source, backups_dir=tmp_path / "backups", state_store=store)
    snapshot = adapter.backup(expected_revision=adapter.current_revision())
    mutation = adapter.plan_mutation(
        MutationOperation(kind=MutationKind.UPDATE_CONTENT, record_id="a", value="new"),
        expected_revision=adapter.current_revision(),
    )
    mutation_receipt = adapter.apply(mutation)
    original_finish = store.finish_memory_restore
    failed = False

    def lose_first_receipt(receipt: object) -> None:
        nonlocal failed
        if not failed:
            failed = True
            raise PermissionError("C:/secret-state/receipt.sqlite3")
        original_finish(receipt)  # type: ignore[arg-type]

    monkeypatch.setattr(store, "finish_memory_restore", lose_first_receipt)
    with pytest.raises(MemoryError, match="reconciliation") as failure:
        adapter.restore(
            snapshot.snapshot_id,
            expected_snapshot_digest=snapshot.digest,
            expected_revision=mutation_receipt.after_revision,
        )
    assert "secret-state" not in str(failure.value)
    assert adapter.get("a").content == "old"

    reopened = _state_store(tmp_path, owner_alive=False)
    recovered = JsonMemoryAdapter(source, backups_dir=tmp_path / "backups", state_store=reopened)
    receipt = recovered.restore(
        snapshot.snapshot_id,
        expected_snapshot_digest=snapshot.digest,
        expected_revision=mutation_receipt.after_revision,
    )

    assert receipt.operation == "reconciled_restore"
    assert recovered.get("a").content == "old"


def test_apply_journal_lock_is_bounded_and_same_process_session_recovers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "memory.json"
    source.write_text('[{"id":"a","content":"old"}]', encoding="utf-8")
    store = SQLiteStateStore(
        AppPaths(
            data_dir=tmp_path / "app-data",
            state_dir=tmp_path / "app-state",
            runtime_dir=tmp_path / "app-runtime",
            backups_dir=tmp_path / "backups",
            graveyard_dir=tmp_path / "graveyard",
        ),
        busy_timeout_ms=10,
    )
    store.initialize()
    adapter = JsonMemoryAdapter(source, backups_dir=tmp_path / "backups", state_store=store)
    plan = adapter.plan_mutation(
        MutationOperation(kind=MutationKind.UPDATE_CONTENT, record_id="a", value="new"),
        expected_revision=adapter.current_revision(),
    )
    original_replace = adapter._replace
    blocker: sqlite3.Connection | None = None

    def replace_then_lock(data: bytes, **binding: object) -> None:
        nonlocal blocker
        original_replace(data, **binding)  # type: ignore[arg-type]
        if blocker is not None:
            return
        blocker = sqlite3.connect(store.database_path, isolation_level=None, timeout=0.01)
        blocker.execute("PRAGMA busy_timeout=10")
        blocker.execute("BEGIN EXCLUSIVE")

    monkeypatch.setattr(adapter, "_replace", replace_then_lock)
    with pytest.raises(MemoryError, match="journal|recover|safe") as failure:
        adapter.apply(plan)
    assert str(store.database_path) not in str(failure.value)
    assert blocker is not None
    blocker.rollback()
    blocker.close()

    reopened = _state_store(tmp_path)
    JsonMemoryAdapter(source, backups_dir=tmp_path / "backups", state_store=reopened)

    assert json.loads(source.read_text(encoding="utf-8"))[0]["content"] == "new"
    with sqlite3.connect(reopened.database_path) as connection:
        assert (
            connection.execute(
                "SELECT status FROM memory_mutation_plans WHERE plan_id=?", (plan.plan_id,)
            ).fetchone()[0]
            == "succeeded"
        )


def test_restore_journal_lock_reconciles_and_failed_attempt_can_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "memory.json"
    source.write_text('[{"id":"a","content":"old"}]', encoding="utf-8")
    store = SQLiteStateStore(
        AppPaths(
            data_dir=tmp_path / "app-data",
            state_dir=tmp_path / "app-state",
            runtime_dir=tmp_path / "app-runtime",
            backups_dir=tmp_path / "backups",
            graveyard_dir=tmp_path / "graveyard",
        ),
        busy_timeout_ms=10,
    )
    store.initialize()
    adapter = JsonMemoryAdapter(source, backups_dir=tmp_path / "backups", state_store=store)
    snapshot = adapter.backup(expected_revision=adapter.current_revision())
    mutation = adapter.plan_mutation(
        MutationOperation(kind=MutationKind.UPDATE_CONTENT, record_id="a", value="new"),
        expected_revision=adapter.current_revision(),
    )
    mutation_receipt = adapter.apply(mutation)
    original_replace = adapter._replace
    blocker: sqlite3.Connection | None = None

    def restore_then_lock(data: bytes, **binding: object) -> None:
        nonlocal blocker
        original_replace(data, **binding)  # type: ignore[arg-type]
        blocker = sqlite3.connect(store.database_path, isolation_level=None, timeout=0.01)
        blocker.execute("PRAGMA busy_timeout=10")
        blocker.execute("BEGIN EXCLUSIVE")

    monkeypatch.setattr(adapter, "_replace", restore_then_lock)
    with pytest.raises(MemoryError, match="journal|reconcil|uncertain"):
        adapter.restore(
            snapshot.snapshot_id,
            expected_snapshot_digest=snapshot.digest,
            expected_revision=mutation_receipt.after_revision,
        )
    assert blocker is not None
    blocker.rollback()
    blocker.close()

    reopened = _state_store(tmp_path)
    recovered = JsonMemoryAdapter(source, backups_dir=tmp_path / "backups", state_store=reopened)
    replay = recovered.restore(
        snapshot.snapshot_id,
        expected_snapshot_digest=snapshot.digest,
        expected_revision=mutation_receipt.after_revision,
    )
    assert replay.operation == "reconciled_restore"

    second_source = tmp_path / "retry.json"
    second_source.write_text('[{"id":"a","content":"old"}]', encoding="utf-8")
    second = _adapter(second_source, tmp_path)
    second_snapshot = second.backup(expected_revision=second.current_revision())
    second_plan = second.plan_mutation(
        MutationOperation(kind=MutationKind.UPDATE_CONTENT, record_id="a", value="new"),
        expected_revision=second.current_revision(),
    )
    second_receipt = second.apply(second_plan)
    real_replace = second._replace
    replace_calls = 0

    def fail_restore_once(data: bytes, **binding: object) -> None:
        nonlocal replace_calls
        replace_calls += 1
        if replace_calls == 1:
            raise MemoryError("synthetic restore failure")
        real_replace(data, **binding)  # type: ignore[arg-type]

    monkeypatch.setattr(second, "_replace", fail_restore_once)
    with pytest.raises(MemoryError, match="restore"):
        second.restore(
            second_snapshot.snapshot_id,
            expected_snapshot_digest=second_snapshot.digest,
            expected_revision=second_receipt.after_revision,
        )
    with sqlite3.connect(second._state_store.database_path) as connection:
        failed_id = connection.execute(
            "SELECT restore_plan_id FROM memory_restore_plans WHERE status='failed'"
        ).fetchone()[0]
    monkeypatch.setattr(second, "_replace", real_replace)
    retried = second.restore(
        second_snapshot.snapshot_id,
        expected_snapshot_digest=second_snapshot.digest,
        expected_revision=second_receipt.after_revision,
    )
    assert retried.restore_plan_id != failed_id


def test_apply_store_path_outage_is_redacted_and_same_process_reconciles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "memory.json"
    source.write_text('[{"id":"a","content":"old"}]', encoding="utf-8")
    store = _state_store(tmp_path)
    adapter = JsonMemoryAdapter(source, backups_dir=tmp_path / "backups", state_store=store)
    plan = adapter.plan_mutation(
        MutationOperation(kind=MutationKind.UPDATE_CONTENT, record_id="a", value="new"),
        expected_revision=adapter.current_revision(),
    )
    original_connect = store._connect
    original_replace = adapter._replace
    outage = False

    def replace_then_outage(data: bytes, **binding: object) -> None:
        nonlocal outage
        original_replace(data, **binding)  # type: ignore[arg-type]
        outage = True

    def unavailable_connect(*, allow_missing: bool = False) -> sqlite3.Connection:
        if outage:
            raise StorePathError("C:/sensitive-state/journal.sqlite3")
        return original_connect(allow_missing=allow_missing)

    monkeypatch.setattr(adapter, "_replace", replace_then_outage)
    monkeypatch.setattr(store, "_connect", unavailable_connect)
    with pytest.raises(MemoryError, match="journal|reconcil") as failure:
        adapter.apply(plan)
    assert "sensitive-state" not in str(failure.value)
    assert failure.value.__cause__ is None

    outage = False
    reopened = _state_store(tmp_path)
    JsonMemoryAdapter(source, backups_dir=tmp_path / "backups", state_store=reopened)
    with sqlite3.connect(reopened.database_path) as connection:
        assert (
            connection.execute(
                "SELECT status FROM memory_mutation_plans WHERE plan_id=?", (plan.plan_id,)
            ).fetchone()[0]
            == "succeeded"
        )


def test_restore_permission_outage_is_redacted_and_same_process_reconciles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "memory.json"
    source.write_text('[{"id":"a","content":"old"}]', encoding="utf-8")
    store = _state_store(tmp_path)
    adapter = JsonMemoryAdapter(source, backups_dir=tmp_path / "backups", state_store=store)
    snapshot = adapter.backup(expected_revision=adapter.current_revision())
    mutation = adapter.plan_mutation(
        MutationOperation(kind=MutationKind.UPDATE_CONTENT, record_id="a", value="new"),
        expected_revision=adapter.current_revision(),
    )
    mutation_receipt = adapter.apply(mutation)
    original_connect = store._connect
    original_replace = adapter._replace
    outage = False

    def replace_then_outage(data: bytes, **binding: object) -> None:
        nonlocal outage
        original_replace(data, **binding)  # type: ignore[arg-type]
        outage = True

    def unavailable_connect(*, allow_missing: bool = False) -> sqlite3.Connection:
        if outage:
            raise PermissionError("C:/private-state/journal.sqlite3")
        return original_connect(allow_missing=allow_missing)

    monkeypatch.setattr(adapter, "_replace", replace_then_outage)
    monkeypatch.setattr(store, "_connect", unavailable_connect)
    with pytest.raises(MemoryError, match="journal|reconcil|uncertain") as failure:
        adapter.restore(
            snapshot.snapshot_id,
            expected_snapshot_digest=snapshot.digest,
            expected_revision=mutation_receipt.after_revision,
        )
    assert "private-state" not in str(failure.value)
    assert failure.value.__cause__ is None

    outage = False
    reopened = _state_store(tmp_path)
    recovered = JsonMemoryAdapter(source, backups_dir=tmp_path / "backups", state_store=reopened)
    replay = recovered.restore(
        snapshot.snapshot_id,
        expected_snapshot_digest=snapshot.digest,
        expected_revision=mutation_receipt.after_revision,
    )
    assert replay.operation == "reconciled_restore"


def test_restore_uses_stored_snapshot_id_and_rejects_raw_or_dotdot_authority(
    tmp_path: Path,
) -> None:
    source = tmp_path / "memory.json"
    source.write_text('[{"id":"a","content":"old"}]', encoding="utf-8")
    store = _state_store(tmp_path)
    adapter = JsonMemoryAdapter(
        source,
        backups_dir=tmp_path / "backups",
        state_store=store,
    )
    plan = adapter.plan_mutation(
        MutationOperation(kind=MutationKind.UPDATE_CONTENT, record_id="a", value="new"),
        expected_revision=adapter.current_revision(),
    )
    receipt = adapter.apply(plan)
    snapshot = store.get_memory_snapshot(receipt.snapshot_id)
    assert snapshot is not None

    with pytest.raises((TypeError, MemoryError)):
        adapter.restore(  # type: ignore[arg-type]
            snapshot,
            expected_snapshot_digest=snapshot.digest,
            expected_revision=receipt.after_revision,
        )

    backup = Path(snapshot.backup_path)
    replacement = backup.with_name("replacement.snapshot")
    replacement.write_bytes(backup.read_bytes())
    os.replace(replacement, backup)
    with pytest.raises(MemoryError, match="identity|snapshot"):
        adapter.restore(
            snapshot.snapshot_id,
            expected_snapshot_digest=snapshot.digest,
            expected_revision=receipt.after_revision,
        )

    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE memory_snapshots SET backup_path = ? WHERE snapshot_id = ?",
            (str(tmp_path / "backups" / ".." / "attacker.snapshot"), snapshot.snapshot_id),
        )
    with pytest.raises(MemoryError, match="snapshot|backup|path"):
        adapter.restore(
            snapshot.snapshot_id,
            expected_snapshot_digest=snapshot.digest,
            expected_revision=receipt.after_revision,
        )


def test_file_access_denial_is_normalized_without_path_leakage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "sensitive-name.json"
    source.write_text("[]", encoding="utf-8")

    def deny(*_args: object, **_kwargs: object) -> int:
        raise PermissionError(f"denied {source}")

    monkeypatch.setattr(os, "open", deny)
    with pytest.raises(MemoryError, match="could not be opened") as captured:
        read_pinned(source, max_bytes=1024)
    assert str(source) not in str(captured.value)


def test_json_lazy_reconciliation_finalizes_crash_after_replace(tmp_path: Path) -> None:
    source = tmp_path / "memory.json"
    source.write_text('[{"id":"a","content":"old"}]', encoding="utf-8")
    store = _state_store(tmp_path)
    adapter = JsonMemoryAdapter(source, backups_dir=tmp_path / "backups", state_store=store)
    plan = adapter.plan_mutation(
        MutationOperation(kind=MutationKind.UPDATE_CONTENT, record_id="a", value="new"),
        expected_revision=adapter.current_revision(),
    )
    store.claim_memory_plan(plan.plan_id, expected_digest=plan.digest)
    data, parsed, _identity = adapter._read()
    mutated, _old, _new, _field = adapter._mutate(parsed, plan.operation)
    snapshot = adapter.backup(expected_revision=adapter._revision(data))
    store.update_memory_plan_phase(
        plan.plan_id, "snapshot_verified", snapshot_id=snapshot.snapshot_id
    )
    store.update_memory_plan_phase(plan.plan_id, "write_issuing")
    adapter._replace(adapter._render(mutated))
    store.update_memory_plan_phase(plan.plan_id, "committed")

    reopened_store = _state_store(tmp_path, owner_alive=False)
    JsonMemoryAdapter(
        source,
        backups_dir=tmp_path / "backups",
        state_store=reopened_store,
    )

    with sqlite3.connect(reopened_store.database_path) as connection:
        assert connection.execute(
            "SELECT status, phase FROM memory_mutation_plans WHERE plan_id = ?",
            (plan.plan_id,),
        ).fetchone() == ("succeeded", "recovered_completed")
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM memory_receipts WHERE plan_id = ?",
                (plan.plan_id,),
            ).fetchone()[0]
            == 1
        )


def test_relative_symlink_and_alternate_stream_paths_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(MemoryError, match="absolute"):
        JsonMemoryAdapter(
            Path("relative.json"),
            backups_dir=tmp_path / "backups",
            state_store=_state_store(tmp_path),
        )

    source = tmp_path / "memory.json"
    source.write_text("[]", encoding="utf-8")
    alias_parent = tmp_path / "alias-parent"
    alias_parent.mkdir()
    lexical_alias = alias_parent / ".." / source.name
    with pytest.raises(MemoryError, match="dot|segment|path"):
        JsonMemoryAdapter(
            lexical_alias,
            backups_dir=tmp_path / "backups",
            state_store=_state_store(tmp_path),
        )
    link = tmp_path / "link.json"
    try:
        link.symlink_to(source)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(MemoryError, match="link|reparse"):
        JsonMemoryAdapter(
            link,
            backups_dir=tmp_path / "backups",
            state_store=_state_store(tmp_path),
        )

    if os.name == "nt":
        with pytest.raises(MemoryError, match="stream"):
            JsonMemoryAdapter(
                Path(f"{source}:stream"),
                backups_dir=tmp_path / "backups",
                state_store=_state_store(tmp_path),
            )


def test_persistent_sidecar_lock_survives_source_inode_replacement(tmp_path: Path) -> None:
    source = tmp_path / "memory.json"
    source.write_text("[]", encoding="utf-8")
    replacement = tmp_path / "replacement.json"
    replacement.write_text("[]", encoding="utf-8")
    probe = (
        "from pathlib import Path\n"
        "from zombie_killer_engine.memory.base import MemoryError, exclusive_file_lock\n"
        "try:\n"
        "    with exclusive_file_lock(Path(__import__('sys').argv[1])):\n"
        "        raise SystemExit(9)\n"
        "except MemoryError:\n"
        "    raise SystemExit(0)\n"
    )

    with exclusive_file_lock(source):
        os.replace(replacement, source)
        child = subprocess.run(
            [sys.executable, "-c", probe, str(source)],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )

    assert child.returncode == 0, child.stderr


def test_json_commit_revalidates_after_replacement_preparation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "memory.json"
    source.write_text('[{"id":"a","content":"old"}]', encoding="utf-8")
    adapter = _adapter(source, tmp_path)
    plan = adapter.plan_mutation(
        MutationOperation(kind=MutationKind.UPDATE_CONTENT, record_id="a", value="new"),
        expected_revision=adapter.current_revision(),
    )
    original_read = json_store_module.read_pinned
    external = b'[{"id":"a","content":"external"}]'

    def write_during_preparation(path: Path, *, max_bytes: int) -> tuple[bytes, object]:
        result = original_read(path, max_bytes=max_bytes)
        if path.suffix == ".tmp":
            source.write_bytes(external)
        return result

    monkeypatch.setattr(json_store_module, "read_pinned", write_during_preparation)
    with pytest.raises(MemoryError, match="changed|revision|uncertain"):
        adapter.apply(plan)

    assert source.read_bytes() == external


def test_json_failed_apply_preserves_later_external_version_and_recovery_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "memory.json"
    source.write_text('[{"id":"a","content":"old"}]', encoding="utf-8")
    store = _state_store(tmp_path)
    adapter = JsonMemoryAdapter(source, backups_dir=tmp_path / "backups", state_store=store)
    plan = adapter.plan_mutation(
        MutationOperation(kind=MutationKind.UPDATE_CONTENT, record_id="a", value="new"),
        expected_revision=adapter.current_revision(),
    )
    original_phase = store.update_memory_plan_phase
    external = b'[{"id":"a","content":"external"}]'

    def external_write(plan_id: str, phase: str, *, snapshot_id: str | None = None) -> None:
        original_phase(plan_id, phase, snapshot_id=snapshot_id)
        if phase == "committed":
            source.write_bytes(external)
            raise MemoryError("synthetic post-commit verification failure")

    monkeypatch.setattr(store, "update_memory_plan_phase", external_write)
    with pytest.raises(MemoryError):
        adapter.apply(plan)

    assert source.read_bytes() == external
    reopened = _state_store(tmp_path, owner_alive=False)
    JsonMemoryAdapter(source, backups_dir=tmp_path / "backups", state_store=reopened)
    with sqlite3.connect(reopened.database_path) as connection:
        status, snapshot_id = connection.execute(
            "SELECT status, snapshot_id FROM memory_mutation_plans WHERE plan_id=?",
            (plan.plan_id,),
        ).fetchone()
        assert status == "interrupted"
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM memory_receipts WHERE plan_id=?", (plan.plan_id,)
            ).fetchone()[0]
            == 0
        )
    assert adapter.snapshot(snapshot_id).digest == plan.source_revision


def test_json_restore_refuses_source_change_after_rollback_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "memory.json"
    source.write_text('[{"id":"a","content":"old"}]', encoding="utf-8")
    store = _state_store(tmp_path)
    adapter = JsonMemoryAdapter(source, backups_dir=tmp_path / "backups", state_store=store)
    snapshot = adapter.backup(expected_revision=adapter.current_revision())
    receipt = adapter.apply(
        adapter.plan_mutation(
            MutationOperation(kind=MutationKind.UPDATE_CONTENT, record_id="a", value="new"),
            expected_revision=adapter.current_revision(),
        )
    )
    original_phase = store.update_memory_restore_phase
    external = b'[{"id":"a","content":"external"}]'

    def external_write(
        restore_plan_id: str, phase: str, *, rollback_snapshot_id: str | None = None
    ) -> None:
        original_phase(restore_plan_id, phase, rollback_snapshot_id=rollback_snapshot_id)
        if phase == "restore_issuing":
            source.write_bytes(external)

    monkeypatch.setattr(store, "update_memory_restore_phase", external_write)
    with pytest.raises(MemoryError, match="changed|revision|uncertain"):
        adapter.restore(
            snapshot.snapshot_id,
            expected_snapshot_digest=snapshot.digest,
            expected_revision=receipt.after_revision,
        )

    assert source.read_bytes() == external


def test_json_restore_reconciliation_requires_intact_snapshot_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "memory.json"
    source.write_text('[{"id":"a","content":"old"}]', encoding="utf-8")
    store = _state_store(tmp_path)
    adapter = JsonMemoryAdapter(source, backups_dir=tmp_path / "backups", state_store=store)
    snapshot = adapter.backup(expected_revision=adapter.current_revision())
    receipt = adapter.apply(
        adapter.plan_mutation(
            MutationOperation(kind=MutationKind.UPDATE_CONTENT, record_id="a", value="new"),
            expected_revision=adapter.current_revision(),
        )
    )

    def lose_receipt(_receipt: object) -> None:
        raise MemoryError("synthetic journal outage")

    monkeypatch.setattr(store, "finish_memory_restore", lose_receipt)
    with pytest.raises(MemoryError, match="reconciliation"):
        adapter.restore(
            snapshot.snapshot_id,
            expected_snapshot_digest=snapshot.digest,
            expected_revision=receipt.after_revision,
        )
    Path(snapshot.backup_path).write_bytes(b"tampered evidence")
    reopened = _state_store(tmp_path, owner_alive=False)
    JsonMemoryAdapter(source, backups_dir=tmp_path / "backups", state_store=reopened)
    with sqlite3.connect(reopened.database_path) as connection:
        assert connection.execute("SELECT status FROM memory_restore_plans").fetchall() == [
            ("interrupted",)
        ]
        assert connection.execute(
            "SELECT COUNT(*) FROM memory_receipts WHERE restore_plan_id IS NOT NULL"
        ).fetchone() == (0,)


@pytest.mark.skipif(os.name == "nt", reason="Windows denies rename of CRT-open source")
def test_pinned_read_rejects_path_swap_during_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "memory.json"
    source.write_bytes(b"original")
    replacement = tmp_path / "replacement.json"
    replacement.write_bytes(b"replacement")
    original_read = os.read
    swapped = False

    def swap_during_read(descriptor: int, size: int) -> bytes:
        nonlocal swapped
        data = original_read(descriptor, size)
        if not swapped:
            swapped = True
            os.replace(replacement, source)
        return data

    monkeypatch.setattr(os, "read", swap_during_read)
    with pytest.raises(MemoryError, match="changed|identity"):
        read_pinned(source, max_bytes=100)
    assert source.read_bytes() == b"replacement"


@pytest.mark.parametrize("prefix", [False, True])
def test_pinned_reads_recheck_named_identity_after_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, prefix: bool
) -> None:
    source = tmp_path / "memory.json"
    source.write_bytes(b"original")
    other = tmp_path / "other.json"
    other.write_bytes(b"other")
    other_stat = other.stat()
    original_read, original_lstat = os.read, os.lstat
    read_started = False

    def observe_name_change(descriptor: int, size: int) -> bytes:
        nonlocal read_started
        read_started = True
        return original_read(descriptor, size)

    def changed_name(path: object, **options: object) -> os.stat_result:
        if path == source and read_started:
            return other_stat
        return original_lstat(path, **options)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "read", observe_name_change)
    monkeypatch.setattr(os, "lstat", changed_name)
    with pytest.raises(MemoryError, match="changed|identity"):
        if prefix:
            read_prefix_pinned(source, prefix_bytes=4)
        else:
            read_pinned(source, max_bytes=100)


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission semantics")
def test_world_writable_non_sticky_source_ancestor_is_rejected(tmp_path: Path) -> None:
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o700)
    source = unsafe / "memory.json"
    source.write_text("[]", encoding="utf-8")
    unsafe.chmod(0o777)

    with pytest.raises(MemoryError, match="ancestor|access"):
        JsonMemoryAdapter(
            source,
            backups_dir=tmp_path / "backups",
            state_store=_state_store(tmp_path),
        )


def test_json_apply_rejects_expiry_after_temporary_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "memory.json"
    before = b'[{"id":"a","content":"old"}]'
    source.write_bytes(before)
    adapter = _adapter(source, tmp_path)
    clock = [datetime.now(UTC)]
    monkeypatch.setattr(base_module, "utc_now", lambda: clock[0])
    monkeypatch.setattr(json_store_module, "utc_now", lambda: clock[0])
    plan = adapter.plan_mutation(
        MutationOperation(kind=MutationKind.UPDATE_CONTENT, record_id="a", value="new"),
        expected_revision=adapter.current_revision(),
    )
    original_read = json_store_module.read_pinned

    def expire_at_temporary_verification(path: Path, *, max_bytes: int) -> tuple[bytes, object]:
        result = original_read(path, max_bytes=max_bytes)
        if path.suffix == ".tmp":
            clock[0] = plan.expires_at
        return result

    monkeypatch.setattr(json_store_module, "read_pinned", expire_at_temporary_verification)
    with pytest.raises(MemoryError, match="expired"):
        adapter.apply(plan)
    assert source.read_bytes() == before


@pytest.mark.parametrize("reviewed_seconds", [None, 10, 60])
def test_json_restore_checks_earliest_deadline_after_temporary_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reviewed_seconds: int | None
) -> None:
    source = tmp_path / "memory.json"
    source.write_bytes(b'[{"id":"a","content":"old"}]')
    adapter = _adapter(source, tmp_path)
    snapshot = adapter.backup(expected_revision=adapter.current_revision())
    adapter.apply(
        adapter.plan_mutation(
            MutationOperation(kind=MutationKind.UPDATE_CONTENT, record_id="a", value="new"),
            expected_revision=adapter.current_revision(),
        )
    )
    before = source.read_bytes()
    clock = [datetime.now(UTC)]
    reviewed = (
        clock[0] + timedelta(seconds=reviewed_seconds) if reviewed_seconds is not None else None
    )
    boundary = clock[0] + timedelta(seconds=min(reviewed_seconds or 30, 30))
    monkeypatch.setattr(base_module, "utc_now", lambda: clock[0])
    monkeypatch.setattr(json_store_module, "utc_now", lambda: clock[0])
    original_read = json_store_module.read_pinned

    def expire_at_temporary_verification(path: Path, *, max_bytes: int) -> tuple[bytes, object]:
        result = original_read(path, max_bytes=max_bytes)
        if path.suffix == ".tmp":
            clock[0] = boundary
        return result

    monkeypatch.setattr(json_store_module, "read_pinned", expire_at_temporary_verification)
    options = {"reviewed_expires_at": reviewed} if reviewed is not None else {}
    with pytest.raises(MemoryError, match="expired"):
        adapter.restore(
            snapshot.snapshot_id,
            expected_snapshot_digest=snapshot.digest,
            expected_revision=adapter.current_revision(),
            **options,
        )
    assert source.read_bytes() == before


@pytest.mark.parametrize("deadline", [datetime(2026, 10, 2), float("nan"), "invalid"])
def test_json_restore_rejects_nonaware_or_invalid_reviewed_deadline(
    tmp_path: Path, deadline: object
) -> None:
    source = tmp_path / "memory.json"
    before = b'[{"id":"a","content":"old"}]'
    source.write_bytes(before)
    adapter = _adapter(source, tmp_path)
    snapshot = adapter.backup(expected_revision=adapter.current_revision())
    with pytest.raises(MemoryError, match="deadline|datetime"):
        adapter.restore(
            snapshot.snapshot_id,
            expected_snapshot_digest=snapshot.digest,
            expected_revision=adapter.current_revision(),
            reviewed_expires_at=deadline,  # type: ignore[arg-type]
        )
    assert source.read_bytes() == before


@pytest.mark.parametrize("through_workflow", [False, True])
def test_json_post_commit_reversion_cannot_erase_known_write_issuance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, through_workflow: bool
) -> None:
    source = tmp_path / "memory.json"
    before = b'[{"id":"a","content":"before"}]'
    source.write_bytes(before)
    store = _state_store(tmp_path)
    adapter = JsonMemoryAdapter(source, backups_dir=tmp_path / "backups", state_store=store)
    workflow = MemoryWorkflow(store, lambda _selected_id: adapter)
    operation = MutationOperation(kind=MutationKind.UPDATE_CONTENT, record_id="a", value="after")
    domain_plan = None
    if through_workflow:
        reviewed = workflow.plan_mutation(
            base_module.source_id(source), operation, adapter.current_revision()
        )
        plan_id = str(reviewed["plan_id"])
    else:
        domain_plan = adapter.plan_mutation(operation, expected_revision=adapter.current_revision())
        plan_id = domain_plan.plan_id
    original_phase = store.update_memory_plan_phase
    observed_commits: list[str] = []

    def revert_after_observed_commit(
        selected_plan: str, phase: str, *, snapshot_id: str | None = None
    ) -> None:
        original_phase(selected_plan, phase, snapshot_id=snapshot_id)
        if phase == "committed":
            observed_commits.append(json.loads(source.read_bytes())[0]["content"])
            source.write_bytes(before)
            raise OSError("fixture post-write journal failure")

    monkeypatch.setattr(store, "update_memory_plan_phase", revert_after_observed_commit)
    if through_workflow:
        result = workflow.execute_mutation(plan_id, str(reviewed["digest"]))
        assert result["certainty"] == "uncertain"
        assert result["action_issued"] is None
    else:
        assert domain_plan is not None
        with pytest.raises(MemoryError, match="uncertain"):
            adapter.apply(domain_plan)
    assert observed_commits == ["after"]
    assert source.read_bytes() == before
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "SELECT status FROM memory_mutation_plans WHERE plan_id=?", (plan_id,)
        ).fetchone() == ("interrupted",)
