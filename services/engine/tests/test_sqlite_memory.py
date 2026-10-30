from __future__ import annotations

import os
import sqlite3
import subprocess
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from zombie_killer_engine.memory import (
    MemoryError,
    MutationKind,
    MutationOperation,
    SQLiteMemoryAdapter,
    UnsupportedReadOnlyAdapter,
    VaultFormat,
)
from zombie_killer_engine.memory import base as base_module
from zombie_killer_engine.memory import sqlite_store as sqlite_store_module
from zombie_killer_engine.memory.base import capture_file_security
from zombie_killer_engine.paths import AppPaths
from zombie_killer_engine.store import SQLiteStateStore


def _database(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            PRAGMA foreign_keys = ON;
            CREATE TABLE memories (
                id INTEGER PRIMARY KEY,
                content TEXT NOT NULL,
                tag TEXT,
                score REAL
            );
            INSERT INTO memories(content, tag, score) VALUES ('alpha', 'red', 1.5);
            CREATE TABLE composite (a INTEGER, b INTEGER, value TEXT, PRIMARY KEY(a,b));
            CREATE TABLE no_pk (value TEXT);
            CREATE VIEW memory_view AS SELECT id, content FROM memories;
            """
        )


def _adapter(source: Path, tmp_path: Path) -> SQLiteMemoryAdapter:
    backups = tmp_path / "backups"
    backups.mkdir(mode=0o700, exist_ok=True)
    return SQLiteMemoryAdapter(source, backups_dir=backups, state_store=_state_store(tmp_path))


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


def test_sqlite_inventory_and_parameterized_browse(tmp_path: Path) -> None:
    source = tmp_path / "memory.sqlite3"
    _database(source)
    adapter = _adapter(source, tmp_path).open(read_only=True)

    inventory = {item.name: item for item in adapter.inventory()}

    assert inventory["memories"].editable is True
    assert inventory["composite"].editable is False
    assert inventory["no_pk"].editable is False
    assert inventory["memory_view"].editable is False
    page = adapter.query(namespace="memories")
    assert page.records[0].record_id == "memories:i:1"
    assert page.records[0].content == "alpha"
    assert adapter.get("memories:i:1").metadata["tag"] == "red"


def test_sqlite_cursor_pagination_orders_table_without_primary_key_deterministically(
    tmp_path: Path,
) -> None:
    source = tmp_path / "no-primary-key.sqlite3"
    with sqlite3.connect(source) as connection:
        connection.execute(
            "CREATE TABLE unordered_rows(content TEXT NOT NULL, tag INTEGER NOT NULL)"
        )
        connection.executemany(
            "INSERT INTO unordered_rows(content, tag) VALUES (?, ?)",
            ((f"memory-{index:03d}", index % 3) for index in reversed(range(64))),
        )
    adapter = _adapter(source, tmp_path).open(read_only=True)

    first = adapter.query(namespace="unordered_rows", limit=32)
    assert first.next_cursor == "32"
    second = adapter.query(
        namespace="unordered_rows",
        cursor=first.next_cursor,
        limit=32,
    )

    assert [record.content for record in (*first.records, *second.records)] == [
        f"memory-{index:03d}" for index in range(64)
    ]
    assert [record.record_id for record in (*first.records, *second.records)] == [
        f"unordered_rows:row-{index}" for index in range(64)
    ]


def test_sqlite_volatile_views_are_inventory_only_and_cannot_issue_cursors(
    tmp_path: Path,
) -> None:
    source = tmp_path / "volatile-view.sqlite3"
    with sqlite3.connect(source) as connection:
        connection.executescript(
            "CREATE TABLE source_rows(position INTEGER PRIMARY KEY, content TEXT NOT NULL);"
            "CREATE VIEW volatile_rows AS "
            "SELECT random() AS shuffle, content FROM source_rows;"
        )
        connection.executemany(
            "INSERT INTO source_rows(position, content) VALUES (?, ?)",
            ((index, f"memory-{index:03d}") for index in range(64)),
        )
    adapter = _adapter(source, tmp_path).open(read_only=True)

    inventory = {item.name: item for item in adapter.inventory()}
    assert inventory["volatile_rows"].reason == "views are inventory-only"
    with pytest.raises(MemoryError, match="inventory-only"):
        adapter.query(namespace="volatile_rows", limit=32)


def test_chroma_and_faiss_are_recognized_as_explicitly_read_only(tmp_path: Path) -> None:
    chroma = tmp_path / "chroma.sqlite3"
    with sqlite3.connect(chroma) as connection:
        connection.executescript(
            "CREATE TABLE collections(id TEXT PRIMARY KEY);"
            "CREATE TABLE embeddings(id TEXT PRIMARY KEY);"
        )
    chroma_probe = SQLiteMemoryAdapter.probe(chroma)
    assert chroma_probe.format is VaultFormat.CHROMA
    assert chroma_probe.capabilities.editable is False
    assert "inventory-only" in (chroma_probe.reason or "")

    faiss = tmp_path / "vectors.faiss"
    faiss.write_bytes(b"IxF2" + b"\x00" * 64)
    faiss_probe = UnsupportedReadOnlyAdapter.probe(faiss)
    assert faiss_probe.format is VaultFormat.FAISS
    assert faiss_probe.capabilities.editable is False
    unsupported = UnsupportedReadOnlyAdapter(
        faiss, format=VaultFormat.FAISS, reason=faiss_probe.reason or "read-only"
    ).open(read_only=True)
    assert unsupported.list_namespaces() == ()
    assert len(unsupported.current_revision()) == 64
    unsupported.healthcheck()
    with pytest.raises(MemoryError, match="query|read-only|unsupported"):
        unsupported.query()
    with pytest.raises(MemoryError, match="query|read-only|unsupported"):
        unsupported.get("record")
    with pytest.raises(MemoryError, match="restore|read-only|unsupported"):
        unsupported.restore(
            "snapshot",
            expected_snapshot_digest="0" * 64,
            expected_revision=unsupported.current_revision(),
        )

    chroma_adapter = SQLiteMemoryAdapter(
        chroma,
        backups_dir=tmp_path / "backups",
        state_store=_state_store(tmp_path),
    )
    with pytest.raises(MemoryError, match="inventory|query|read-only"):
        chroma_adapter.query(namespace="collections")
    with pytest.raises(MemoryError, match="snapshot|read-only"):
        chroma_adapter.backup(expected_revision=chroma_adapter.current_revision())


def test_sqlite_update_is_backed_up_transactional_and_restorable(tmp_path: Path) -> None:
    source = tmp_path / "memory.sqlite3"
    _database(source)
    adapter = _adapter(source, tmp_path)
    revision = adapter.current_revision()
    plan = adapter.plan_mutation(
        MutationOperation(
            kind=MutationKind.UPDATE_FIELD,
            record_id="memories:i:1",
            field="tag",
            value="blue secret",
        ),
        expected_revision=revision,
    )
    assert "blue secret" not in plan.model_dump_json()

    receipt = adapter.apply(plan)

    assert adapter.get("memories:i:1").metadata["tag"] == "blue secret"
    snapshot = adapter.snapshot(receipt.snapshot_id)
    adapter.restore(
        snapshot.snapshot_id,
        expected_snapshot_digest=snapshot.digest,
        expected_revision=receipt.after_revision,
    )
    assert adapter.get("memories:i:1").metadata["tag"] == "red"


def test_sqlite_failed_apply_preserves_later_external_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "memory.sqlite3"
    _database(source)
    store = _state_store(tmp_path)
    adapter = SQLiteMemoryAdapter(source, backups_dir=tmp_path / "backups", state_store=store)
    plan = adapter.plan_mutation(
        MutationOperation(
            kind=MutationKind.UPDATE_FIELD, record_id="memories:i:1", field="tag", value="blue"
        ),
        expected_revision=adapter.current_revision(),
    )
    original_phase = store.update_memory_plan_phase

    def external_write(plan_id: str, phase: str, *, snapshot_id: str | None = None) -> None:
        original_phase(plan_id, phase, snapshot_id=snapshot_id)
        if phase == "committed":
            with sqlite3.connect(source) as writer:
                writer.execute("UPDATE memories SET tag='external' WHERE id=1")
            raise MemoryError("synthetic post-commit verification failure")

    monkeypatch.setattr(store, "update_memory_plan_phase", external_write)
    with pytest.raises(MemoryError):
        adapter.apply(plan)

    with sqlite3.connect(source) as connection:
        assert connection.execute("SELECT tag FROM memories WHERE id=1").fetchone() == ("external",)
    reopened = _state_store(tmp_path, owner_alive=False)
    SQLiteMemoryAdapter(source, backups_dir=tmp_path / "backups", state_store=reopened)
    with sqlite3.connect(reopened.database_path) as connection:
        assert connection.execute(
            "SELECT status FROM memory_mutation_plans WHERE plan_id=?", (plan.plan_id,)
        ).fetchone() == ("interrupted",)
        assert connection.execute(
            "SELECT COUNT(*) FROM memory_receipts WHERE plan_id=?", (plan.plan_id,)
        ).fetchone() == (0,)


def test_sqlite_receipt_outage_reconciles_committed_apply_without_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "memory.sqlite3"
    _database(source)
    store = _state_store(tmp_path)
    adapter = SQLiteMemoryAdapter(source, backups_dir=tmp_path / "backups", state_store=store)
    plan = adapter.plan_mutation(
        MutationOperation(
            kind=MutationKind.UPDATE_FIELD, record_id="memories:i:1", field="tag", value="blue"
        ),
        expected_revision=adapter.current_revision(),
    )

    def lose_receipt(_receipt: object) -> None:
        raise PermissionError("C:/private-state/receipt.sqlite3")

    def lose_journal(_plan_id: str, *, interrupted: bool) -> None:
        raise PermissionError("C:/private-state/journal.sqlite3")

    monkeypatch.setattr(store, "finish_memory_plan", lose_receipt)
    monkeypatch.setattr(store, "fail_memory_plan", lose_journal)
    with pytest.raises(MemoryError, match="journal|reconciliation|uncertain") as failure:
        adapter.apply(plan)
    assert "private-state" not in str(failure.value)
    assert failure.value.__cause__ is None
    with sqlite3.connect(source) as connection:
        assert connection.execute("SELECT tag FROM memories WHERE id=1").fetchone() == ("blue",)
    reopened = _state_store(tmp_path, owner_alive=False)
    SQLiteMemoryAdapter(source, backups_dir=tmp_path / "backups", state_store=reopened)
    with sqlite3.connect(reopened.database_path) as connection:
        assert connection.execute(
            "SELECT status FROM memory_mutation_plans WHERE plan_id=?", (plan.plan_id,)
        ).fetchone() == ("succeeded",)
        assert connection.execute(
            "SELECT COUNT(*) FROM memory_receipts WHERE plan_id=?", (plan.plan_id,)
        ).fetchone() == (1,)


def test_sqlite_apply_rechecks_named_identity_before_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "memory.sqlite3"
    _database(source)
    other = tmp_path / "other.sqlite3"
    _database(other)
    other_stat = other.stat()
    adapter = _adapter(source, tmp_path)
    plan = adapter.plan_mutation(
        MutationOperation(
            kind=MutationKind.UPDATE_FIELD, record_id="memories:i:1", field="tag", value="blue"
        ),
        expected_revision=adapter.current_revision(),
    )
    original_update, original_lstat = adapter._execute_update, os.lstat
    updated = False

    def update_then_observe_swap(
        connection: sqlite3.Connection,
        operation: MutationOperation,
        *,
        expected_old_hash: str | None,
        expected_record_hash: str | None = None,
    ) -> tuple[object, object, str, str]:
        nonlocal updated
        result = original_update(
            connection,
            operation,
            expected_old_hash=expected_old_hash,
            expected_record_hash=expected_record_hash,
        )
        updated = True
        return result

    def changed_name(path: object, **options: object) -> os.stat_result:
        if path == source and updated:
            return other_stat
        return original_lstat(path, **options)  # type: ignore[arg-type]

    monkeypatch.setattr(adapter, "_execute_update", update_then_observe_swap)
    monkeypatch.setattr(os, "lstat", changed_name)
    with pytest.raises(MemoryError, match="identity|changed|uncertain"):
        adapter.apply(plan)
    with sqlite3.connect(source) as connection:
        assert connection.execute("SELECT tag FROM memories WHERE id=1").fetchone() == ("red",)


def test_sqlite_apply_cannot_receipt_a_later_writer_as_its_verified_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "memory.sqlite3"
    _database(source)
    store = _state_store(tmp_path)
    adapter = SQLiteMemoryAdapter(source, backups_dir=tmp_path / "backups", state_store=store)
    plan = adapter.plan_mutation(
        MutationOperation(
            kind=MutationKind.UPDATE_FIELD, record_id="memories:i:1", field="tag", value="blue"
        ),
        expected_revision=adapter.current_revision(),
    )
    original_phase, original_revision = store.update_memory_plan_phase, adapter._revision_parts
    verifying = False

    def verification_phase(plan_id: str, phase: str, *, snapshot_id: str | None = None) -> None:
        nonlocal verifying
        original_phase(plan_id, phase, snapshot_id=snapshot_id)
        if phase == "post_verifying":
            verifying = True

    def race_revision() -> tuple[str, object]:
        nonlocal verifying
        if verifying:
            verifying = False
            with sqlite3.connect(source, timeout=0.01) as writer:
                writer.execute("UPDATE memories SET tag='external' WHERE id=1")
        return original_revision()

    monkeypatch.setattr(store, "update_memory_plan_phase", verification_phase)
    monkeypatch.setattr(adapter, "_revision_parts", race_revision)
    with pytest.raises(MemoryError, match="uncertain|changed|writer|transaction"):
        adapter.apply(plan)
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM memory_receipts WHERE plan_id=?", (plan.plan_id,)
        ).fetchone() == (0,)


def test_sqlite_restore_refuses_commit_after_source_changed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "memory.sqlite3"
    _database(source)
    store = _state_store(tmp_path)
    adapter = SQLiteMemoryAdapter(source, backups_dir=tmp_path / "backups", state_store=store)
    snapshot = adapter.backup(expected_revision=adapter.current_revision())
    receipt = adapter.apply(
        adapter.plan_mutation(
            MutationOperation(
                kind=MutationKind.UPDATE_FIELD, record_id="memories:i:1", field="tag", value="blue"
            ),
            expected_revision=adapter.current_revision(),
        )
    )
    original_phase = store.update_memory_restore_phase

    def external_write(
        restore_plan_id: str, phase: str, *, rollback_snapshot_id: str | None = None
    ) -> None:
        original_phase(restore_plan_id, phase, rollback_snapshot_id=rollback_snapshot_id)
        if phase == "restore_issuing":
            with sqlite3.connect(source) as writer:
                writer.execute("UPDATE memories SET tag='external' WHERE id=1")

    monkeypatch.setattr(store, "update_memory_restore_phase", external_write)
    with pytest.raises(MemoryError, match="changed|revision|uncertain"):
        adapter.restore(
            snapshot.snapshot_id,
            expected_snapshot_digest=snapshot.digest,
            expected_revision=receipt.after_revision,
        )

    with sqlite3.connect(source) as connection:
        assert connection.execute("SELECT tag FROM memories WHERE id=1").fetchone() == ("external",)


@pytest.mark.parametrize("wal", [False, True])
def test_sqlite_restore_obeys_external_writer_transaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, wal: bool
) -> None:
    source = tmp_path / "memory.sqlite3"
    _database(source)
    store = _state_store(tmp_path)
    adapter = SQLiteMemoryAdapter(
        source, backups_dir=tmp_path / "backups", state_store=store, busy_timeout_ms=10
    )
    if wal:
        with sqlite3.connect(source) as configure:
            configure.execute("PRAGMA journal_mode=WAL")
    snapshot = adapter.backup(expected_revision=adapter.current_revision())
    receipt = adapter.apply(
        adapter.plan_mutation(
            MutationOperation(
                kind=MutationKind.UPDATE_FIELD, record_id="memories:i:1", field="tag", value="blue"
            ),
            expected_revision=adapter.current_revision(),
        )
    )
    original_phase = store.update_memory_restore_phase
    writer = sqlite3.connect(source, isolation_level=None, timeout=0.01)

    def begin_writer(
        restore_plan_id: str, phase: str, *, rollback_snapshot_id: str | None = None
    ) -> None:
        original_phase(restore_plan_id, phase, rollback_snapshot_id=rollback_snapshot_id)
        if phase == "restore_issuing":
            writer.execute("BEGIN IMMEDIATE")
            writer.execute("UPDATE memories SET tag='external' WHERE id=1")

    monkeypatch.setattr(store, "update_memory_restore_phase", begin_writer)
    try:
        with pytest.raises(MemoryError, match="writer|transaction|uncertain|restore"):
            adapter.restore(
                snapshot.snapshot_id,
                expected_snapshot_digest=snapshot.digest,
                expected_revision=receipt.after_revision,
            )
        writer.commit()
    finally:
        writer.close()
    with sqlite3.connect(source) as connection:
        assert connection.execute("SELECT tag FROM memories WHERE id=1").fetchone() == ("external",)


def test_sqlite_restore_keeps_source_identity_and_autoincrement_state(tmp_path: Path) -> None:
    source = tmp_path / "memory.sqlite3"
    with sqlite3.connect(source) as connection:
        connection.executescript(
            "CREATE TABLE memories(id INTEGER PRIMARY KEY AUTOINCREMENT, content TEXT);"
            "INSERT INTO memories(content) VALUES('original');"
            "PRAGMA user_version=7;"
        )
    adapter = _adapter(source, tmp_path)
    snapshot = adapter.backup(expected_revision=adapter.current_revision())
    original_inode = source.stat().st_ino
    with sqlite3.connect(source) as connection:
        connection.execute("INSERT INTO memories(content) VALUES('later')")
        connection.execute("PRAGMA user_version=8")
    adapter.restore(
        snapshot.snapshot_id,
        expected_snapshot_digest=snapshot.digest,
        expected_revision=adapter.current_revision(),
    )
    assert source.stat().st_ino == original_inode
    with sqlite3.connect(source) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (7,)
        connection.execute("INSERT INTO memories(content) VALUES('after restore')")
        assert connection.execute("SELECT id,content FROM memories ORDER BY id").fetchall() == [
            (1, "original"),
            (2, "after restore"),
        ]


def test_sqlite_restore_refuses_changed_schema_without_losing_new_table(tmp_path: Path) -> None:
    source = tmp_path / "memory.sqlite3"
    _database(source)
    adapter = _adapter(source, tmp_path)
    snapshot = adapter.backup(expected_revision=adapter.current_revision())
    with sqlite3.connect(source) as connection:
        connection.execute("CREATE TABLE later(id INTEGER PRIMARY KEY, content TEXT)")
        connection.execute("INSERT INTO later VALUES(1,'keep')")
    with pytest.raises(MemoryError, match="schema"):
        adapter.restore(
            snapshot.snapshot_id,
            expected_snapshot_digest=snapshot.digest,
            expected_revision=adapter.current_revision(),
        )
    with sqlite3.connect(source) as connection:
        assert connection.execute("SELECT content FROM later").fetchall() == [("keep",)]


def test_sqlite_triggered_database_restore_is_explicitly_unavailable(tmp_path: Path) -> None:
    source = tmp_path / "memory.sqlite3"
    _database(source)
    with sqlite3.connect(source) as connection:
        connection.execute("CREATE TRIGGER on_insert AFTER INSERT ON memories BEGIN SELECT 1; END")
    probe = SQLiteMemoryAdapter.probe(source)
    assert probe.capabilities.editable is True
    assert probe.capabilities.restore is False
    adapter = _adapter(source, tmp_path)
    snapshot = adapter.backup(expected_revision=adapter.current_revision())
    with pytest.raises(MemoryError, match="trigger"):
        adapter.restore(
            snapshot.snapshot_id,
            expected_snapshot_digest=snapshot.digest,
            expected_revision=adapter.current_revision(),
        )


def test_sqlite_restore_revalidates_snapshot_at_write_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "memory.sqlite3"
    _database(source)
    store = _state_store(tmp_path)
    adapter = SQLiteMemoryAdapter(source, backups_dir=tmp_path / "backups", state_store=store)
    snapshot = adapter.backup(expected_revision=adapter.current_revision())
    receipt = adapter.apply(
        adapter.plan_mutation(
            MutationOperation(
                kind=MutationKind.UPDATE_FIELD, record_id="memories:i:1", field="tag", value="blue"
            ),
            expected_revision=adapter.current_revision(),
        )
    )
    original_phase = store.update_memory_restore_phase

    def tamper_snapshot(
        restore_plan_id: str, phase: str, *, rollback_snapshot_id: str | None = None
    ) -> None:
        original_phase(restore_plan_id, phase, rollback_snapshot_id=rollback_snapshot_id)
        if phase == "restore_issuing":
            with sqlite3.connect(snapshot.backup_path) as writer:
                writer.execute("UPDATE memories SET tag='tampered' WHERE id=1")

    monkeypatch.setattr(store, "update_memory_restore_phase", tamper_snapshot)
    with pytest.raises(MemoryError, match="snapshot|restore"):
        adapter.restore(
            snapshot.snapshot_id,
            expected_snapshot_digest=snapshot.digest,
            expected_revision=receipt.after_revision,
        )
    with sqlite3.connect(source) as connection:
        assert connection.execute("SELECT tag FROM memories WHERE id=1").fetchone() == ("blue",)


def test_sqlite_restore_reconciliation_requires_intact_snapshot_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "memory.sqlite3"
    _database(source)
    store = _state_store(tmp_path)
    adapter = SQLiteMemoryAdapter(source, backups_dir=tmp_path / "backups", state_store=store)
    snapshot = adapter.backup(expected_revision=adapter.current_revision())
    receipt = adapter.apply(
        adapter.plan_mutation(
            MutationOperation(
                kind=MutationKind.UPDATE_FIELD, record_id="memories:i:1", field="tag", value="blue"
            ),
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
    SQLiteMemoryAdapter(source, backups_dir=tmp_path / "backups", state_store=reopened)
    with sqlite3.connect(reopened.database_path) as connection:
        assert connection.execute("SELECT status FROM memory_restore_plans").fetchall() == [
            ("interrupted",)
        ]
        assert connection.execute(
            "SELECT COUNT(*) FROM memory_receipts WHERE restore_plan_id IS NOT NULL"
        ).fetchone() == (0,)


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode preservation")
def test_sqlite_restore_preserves_selected_source_mode(tmp_path: Path) -> None:
    source = tmp_path / "memory.sqlite3"
    _database(source)
    source.chmod(0o640)
    adapter = _adapter(source, tmp_path)
    snapshot = adapter.backup(expected_revision=adapter.current_revision())

    adapter.restore(
        snapshot.snapshot_id,
        expected_snapshot_digest=snapshot.digest,
        expected_revision=adapter.current_revision(),
    )

    assert source.stat().st_mode & 0o777 == 0o640


@pytest.mark.skipif(os.name != "nt", reason="Windows DACL control semantics")
def test_sqlite_restore_preserves_exact_pai_descriptor(tmp_path: Path) -> None:
    source = tmp_path / "memory.sqlite3"
    _database(source)
    expected_sddl = _set_windows_pai(source)
    adapter = _adapter(source, tmp_path)
    snapshot = adapter.backup(expected_revision=adapter.current_revision())

    adapter.restore(
        snapshot.snapshot_id,
        expected_snapshot_digest=snapshot.digest,
        expected_revision=adapter.current_revision(),
    )

    assert capture_file_security(source).windows_sddl == expected_sddl


def test_sqlite_restore_rejects_a_false_success_without_replacing_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "memory.sqlite3"
    _database(source)
    adapter = _adapter(source, tmp_path)
    snapshot = adapter.backup(expected_revision=adapter.current_revision())
    plan = adapter.plan_mutation(
        MutationOperation(
            kind=MutationKind.UPDATE_FIELD,
            record_id="memories:i:1",
            field="tag",
            value="blue",
        ),
        expected_revision=adapter.current_revision(),
    )
    receipt = adapter.apply(plan)
    original_restore = adapter._restore_from
    calls = 0

    def false_success_then_restore(snapshot_path: Path, **binding: object) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            return
        original_restore(snapshot_path, **binding)  # type: ignore[arg-type]

    monkeypatch.setattr(adapter, "_restore_from", false_success_then_restore)

    with pytest.raises(MemoryError, match="logical|restore"):
        adapter.restore(
            snapshot.snapshot_id,
            expected_snapshot_digest=snapshot.digest,
            expected_revision=receipt.after_revision,
        )

    assert calls == 1
    assert adapter.get("memories:i:1").metadata["tag"] == "blue"


def test_sqlite_rejects_corruption_wal_and_read_only_table_mutation(tmp_path: Path) -> None:
    corrupt = tmp_path / "bad.sqlite3"
    corrupt.write_bytes(b"not a sqlite database")
    with pytest.raises(MemoryError):
        _adapter(corrupt, tmp_path).healthcheck()

    source = tmp_path / "memory.sqlite3"
    _database(source)
    adapter = _adapter(source, tmp_path)
    with pytest.raises(MemoryError, match="read-only|editable"):
        adapter.plan_mutation(
            MutationOperation(
                kind=MutationKind.UPDATE_FIELD,
                record_id="composite:i:1",
                field="value",
                value="x",
            ),
            expected_revision=adapter.current_revision(),
        )


def test_sqlite_rejects_multirow_trigger_and_rolls_back(tmp_path: Path) -> None:
    source = tmp_path / "memory.sqlite3"
    with sqlite3.connect(source) as connection:
        connection.executescript(
            """
            CREATE TABLE memories (id INTEGER PRIMARY KEY, content TEXT, tag TEXT);
            INSERT INTO memories VALUES (1, 'one', 'red'), (2, 'two', 'red');
            CREATE TRIGGER cascade_tag AFTER UPDATE OF tag ON memories
            WHEN NEW.id = 1
            BEGIN
              UPDATE memories SET tag = NEW.tag WHERE id = 2;
            END;
            """
        )
    adapter = _adapter(source, tmp_path)

    with pytest.raises(MemoryError, match="more than one row"):
        adapter.plan_mutation(
            MutationOperation(
                kind=MutationKind.UPDATE_FIELD,
                record_id="memories:i:1",
                field="tag",
                value="blue",
            ),
            expected_revision=adapter.current_revision(),
        )

    assert adapter.get("memories:i:1").metadata["tag"] == "red"
    assert adapter.get("memories:i:2").metadata["tag"] == "red"


def test_sqlite_apply_rejects_active_transaction_as_typed_failure(tmp_path: Path) -> None:
    source = tmp_path / "memory.sqlite3"
    _database(source)
    adapter = SQLiteMemoryAdapter(
        source,
        backups_dir=tmp_path / "backups",
        state_store=_state_store(tmp_path),
        busy_timeout_ms=10,
    )
    plan = adapter.plan_mutation(
        MutationOperation(
            kind=MutationKind.UPDATE_FIELD,
            record_id="memories:i:1",
            field="tag",
            value="blue",
        ),
        expected_revision=adapter.current_revision(),
    )
    with sqlite3.connect(source, isolation_level=None) as writer:
        writer.execute("BEGIN IMMEDIATE")
        with pytest.raises(MemoryError, match="writer|locked|transaction"):
            adapter.apply(plan)
        writer.rollback()

    assert adapter.get("memories:i:1").metadata["tag"] == "red"


def test_sqlite_rejects_redirected_wal_sidecar(tmp_path: Path) -> None:
    source = tmp_path / "memory.sqlite3"
    _database(source)
    attacker_file = tmp_path / "attacker-wal"
    attacker_file.write_bytes(b"active")
    wal = Path(f"{source}-wal")
    try:
        wal.symlink_to(attacker_file)
    except OSError:
        pytest.skip("symlinks unavailable")

    with pytest.raises(MemoryError, match="link|reparse|sidecar"):
        _adapter(source, tmp_path).plan_mutation(
            MutationOperation(
                kind=MutationKind.UPDATE_FIELD,
                record_id="memories:i:1",
                field="tag",
                value="blue",
            ),
            expected_revision=_adapter(source, tmp_path).current_revision(),
        )


def test_direct_sqlite_adapter_enforces_chroma_read_only(tmp_path: Path) -> None:
    source = tmp_path / "chroma.sqlite3"
    with sqlite3.connect(source) as connection:
        connection.executescript(
            "CREATE TABLE collections(id TEXT PRIMARY KEY);"
            "CREATE TABLE embeddings(id TEXT PRIMARY KEY, document TEXT);"
            "INSERT INTO embeddings VALUES ('one', 'memory');"
        )
    adapter = SQLiteMemoryAdapter(
        source,
        backups_dir=tmp_path / "backups",
        state_store=_state_store(tmp_path),
    )

    with pytest.raises(MemoryError, match="Chroma|read-only"):
        adapter.open(read_only=False)
    with pytest.raises(MemoryError, match="Chroma|read-only"):
        adapter.plan_mutation(
            MutationOperation(
                kind=MutationKind.UPDATE_CONTENT,
                record_id="embeddings:one",
                value="changed",
            ),
            expected_revision=adapter.current_revision(),
        )


def test_sqlite_typed_primary_key_tokens_support_direct_lookup_past_page_500(
    tmp_path: Path,
) -> None:
    source = tmp_path / "typed.sqlite3"
    with sqlite3.connect(source) as connection:
        connection.executescript(
            "CREATE TABLE ints(id INTEGER PRIMARY KEY, content TEXT);"
            "CREATE TABLE texts(id TEXT PRIMARY KEY, content TEXT);"
            "CREATE TABLE blobs(id BLOB PRIMARY KEY, content TEXT);"
            "CREATE TABLE nulls(id TEXT PRIMARY KEY, content TEXT);"
            "INSERT INTO texts VALUES ('colon:value', 'text row');"
            "INSERT INTO blobs VALUES (x'0102', 'blob row');"
            "INSERT INTO nulls VALUES (NULL, 'null row');"
        )
        connection.executemany(
            "INSERT INTO ints(id, content) VALUES (?, ?)",
            ((index, f"row-{index}") for index in range(1, 602)),
        )
    adapter = SQLiteMemoryAdapter(
        source,
        backups_dir=tmp_path / "backups",
        state_store=_state_store(tmp_path),
    )
    int_page = adapter.query(namespace="ints", cursor="600", limit=1)
    text_record = adapter.query(namespace="texts").records[0]
    null_record = adapter.query(namespace="nulls").records[0]
    inventory = {item.name: item for item in adapter.inventory()}

    assert adapter.get(int_page.records[0].record_id).content == "row-601"
    assert adapter.get(text_record.record_id).content == "text row"
    assert adapter.get("blobs:b:AQI").content == "blob row"
    assert null_record.record_id == "nulls:n:"
    assert adapter.get(null_record.record_id).content == "null row"
    assert ":i:" in int_page.records[0].record_id
    assert ":s:" in text_record.record_id
    assert inventory["blobs"].editable is False
    with pytest.raises(MemoryError, match="token"):
        adapter.get(text_record.record_id + "$")


def test_sqlite_revalidates_source_after_snapshot_before_update(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "memory.sqlite3"
    _database(source)
    adapter = SQLiteMemoryAdapter(
        source,
        backups_dir=tmp_path / "backups",
        state_store=_state_store(tmp_path),
    )
    plan = adapter.plan_mutation(
        MutationOperation(
            kind=MutationKind.UPDATE_FIELD,
            record_id="memories:i:1",
            field="tag",
            value="blue",
        ),
        expected_revision=adapter.current_revision(),
    )
    replacement = tmp_path / "replacement.sqlite3"
    _database(replacement)
    original_backup = adapter.backup

    def swap_after_backup(*, expected_revision: str):
        snapshot = original_backup(expected_revision=expected_revision)
        source.write_bytes(replacement.read_bytes())
        return snapshot

    monkeypatch.setattr(adapter, "backup", swap_after_backup)
    with pytest.raises(MemoryError, match="identity|revision|changed"):
        adapter.apply(plan)
    assert adapter.get("memories:i:1").metadata["tag"] == "red"


def test_sqlite_post_commit_failure_retains_committed_state_and_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "memory.sqlite3"
    _database(source)
    store = _state_store(tmp_path)
    adapter = SQLiteMemoryAdapter(
        source,
        backups_dir=tmp_path / "backups",
        state_store=store,
    )
    plan = adapter.plan_mutation(
        MutationOperation(
            kind=MutationKind.UPDATE_FIELD,
            record_id="memories:i:1",
            field="tag",
            value="blue",
        ),
        expected_revision=adapter.current_revision(),
    )
    original_check = adapter._check_database
    failed = False

    def fail_first_post_commit(path: Path) -> None:
        nonlocal failed
        if path == source and not failed:
            with sqlite3.connect(source) as connection:
                value = connection.execute("SELECT tag FROM memories WHERE id=1").fetchone()[0]
            if value == "blue":
                failed = True
                raise MemoryError("synthetic post-commit verification failure")
        original_check(path)

    monkeypatch.setattr(adapter, "_check_database", fail_first_post_commit)
    with pytest.raises(MemoryError, match="post-commit|restored"):
        adapter.apply(plan)

    assert adapter.get("memories:i:1").metadata["tag"] == "blue"


def test_sqlite_committed_phase_persistence_failure_retains_committed_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "memory.sqlite3"
    _database(source)
    store = _state_store(tmp_path)
    adapter = SQLiteMemoryAdapter(source, backups_dir=tmp_path / "backups", state_store=store)
    plan = adapter.plan_mutation(
        MutationOperation(
            kind=MutationKind.UPDATE_FIELD,
            record_id="memories:i:1",
            field="tag",
            value="blue",
        ),
        expected_revision=adapter.current_revision(),
    )
    original_phase = store.update_memory_plan_phase

    def fail_committed(plan_id: str, phase: str, *, snapshot_id: str | None = None) -> None:
        if phase == "committed":
            raise PermissionError("C:/sensitive/journal.sqlite3")
        original_phase(plan_id, phase, snapshot_id=snapshot_id)

    monkeypatch.setattr(store, "update_memory_plan_phase", fail_committed)

    with pytest.raises(MemoryError, match="post-commit|restored") as failure:
        adapter.apply(plan)

    assert "sensitive" not in str(failure.value)
    assert adapter.get("memories:i:1").metadata["tag"] == "blue"


def test_sqlite_pathological_view_is_rejected_before_execution(tmp_path: Path) -> None:
    source = tmp_path / "slow.sqlite3"
    with sqlite3.connect(source) as connection:
        connection.execute(
            "CREATE VIEW slow AS WITH RECURSIVE count(value) AS ("
            "VALUES(1) UNION ALL SELECT value + 1 FROM count WHERE value < 100000000) "
            "SELECT value AS id, printf('%d', value) AS content FROM count"
        )
    adapter = SQLiteMemoryAdapter(
        source,
        backups_dir=tmp_path / "backups",
        state_store=_state_store(tmp_path),
        operation_timeout_seconds=0.001,
    )

    with pytest.raises(MemoryError, match="inventory-only"):
        adapter.query(namespace="slow")


def test_sqlite_lazy_reconciliation_finalizes_crash_after_commit(tmp_path: Path) -> None:
    source = tmp_path / "memory.sqlite3"
    _database(source)
    store = _state_store(tmp_path)
    adapter = SQLiteMemoryAdapter(source, backups_dir=tmp_path / "backups", state_store=store)
    plan = adapter.plan_mutation(
        MutationOperation(
            kind=MutationKind.UPDATE_FIELD,
            record_id="memories:i:1",
            field="tag",
            value="blue",
        ),
        expected_revision=adapter.current_revision(),
    )
    store.claim_memory_plan(plan.plan_id, expected_digest=plan.digest)
    snapshot = adapter.backup(expected_revision=adapter.current_revision())
    store.update_memory_plan_phase(
        plan.plan_id, "snapshot_verified", snapshot_id=snapshot.snapshot_id
    )
    store.update_memory_plan_phase(plan.plan_id, "write_issuing")
    with sqlite3.connect(source) as connection:
        connection.execute("UPDATE memories SET tag = 'blue' WHERE id = 1")
    store.update_memory_plan_phase(plan.plan_id, "committed")

    reopened_store = _state_store(tmp_path, owner_alive=False)
    SQLiteMemoryAdapter(
        source,
        backups_dir=tmp_path / "backups",
        state_store=reopened_store,
    )

    with sqlite3.connect(reopened_store.database_path) as connection:
        assert connection.execute(
            "SELECT status, phase FROM memory_mutation_plans WHERE plan_id = ?",
            (plan.plan_id,),
        ).fetchone() == ("succeeded", "recovered_completed")


def test_clean_wal_reader_does_not_look_like_an_external_writer(tmp_path: Path) -> None:
    source = tmp_path / "memory.sqlite3"
    _database(source)
    reader = sqlite3.connect(source)
    assert reader.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower() == "wal"
    reader.execute("SELECT * FROM memories").fetchone()
    try:
        adapter = _adapter(source, tmp_path)
        plan = adapter.plan_mutation(
            MutationOperation(
                kind=MutationKind.UPDATE_FIELD,
                record_id="memories:i:1",
                field="tag",
                value="blue",
            ),
            expected_revision=adapter.current_revision(),
        )
        adapter.apply(plan)
    finally:
        reader.close()

    assert adapter.get("memories:i:1").metadata["tag"] == "blue"


def test_empty_wal_identity_is_not_revision_authority_without_a_reader(
    tmp_path: Path,
) -> None:
    source = tmp_path / "memory.sqlite3"
    _database(source)
    adapter = _adapter(source, tmp_path)
    wal = Path(f"{source}-wal")
    wal.write_bytes(b"")
    first = adapter.current_revision()
    wal.unlink(missing_ok=True)
    wal.write_bytes(b"")

    second = adapter.current_revision()
    plan = adapter.plan_mutation(
        MutationOperation(
            kind=MutationKind.UPDATE_FIELD,
            record_id="memories:i:1",
            field="tag",
            value="blue",
        ),
        expected_revision=second,
    )
    adapter.apply(plan)

    assert first == second
    assert adapter.get("memories:i:1").metadata["tag"] == "blue"


def test_sqlite_busy_wait_respects_tiny_operation_deadline(tmp_path: Path) -> None:
    source = tmp_path / "memory.sqlite3"
    _database(source)
    adapter = SQLiteMemoryAdapter(
        source,
        backups_dir=tmp_path / "backups",
        state_store=_state_store(tmp_path),
        busy_timeout_ms=2_000,
        operation_timeout_seconds=0.01,
    )
    blocker = sqlite3.connect(source, isolation_level=None)
    blocker.execute("BEGIN IMMEDIATE")
    started = time.monotonic()
    try:
        with pytest.raises(MemoryError, match="writer|lock|changed|access"):
            adapter.plan_mutation(
                MutationOperation(
                    kind=MutationKind.UPDATE_FIELD,
                    record_id="memories:i:1",
                    field="tag",
                    value="blue",
                ),
                expected_revision=adapter.current_revision(),
            )
    finally:
        elapsed = time.monotonic() - started
        blocker.rollback()
        blocker.close()

    assert elapsed < 0.25


def test_sqlite_query_rejects_oversized_cell_without_echoing_data(tmp_path: Path) -> None:
    source = tmp_path / "oversized.sqlite3"
    secret = "oversized-secret-marker-" + "x" * (1024 * 1024)
    with sqlite3.connect(source) as connection:
        connection.execute("CREATE TABLE memories(id INTEGER PRIMARY KEY, content TEXT)")
        connection.execute("INSERT INTO memories(content) VALUES (?)", (secret,))
    adapter = SQLiteMemoryAdapter(
        source,
        backups_dir=tmp_path / "backups",
        state_store=_state_store(tmp_path),
        max_bytes=2 * 1024 * 1024,
    )

    with pytest.raises(MemoryError, match="bound|large|cell") as failure:
        adapter.query(namespace="memories")

    assert "oversized-secret-marker" not in str(failure.value)


def test_sqlite_apply_rejects_expiry_at_final_commit_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "memory.sqlite3"
    _database(source)
    adapter = _adapter(source, tmp_path)
    before = source.read_bytes()
    clock = [datetime.now(UTC)]
    monkeypatch.setattr(base_module, "utc_now", lambda: clock[0])
    monkeypatch.setattr(sqlite_store_module, "utc_now", lambda: clock[0])
    plan = adapter.plan_mutation(
        MutationOperation(
            kind=MutationKind.UPDATE_FIELD, record_id="memories:i:1", field="tag", value="blue"
        ),
        expected_revision=adapter.current_revision(),
    )
    original_security = sqlite_store_module.capture_file_security
    calls = 0

    def expire_at_commit_validation(path: Path) -> object:
        nonlocal calls
        result = original_security(path)
        calls += 1
        if calls == 2:
            clock[0] = plan.expires_at
        return result

    monkeypatch.setattr(sqlite_store_module, "capture_file_security", expire_at_commit_validation)
    with pytest.raises(MemoryError, match="expired"):
        adapter.apply(plan)
    assert source.read_bytes() == before
    assert adapter.get("memories:i:1").metadata["tag"] == "red"


@pytest.mark.parametrize("reviewed_seconds", [None, 10, 60])
def test_sqlite_restore_checks_earliest_deadline_at_final_commit_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reviewed_seconds: int | None
) -> None:
    source = tmp_path / "memory.sqlite3"
    _database(source)
    adapter = _adapter(source, tmp_path)
    snapshot = adapter.backup(expected_revision=adapter.current_revision())
    adapter.apply(
        adapter.plan_mutation(
            MutationOperation(
                kind=MutationKind.UPDATE_FIELD, record_id="memories:i:1", field="tag", value="blue"
            ),
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
    monkeypatch.setattr(sqlite_store_module, "utc_now", lambda: clock[0])
    original_verify = adapter._verified_snapshot_model
    calls = 0

    def expire_after_final_snapshot_verification(snapshot: object) -> Path:
        nonlocal calls
        result = original_verify(snapshot)  # type: ignore[arg-type]
        calls += 1
        if calls == 3:
            clock[0] = boundary
        return result

    monkeypatch.setattr(
        adapter, "_verified_snapshot_model", expire_after_final_snapshot_verification
    )
    options = {"reviewed_expires_at": reviewed} if reviewed is not None else {}
    with pytest.raises(MemoryError, match="expired"):
        adapter.restore(
            snapshot.snapshot_id,
            expected_snapshot_digest=snapshot.digest,
            expected_revision=adapter.current_revision(),
            **options,
        )
    assert source.read_bytes() == before
    assert adapter.get("memories:i:1").metadata["tag"] == "blue"


@pytest.mark.parametrize("deadline", [datetime(2026, 10, 2), float("nan"), "invalid"])
def test_sqlite_restore_rejects_nonaware_or_invalid_reviewed_deadline(
    tmp_path: Path, deadline: object
) -> None:
    source = tmp_path / "memory.sqlite3"
    _database(source)
    before = source.read_bytes()
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
