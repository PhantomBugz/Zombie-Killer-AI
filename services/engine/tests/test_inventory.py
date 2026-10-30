from __future__ import annotations

import os
import struct
from pathlib import Path

import pytest

from zombie_killer_engine.memory.base import MemoryError, VaultFormat
from zombie_killer_engine.memory.inventory import FaissInventoryAdapter


def _flat_header(magic: bytes = b"IxF2") -> bytes:
    metric = 0 if magic == b"IxFI" else 1
    return magic + struct.pack("<iqQQ?iQ", 2, 0, 1 << 20, 1 << 20, True, metric, 0)


@pytest.mark.parametrize("magic", [b"IxF2", b"IxFI", b"IxFl"])
def test_flat_index_inventory_recognizes_header_without_loading_vectors(
    tmp_path: Path, magic: bytes
) -> None:
    path = tmp_path / "index.faiss"
    path.write_bytes(_flat_header(magic))
    result = FaissInventoryAdapter.probe(path)
    assert result.format is VaultFormat.FAISS
    assert result.recognized
    assert result.capabilities.readable
    assert not result.capabilities.queryable
    assert not result.capabilities.editable
    assert not result.capabilities.snapshot
    assert not result.capabilities.restore
    assert "header" in (result.reason or "")


@pytest.mark.parametrize(
    "content",
    [b"IxF2", b"not a FAISS index", b"IxF2" + b"\xff" * 41, b'{"memory": []}'],
)
def test_inventory_does_not_infer_format_from_file_extension(
    tmp_path: Path, content: bytes
) -> None:
    path = tmp_path / "index.faiss"
    path.write_bytes(content)
    result = FaissInventoryAdapter.probe(path)
    assert not result.recognized
    assert result.format is VaultFormat.UNSUPPORTED


def test_inventory_source_revision_changes_when_the_index_changes(tmp_path: Path) -> None:
    path = tmp_path / "index.faiss"
    path.write_bytes(_flat_header())
    adapter = FaissInventoryAdapter(path).open(read_only=True)
    before = adapter.current_revision()
    source = adapter.source
    assert source.format is VaultFormat.FAISS
    assert source.revision == before
    path.write_bytes(_flat_header() + b"changed data")
    assert adapter.current_revision() != before
    assert path.read_bytes().endswith(b"changed data")


def test_inventory_cannot_be_opened_for_mutation(tmp_path: Path) -> None:
    path = tmp_path / "index.faiss"
    original = _flat_header()
    path.write_bytes(original)
    adapter = FaissInventoryAdapter(path)
    with pytest.raises(MemoryError, match="inventory-only"):
        adapter.open(read_only=False)
    assert path.read_bytes() == original


def test_inventory_reads_only_a_bounded_header_of_a_large_index(tmp_path: Path) -> None:
    path = tmp_path / "large.index"
    with path.open("wb") as stream:
        stream.write(_flat_header())
        stream.truncate(32 * 1024 * 1024)
    adapter = FaissInventoryAdapter(path).open(read_only=True)
    assert adapter.source.format is VaultFormat.FAISS
    assert len(adapter.current_revision()) == 64


def test_inventory_observes_header_read_ceiling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "large.index"
    path.write_bytes(_flat_header() + b"private vector payload" * 100)
    original = os.read
    requested: list[int] = []

    def bounded_read(descriptor: int, count: int) -> bytes:
        requested.append(count)
        return original(descriptor, count)

    monkeypatch.setattr(os, "read", bounded_read)
    assert FaissInventoryAdapter.probe(path).recognized
    assert requested == [45]


@pytest.mark.parametrize(
    ("magic", "metric", "count", "recognized"),
    [
        (b"IxF2", 1, 6, True),
        (b"IxFI", 0, 6, True),
        (b"IxF2", 0, 6, False),
        (b"IxFI", 1, 6, False),
        (b"IxFl", 7, 6, False),
        (b"IxF2", 1, 5, False),
    ],
)
def test_nonempty_inventory_header_checks_metric_and_element_count(
    tmp_path: Path,
    magic: bytes,
    metric: int,
    count: int,
    recognized: bool,
) -> None:
    path = tmp_path / "index.faiss"
    path.write_bytes(magic + struct.pack("<iqQQ?iQ", 2, 3, 1 << 20, 1 << 20, True, metric, count))
    assert FaissInventoryAdapter.probe(path).recognized is recognized


def test_inventory_rechecks_format_after_registration(tmp_path: Path) -> None:
    path = tmp_path / "index.faiss"
    path.write_bytes(_flat_header())
    adapter = FaissInventoryAdapter(path).open(read_only=True)
    path.write_bytes(b"replaced by another format")
    with pytest.raises(MemoryError, match="recognized"):
        adapter.current_revision()
