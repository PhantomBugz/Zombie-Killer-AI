"""Bounded, read-only recognition of common FAISS flat-index headers."""

from __future__ import annotations

import struct
from pathlib import Path

from zombie_killer_engine.memory.base import (
    FileIdentity,
    MemoryError,
    ProbeResult,
    VaultCapabilities,
    VaultFormat,
    VaultSource,
    canonical_hash,
    read_prefix_pinned,
    source_id,
)

# Upstream flat-index serialization uses these four-character type identifiers:
# https://github.com/facebookresearch/faiss/blob/main/faiss/impl/index_read.cpp
_FLAT_TYPES = {b"IxF2", b"IxFI", b"IxFl"}
_HEADER_BYTES = 45
_INVENTORY_REASON = (
    "FAISS flat-index header detected; inventory-only. The complete index and vectors "
    "are not deserialized or validated."
)


def _recognized_header(prefix: bytes) -> bool:
    if len(prefix) < _HEADER_BYTES or prefix[:4] not in _FLAT_TYPES:
        return False
    dimension, total = struct.unpack_from("<iq", prefix, 4)
    metric = struct.unpack_from("<i", prefix, 33)[0]
    vector_count = struct.unpack_from("<Q", prefix, 37)[0]
    return (
        0 <= dimension <= 1 << 20
        and total >= 0
        and prefix[32] in {0, 1}
        and metric in {0, 1}
        and vector_count == dimension * total
        and (prefix[:4] != b"IxFI" or metric == 0)
        and (prefix[:4] != b"IxF2" or metric == 1)
    )


def _capabilities() -> VaultCapabilities:
    return VaultCapabilities(
        readable=True,
        queryable=False,
        editable=False,
        snapshot=False,
        restore=False,
        reason=_INVENTORY_REASON,
    )


class FaissInventoryAdapter:
    """Inspect headers without loading FAISS, vector data, or pickle companions."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.healthcheck()

    @classmethod
    def probe(cls, path: Path) -> ProbeResult:
        prefix, _identity = read_prefix_pinned(path, prefix_bytes=_HEADER_BYTES)
        recognized = _recognized_header(prefix)
        return ProbeResult(
            format=VaultFormat.FAISS if recognized else VaultFormat.UNSUPPORTED,
            recognized=recognized,
            capabilities=(
                _capabilities()
                if recognized
                else VaultCapabilities(
                    readable=False,
                    queryable=False,
                    reason="No supported FAISS flat-index header was recognized.",
                )
            ),
            reason=(
                _INVENTORY_REASON
                if recognized
                else "No supported FAISS flat-index header was recognized."
            ),
        )

    def _read_header(self) -> tuple[bytes, FileIdentity]:
        prefix, identity = read_prefix_pinned(self.path, prefix_bytes=_HEADER_BYTES)
        if not _recognized_header(prefix):
            raise MemoryError("a supported FAISS flat-index header was not recognized")
        return prefix, identity

    def open(self, *, read_only: bool) -> FaissInventoryAdapter:
        if not read_only:
            raise MemoryError("FAISS is inventory-only and cannot be opened for mutation")
        self.healthcheck()
        return self

    def current_revision(self) -> str:
        """Return an inventory revision, not a hash of all vector content."""
        prefix, identity = self._read_header()
        return canonical_hash(
            {
                "kind": "faiss_header_inventory",
                "header": prefix.hex(),
                "identity": identity.model_dump(mode="json"),
            }
        )

    @property
    def source(self) -> VaultSource:
        return VaultSource(
            source_id=source_id(self.path),
            path=str(self.path),
            format=VaultFormat.FAISS,
            capabilities=_capabilities(),
            revision=self.current_revision(),
        )

    def healthcheck(self) -> None:
        self._read_header()


__all__ = ["FaissInventoryAdapter"]
