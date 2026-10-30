"""Shared, platform-aware fingerprints for process identity text fields."""

from __future__ import annotations

import hashlib


def normalized_identity_fingerprint(value: str, *, platform_name: str) -> str:
    """Hash an observed identity string using the platform comparison policy."""
    normalized = value.casefold() if platform_name.casefold().startswith("win") else value
    return hashlib.sha256(normalized.encode("utf-8", errors="strict")).hexdigest()
