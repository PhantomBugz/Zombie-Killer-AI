"""Finite, persistent, content-minimized local diagnostics export."""

from __future__ import annotations

import json
import os
import secrets
import stat
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

from zombie_killer_engine.memory.base import (
    canonical_hash,
    secure_created_file,
    sha256_bytes,
    validate_local_path_lexical,
)
from zombie_killer_engine.quarantine import (
    _chain_to,
    _close_native_handles,
    _default_reparse_checker,
    _open_posix_directory_chain,
    _validate_root,
    _windows_assert_root_acl,
    _windows_current_user_sid,
    _windows_open_handle,
    _windows_owner_sid_from_handle,
)
from zombie_killer_engine.redaction import redact_display_text
from zombie_killer_engine.store import PlanClaimError, SQLiteStateStore

_KIND = "diagnostics_export"
_LIMIT = 32_768
_EXCLUDED = ("command_lines", "memory_contents", "paths", "secrets")
_SETTINGS = frozenset(
    {
        "revision",
        "scan_interval_seconds",
        "heartbeat_grace_seconds",
        "include_unmanaged",
        "include_unmanaged_candidates",
        "quarantine_retention_days",
        "retention_days",
        "theme",
        "appearance",
        "reduced_motion",
    }
)
_RECEIPT_FIELDS = frozenset(
    {
        "receipt_id",
        "plan_id",
        "outcome",
        "certainty",
        "action_issued",
        "created_at",
        "kind",
    }
)


def _text(value: object, limit: int = 128) -> str:
    return redact_display_text(value, max_length=limit)


def _public_snapshot(
    diagnostics: Mapping[str, object],
    *,
    include_receipts: bool,
    include_settings: bool,
) -> dict[str, object]:
    """Select fields, rather than attempting to sanitize arbitrary private records."""
    result: dict[str, object] = {
        "schema_version": 1,
        "local_only": True,
        "network_listener": False,
        "excluded_by_default": _EXCLUDED,
    }
    for key in ("engine_version", "protocol_version", "platform"):
        value = diagnostics.get(key)
        if isinstance(value, str):
            result[key] = _text(value, 64)
    doctor = diagnostics.get("doctor")
    if isinstance(doctor, Mapping):
        checks: list[dict[str, object]] = []
        raw_checks = doctor.get("checks")
        if isinstance(raw_checks, (list, tuple)):
            for check in raw_checks[:64]:
                if isinstance(check, Mapping):
                    checks.append(
                        {
                            "name": _text(check.get("name", "unknown")),
                            "ok": check.get("ok") is True,
                        }
                    )
        result["doctor"] = {"healthy": doctor.get("healthy") is True, "checks": checks}
    if include_settings:
        raw_settings = diagnostics.get("settings")
        if isinstance(raw_settings, Mapping):
            settings: dict[str, object] = {}
            for key in sorted(_SETTINGS):
                value = raw_settings.get(key)
                if (
                    key in {"include_unmanaged", "include_unmanaged_candidates", "reduced_motion"}
                    and isinstance(value, bool)
                    or key
                    in {
                        "revision",
                        "scan_interval_seconds",
                        "heartbeat_grace_seconds",
                        "quarantine_retention_days",
                        "retention_days",
                    }
                    and type(value) is int
                    and 0 <= value <= 9_007_199_254_740_991
                    or key in {"theme", "appearance"}
                    and isinstance(value, str)
                    and value in {"system", "light", "dark"}
                ):
                    settings[key] = value
            result["settings"] = settings
    if include_receipts:
        raw_receipts = diagnostics.get("receipts")
        receipts: list[dict[str, object]] = []
        if isinstance(raw_receipts, (list, tuple)):
            for raw in raw_receipts[:20]:
                if not isinstance(raw, Mapping):
                    continue
                receipt: dict[str, object] = {}
                for key in sorted(_RECEIPT_FIELDS):
                    value = raw.get(key)
                    if key == "action_issued" and (value is None or isinstance(value, bool)):
                        receipt[key] = value
                    elif isinstance(value, str):
                        receipt[key] = _text(value)
                # Free-form failure messages are deliberately omitted; public outcome and
                # certainty provide useful diagnostics without copying operational content.
                receipts.append(receipt)
        result["receipts"] = receipts
    return result


def _parent_binding(parent: Path) -> list[list[int]]:
    _validate_root(parent, reparse_checker=_default_reparse_checker)
    values = []
    for component in _chain_to(parent):
        observed = component.lstat()
        if not stat.S_ISDIR(observed.st_mode):
            raise ValueError("diagnostics destination ancestry is not a direct directory")
        values.append([int(observed.st_dev), int(observed.st_ino), int(observed.st_mode)])
    return values


@contextmanager
def _pin_parent(parent: Path, expected: object) -> Iterator[int | None]:
    handles: list[int] = []
    bindings: list[Callable[[], None]] = []
    try:
        descriptor: int | None = None
        if os.name == "nt":
            for component in _chain_to(parent):
                # Keep every selected ancestor name stable through exclusive creation.
                handles.append(_windows_open_handle(component, access=0x80, share=3))
        else:
            descriptor = _open_posix_directory_chain(
                parent,
                handles=handles,
                validators=[],
                binding_validators=bindings,
                label="diagnostics destination",
            )
        for validate in bindings:
            validate()
        if _parent_binding(parent) != expected:
            raise ValueError("diagnostics destination parent changed after review")
        yield descriptor
        for validate in bindings:
            validate()
        if _parent_binding(parent) != expected:
            raise ValueError("diagnostics destination parent changed during export")
    finally:
        _close_native_handles(handles)


def _write_export(descriptor: int, contents: bytes) -> None:
    remaining = memoryview(contents)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError("diagnostics export write made no progress")
        remaining = remaining[written:]
    os.fsync(descriptor)


def _read_export(descriptor: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks = []
    remaining = _LIMIT + 1
    while remaining:
        chunk = os.read(descriptor, min(4096, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    contents = b"".join(chunks)
    if len(contents) > _LIMIT:
        raise ValueError("diagnostics export exceeds its bound")
    return contents


def _verify_named_file(destination: Path, descriptor: int, parent_fd: int | None) -> None:
    opened = os.fstat(descriptor)
    named = (
        destination.lstat()
        if parent_fd is None
        else os.stat(destination.name, dir_fd=parent_fd, follow_symlinks=False)
    )
    if (
        not stat.S_ISREG(opened.st_mode)
        or opened.st_nlink != 1
        or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
    ):
        raise ValueError("diagnostics output identity could not be verified")
    if os.name != "nt" and (
        opened.st_uid != os.geteuid()  # type: ignore[attr-defined]
        or stat.S_IMODE(opened.st_mode) & 0o077
    ):
        raise ValueError("diagnostics output permissions are not private")
    if os.name == "nt":
        import msvcrt

        handle = msvcrt.get_osfhandle(descriptor)
        if not secrets.compare_digest(
            _windows_owner_sid_from_handle(handle),
            _windows_current_user_sid(),
        ):
            raise ValueError("diagnostics output is not owned by the current user")
        _windows_assert_root_acl(handle)


class DiagnosticsWorkflow:
    def __init__(
        self,
        store: SQLiteStateStore,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._store = store
        self._clock = clock or (lambda: datetime.now(UTC))

    def plan(
        self,
        destination: str,
        *,
        diagnostics: dict[str, object],
        include_receipts: bool = True,
        include_settings: bool = True,
    ) -> dict[str, object]:
        path = Path(destination)
        if len(destination) > 4096:
            raise ValueError("diagnostics destination exceeds its bound")
        validate_local_path_lexical(path)
        parent = _parent_binding(path.parent)
        if os.path.lexists(path):
            raise ValueError("diagnostics destination already exists")
        snapshot = _public_snapshot(
            diagnostics,
            include_receipts=include_receipts,
            include_settings=include_settings,
        )
        contents = (
            json.dumps(
                snapshot,
                allow_nan=False,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        )
        if len(contents.encode()) > _LIMIT:
            raise ValueError("diagnostics snapshot exceeds its bound")
        now = self._clock()
        plan_id = secrets.token_urlsafe(24)
        expires_at = now + timedelta(seconds=30)
        payload: dict[str, object] = {
            "plan_id": plan_id,
            "destination": str(path),
            "parent_binding": parent,
            "contents": contents,
            "content_digest": sha256_bytes(contents.encode()),
            "created_at": now.isoformat(),
            "expires_at": expires_at.isoformat(),
        }
        digest = canonical_hash(payload)
        payload["digest"] = digest
        self._store.save_workflow_plan(
            _KIND,
            plan_id,
            digest,
            payload,
            expires_at=expires_at,
        )
        return {
            "plan_id": plan_id,
            "digest": digest,
            "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
            "consequences": ("Create the reviewed local diagnostics file without overwrite.",),
            "warnings": ("Export contains at most 20 receipts from the reviewed snapshot.",),
            "excluded_by_default": _EXCLUDED,
        }

    def execute(self, plan_id: str, digest: str) -> dict[str, object]:
        payload = self._store.get_workflow_plan(_KIND, plan_id)
        if payload is None or payload.get("digest") != digest:
            raise PlanClaimError("diagnostics plan digest did not match")
        unsigned = {key: value for key, value in payload.items() if key != "digest"}
        if not secrets.compare_digest(canonical_hash(unsigned), digest):
            raise PlanClaimError("diagnostics plan authority changed")
        previous = self._store.get_workflow_receipt(_KIND, plan_id)
        if previous is not None:
            return previous
        claimed = self._store.claim_workflow_plan(
            _KIND,
            plan_id,
            expected_digest=digest,
            reconcile=True,
        )
        destination = Path(cast(str, claimed["destination"]))
        contents = cast(str, claimed["contents"]).encode()
        expected_digest = cast(str, claimed["content_digest"])
        if len(contents) > _LIMIT or sha256_bytes(contents) != expected_digest:
            raise PlanClaimError("diagnostics content authority changed")
        issued = False
        prior_issue_possible = claimed.get("_workflow_reconcile_required") is True
        recovered = False
        receipt: dict[str, object]
        try:
            with _pin_parent(destination.parent, claimed["parent_binding"]) as parent_fd:
                flags = os.O_RDWR | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
                try:
                    if prior_issue_possible or self._clock() >= datetime.fromisoformat(
                        cast(str, claimed["expires_at"])
                    ):
                        # Dead-owner reconciliation may inspect an existing file but may
                        # never repeat creation, even while the original plan is unexpired.
                        descriptor = os.open(
                            str(destination) if parent_fd is None else destination.name,
                            flags,
                            dir_fd=parent_fd,
                        )
                        recovered = True
                    else:
                        descriptor = os.open(
                            str(destination) if parent_fd is None else destination.name,
                            flags | os.O_CREAT | os.O_EXCL,
                            0o600,
                            dir_fd=parent_fd,
                        )
                except FileExistsError:
                    # A dead-owner claim may have finished the exact export before journaling.
                    # Preserve all other existing destinations. No recovery path overwrites.
                    descriptor = os.open(
                        str(destination) if parent_fd is None else destination.name,
                        flags,
                        dir_fd=parent_fd,
                    )
                    recovered = True
                try:
                    if not recovered:
                        issued = True
                        if os.name == "nt":
                            secure_created_file(destination)
                        else:
                            os.fchmod(descriptor, 0o600)  # type: ignore[attr-defined]
                        _write_export(descriptor, contents)
                    _verify_named_file(destination, descriptor, parent_fd)
                    if sha256_bytes(_read_export(descriptor)) != expected_digest:
                        raise ValueError("existing diagnostics output differs from reviewed export")
                finally:
                    os.close(descriptor)
                if parent_fd is not None:
                    os.fsync(parent_fd)
            receipt = self._receipt(
                plan_id, "already_exported" if recovered else "exported", issued
            )
        except Exception:
            receipt = self._receipt(
                plan_id,
                "uncertain" if issued or prior_issue_possible else "failed_before_issue",
                None if issued or prior_issue_possible else False,
            )
        self._store.finish_workflow_plan(_KIND, plan_id, receipt)
        return receipt

    def _receipt(self, plan_id: str, outcome: str, issued: bool | None) -> dict[str, object]:
        success = outcome in {"exported", "already_exported"}
        return {
            "receipt_id": secrets.token_urlsafe(24),
            "plan_id": plan_id,
            "kind": "diagnostics",
            "outcome": outcome,
            "certainty": "verified"
            if success
            else "uncertain"
            if issued is None
            else "failed_before_issue",
            "action_issued": issued,
            "partial_failures": []
            if success
            else ["Local export could not be verified; existing data was preserved."],
            "created_at": self._clock().isoformat().replace("+00:00", "Z"),
        }
