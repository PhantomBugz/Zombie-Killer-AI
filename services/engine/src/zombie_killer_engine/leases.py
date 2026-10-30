"""Bounded reading of untrusted SDK leases and atomic cancellation requests.

The on-disk lease protocol is ordinary versioned JSON so the separately published
standard-library SDK can produce it without importing Pydantic. Timestamps are RFC
3339 strings with an explicit UTC offset. Lease files must never contain prompts,
response bodies, environment values, or provider credentials.

Cancellation protocol v2 binds every request to one boot/PID/create-time
fingerprint, available executable/user hashes, one lease registration generation,
one plan/request generation, and a maximum thirty-second UTC expiry. Version-1
unbound requests are intentionally ignored.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import math
import os
import re
import stat
import sys
import tempfile
import uuid
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)

from zombie_killer_engine.models import AgentState, Lease, ProcessIdentity
from zombie_killer_engine.paths import (
    WindowsPermissionBackend,
    _effective_user_id,
    _has_redirected_component,
    _open_directory_nofollow,
)
from zombie_killer_engine.redaction import redact_text

LEASE_PROTOCOL_VERSION = 1
CANCELLATION_PROTOCOL_VERSION = 2
CANCELLATION_REQUEST_LIFETIME_SECONDS = 30
MAX_LEASE_BYTES = 128 * 1024
MAX_CANCELLATION_BYTES = 16 * 1024
MAX_LEASE_FILES = 1024
MAX_AGGREGATE_LEASE_BYTES = 16 * 1024 * 1024
MAX_LEASE_WARNINGS = 128
MAX_RESOURCES = 64
MAX_COUNTERS = 64
DEFAULT_TERMINAL_RETENTION_SECONDS = 24 * 60 * 60

_SAFE_AGENT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_WINDOWS_RESERVED_NAMES = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{index}" for index in range(1, 10)}
    | {f"lpt{index}" for index in range(1, 10)}
)
_BoundedText = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256)
]
_BoundedStatus = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2048)
]
_BoundedPath = Annotated[str, StringConstraints(min_length=1, max_length=4096)]
_BoundedExecutable = Annotated[str, StringConstraints(min_length=1, max_length=32_768)]
_HashText = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]

if TYPE_CHECKING:
    from collections.abc import Callable


class _DiskModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class LeaseLifecycle(StrEnum):
    RUNNING = "running"
    IDLE = "idle"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

    @property
    def terminal(self) -> bool:
        return self in {self.COMPLETED, self.FAILED, self.CANCELLED}


def _require_safe_agent_id(agent_id: str) -> str:
    reserved_stem = agent_id.split(".", 1)[0].casefold()
    if (
        not _SAFE_AGENT_ID.fullmatch(agent_id)
        or agent_id.endswith(".")
        or reserved_stem in _WINDOWS_RESERVED_NAMES
    ):
        raise ValueError("agent_id is not a portable request identifier")
    return agent_id


class _DiskIdentity(_DiskModel):
    boot_id: _BoundedText
    pid: int = Field(gt=0)
    create_time: float = Field(ge=0, allow_inf_nan=False)
    executable: _BoundedExecutable | None = None
    user: _BoundedText | None = None


class DeclaredCreationFingerprint(_DiskModel):
    device: int = Field(ge=0)
    inode: int = Field(ge=0)
    mode: int = Field(ge=0)
    size: int = Field(ge=0)
    mtime_ns: int = Field(ge=0)
    ctime_ns: int = Field(ge=0)
    content_digest: _HashText


class DeclaredResource(_DiskModel):
    """A bounded local resource declaration; only temporary paths are v1."""

    kind: Literal["temporary"]
    path: _BoundedPath
    approved_root: _BoundedPath | None = None
    resource_type: Literal["file", "directory"] | None = None
    cleanup_policy: Literal["quarantine"] | None = None
    creation_fingerprint: DeclaredCreationFingerprint | None = None

    @model_validator(mode="after")
    def authority_is_complete_or_legacy(self) -> DeclaredResource:
        supplied = (
            self.approved_root,
            self.resource_type,
            self.cleanup_policy,
            self.creation_fingerprint,
        )
        if any(value is not None for value in supplied) and any(
            value is None for value in supplied
        ):
            raise ValueError("temporary cleanup declaration authority must be complete")
        return self


class LeaseEnvelope(_DiskModel):
    """Strict JSON-native version 1 lease envelope written by the SDK."""

    protocol_version: Literal[1]
    agent_id: _BoundedText
    registration_nonce: _BoundedText | None = None
    identity: _DiskIdentity
    heartbeat_at: str = Field(min_length=1, max_length=64)
    heartbeat_timeout_seconds: float = Field(gt=0, allow_inf_nan=False)
    provider: _BoundedText | None = None
    project: _BoundedText | None = None
    role: _BoundedText | None = None
    status: _BoundedStatus | None = None
    detached: bool = False
    expected_parent_pid: int | None = Field(default=None, gt=0)
    expected_owner: _BoundedText | None = None
    run_id: _BoundedText | None = None
    lifecycle: Literal["running", "idle", "completed", "failed", "cancelled"] = "running"
    terminal_at: str | None = Field(default=None, min_length=1, max_length=64)
    resources: list[DeclaredResource] = Field(default_factory=list, max_length=MAX_RESOURCES)
    counters: dict[_BoundedText, int | float] = Field(
        default_factory=dict,
        max_length=MAX_COUNTERS,
    )

    @field_validator("agent_id")
    @classmethod
    def agent_id_is_portable(cls, value: str) -> str:
        return _require_safe_agent_id(value)

    @model_validator(mode="after")
    def terminal_fields_are_consistent(self) -> LeaseEnvelope:
        if LeaseLifecycle(self.lifecycle).terminal != (self.terminal_at is not None):
            raise ValueError("terminal lifecycle and timestamp must be present together")
        if any(
            isinstance(value, bool) or not math.isfinite(value) or value < 0
            for value in self.counters.values()
        ):
            raise ValueError("counter values must be finite non-negative numbers")
        return self


class LeaseDocument(_DiskModel):
    """Validated lease evidence plus bounded display metadata."""

    protocol_version: Literal[1] = 1
    source_name: str = Field(min_length=1, max_length=256)
    lease: Lease
    provider: _BoundedText | None = None
    project: _BoundedText | None = None
    role: _BoundedText | None = None
    status: _BoundedStatus | None = None
    run_id: _BoundedText | None = None
    lifecycle: LeaseLifecycle
    terminal_at: datetime | None = None
    resources: tuple[DeclaredResource, ...] = Field(max_length=MAX_RESOURCES)
    counters: dict[_BoundedText, float] = Field(max_length=MAX_COUNTERS)


class LeaseWarning(_DiskModel):
    """Structured display-safe warning produced while reading a lease."""

    code: str = Field(min_length=1, max_length=128)
    source_name: str = Field(min_length=1, max_length=256)
    message: str = Field(min_length=1, max_length=512)


class LeaseDiscovery(_DiskModel):
    leases: tuple[LeaseDocument, ...]
    warnings: tuple[LeaseWarning, ...]
    malformed_count: int = Field(ge=0)
    total_count: int = Field(default=0, ge=0)
    skipped_count: int = Field(default=0, ge=0)


class CancellationTarget(_DiskModel):
    """Non-secret fingerprint of the one process instance authorized to observe."""

    boot_id: _BoundedText
    pid: int = Field(gt=0)
    create_time_hash: _HashText
    executable_hash: _HashText | None = None
    user_hash: _HashText | None = None


class CancellationRequest(_DiskModel):
    protocol_version: Literal[2]
    agent_id: _BoundedText
    registration_nonce: _BoundedText
    plan_id: _BoundedText
    request_id: _BoundedText
    target: CancellationTarget
    requested_at: datetime
    expires_at: datetime


class _DiskCancellationRequest(_DiskModel):
    protocol_version: Literal[2]
    agent_id: _BoundedText
    registration_nonce: _BoundedText
    plan_id: _BoundedText
    request_id: _BoundedText
    target: CancellationTarget
    requested_at: str = Field(min_length=1, max_length=64)
    expires_at: str = Field(min_length=1, max_length=64)


class _DiskCancellationAcknowledgement(_DiskModel):
    protocol_version: Literal[2]
    agent_id: _BoundedText
    request_id: _BoundedText


def _utc_now(value: datetime | None) -> datetime:
    resolved = value or datetime.now(UTC)
    if resolved.tzinfo is None or resolved.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return resolved.astimezone(UTC)


def _parse_timestamp(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a UTC offset")
    return parsed.astimezone(UTC)


def _display(value: str | None, *, max_length: int = 256) -> str | None:
    return None if value is None else redact_text(value, max_length=max_length)


def _warning(code: str, source_name: str, message: str) -> LeaseWarning:
    return LeaseWarning(
        code=code,
        source_name=redact_text(source_name, max_length=256) or "[unnamed]",
        message=redact_text(message, max_length=512) or "Lease processing failed.",
    )


class _LeaseWarningCollector:
    def __init__(self) -> None:
        self._grouped: dict[tuple[str, str], tuple[LeaseWarning, int]] = {}

    def add(self, warning: LeaseWarning) -> None:
        key = (warning.code, warning.message)
        existing = self._grouped.get(key)
        self._grouped[key] = (
            warning if existing is None else existing[0],
            1 if existing is None else existing[1] + 1,
        )

    def render(self, *, max_warnings: int) -> tuple[LeaseWarning, ...]:
        return _bounded_lease_warnings(self._grouped, max_warnings=max_warnings)


def _bounded_lease_warnings(
    grouped: dict[tuple[str, str], tuple[LeaseWarning, int]],
    *,
    max_warnings: int,
) -> tuple[LeaseWarning, ...]:
    collapsed: list[LeaseWarning] = []
    for (code, message), (warning, count) in grouped.items():
        if count == 1:
            collapsed.append(warning)
        else:
            collapsed.append(
                _warning(
                    "LEASE_WARNING_SUMMARY",
                    "multiple-leases",
                    f"{code} repeated {count} times. {message}",
                )
            )
    if len(collapsed) <= max_warnings:
        return tuple(collapsed)
    retained = collapsed[: max_warnings - 1]
    retained.append(
        _warning(
            "LEASE_WARNING_SUMMARY",
            "multiple-leases",
            f"{len(collapsed) - len(retained)} additional warning groups were omitted.",
        )
    )
    return tuple(retained)


def _is_reparse_point(path_stat: os.stat_result) -> bool:
    attributes = getattr(path_stat, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(attributes & reparse_flag)


def _same_file_instance(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        left.st_size,
        left.st_mtime_ns,
    ) == (
        right.st_dev,
        right.st_ino,
        right.st_size,
        right.st_mtime_ns,
    )


class _LeaseDirectoryRedirectedError(OSError):
    pass


class _LeaseDirectoryUnverifiableError(OSError):
    pass


class CancellationNotPublishedError(OSError):
    """Cancellation preparation failed before a request could be published."""


class CancellationPublicationUncertainError(OSError):
    """A cancellation was published but its compensating cleanup was uncertain."""


@dataclass(frozen=True, slots=True)
class _WindowsDirectoryComponent:
    path: Path
    handle: int
    inode: int


class _WindowsFileInformation(ctypes.Structure):
    _fields_ = [
        ("file_attributes", ctypes.c_ulong),
        ("creation_time_low", ctypes.c_ulong),
        ("creation_time_high", ctypes.c_ulong),
        ("access_time_low", ctypes.c_ulong),
        ("access_time_high", ctypes.c_ulong),
        ("write_time_low", ctypes.c_ulong),
        ("write_time_high", ctypes.c_ulong),
        ("volume_serial_number", ctypes.c_ulong),
        ("file_size_high", ctypes.c_ulong),
        ("file_size_low", ctypes.c_ulong),
        ("number_of_links", ctypes.c_ulong),
        ("file_index_high", ctypes.c_ulong),
        ("file_index_low", ctypes.c_ulong),
    ]


class _ProtocolSidAndAttributes(ctypes.Structure):
    _fields_ = (("sid", ctypes.c_void_p), ("attributes", ctypes.c_ulong))


class _ProtocolTokenUser(ctypes.Structure):
    _fields_ = (("user", _ProtocolSidAndAttributes),)


@dataclass(slots=True)
class _VerifiedLeaseDirectory:
    directory_fd: int | None
    directory_stat: os.stat_result
    windows_components: tuple[_WindowsDirectoryComponent, ...] = ()

    def verify(self) -> None:
        if self.directory_fd is not None:
            current = os.fstat(self.directory_fd)
            if not stat.S_ISDIR(current.st_mode) or _is_reparse_point(current):
                raise _LeaseDirectoryRedirectedError("verified lease directory handle changed")
            return
        for component in self.windows_components:
            current = os.lstat(component.path)
            if (
                not stat.S_ISDIR(current.st_mode)
                or _is_reparse_point(current)
                or current.st_ino != component.inode
            ):
                raise _LeaseDirectoryRedirectedError("lease directory component changed")

    def close(self) -> None:
        if self.directory_fd is not None:
            os.close(self.directory_fd)
            self.directory_fd = None
        if self.windows_components:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
            for component in self.windows_components:
                kernel32.CloseHandle(component.handle)
            self.windows_components = ()


def _open_verified_posix_directory(path: Path) -> _VerifiedLeaseDirectory:
    if (
        not hasattr(os, "O_DIRECTORY")
        or not hasattr(os, "O_NOFOLLOW")
        or os.open not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
        or os.stat not in os.supports_follow_symlinks
        or os.scandir not in os.supports_fd
    ):
        raise _LeaseDirectoryUnverifiableError("no-follow directory traversal is unavailable")
    absolute = path.absolute()
    flags = (
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW  # type: ignore[attr-defined]
    )
    descriptor = os.open(absolute.anchor, flags)
    try:
        for component_name in absolute.parts[1:]:
            component_stat = os.stat(
                component_name,
                dir_fd=descriptor,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISDIR(component_stat.st_mode)
                or stat.S_ISLNK(component_stat.st_mode)
                or _is_reparse_point(component_stat)
            ):
                raise _LeaseDirectoryRedirectedError("lease directory component is redirected")
            try:
                child_descriptor = os.open(
                    component_name,
                    flags,
                    dir_fd=descriptor,
                )
            except OSError as error:
                if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise _LeaseDirectoryRedirectedError(
                        "lease directory component changed while opening"
                    ) from error
                raise
            try:
                opened_component_stat = os.fstat(child_descriptor)
                if (
                    not stat.S_ISDIR(opened_component_stat.st_mode)
                    or _is_reparse_point(opened_component_stat)
                    or (
                        opened_component_stat.st_dev,
                        opened_component_stat.st_ino,
                    )
                    != (component_stat.st_dev, component_stat.st_ino)
                ):
                    raise _LeaseDirectoryRedirectedError(
                        "lease directory component changed while opening"
                    )
            except BaseException:
                os.close(child_descriptor)
                raise
            os.close(descriptor)
            descriptor = child_descriptor
        directory_stat = os.fstat(descriptor)
        if not stat.S_ISDIR(directory_stat.st_mode):
            raise _LeaseDirectoryRedirectedError("lease directory is not a directory")
    except BaseException:
        os.close(descriptor)
        raise
    return _VerifiedLeaseDirectory(
        directory_fd=descriptor,
        directory_stat=directory_stat,
    )


def _open_verified_windows_directory(path: Path) -> _VerifiedLeaseDirectory:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.restype = ctypes.c_void_p
    kernel32.CreateFileW.argtypes = (
        ctypes.c_wchar_p,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_void_p,
    )
    kernel32.GetFileInformationByHandle.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(_WindowsFileInformation),
    )
    kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
    absolute = path.absolute()
    current_path = Path(absolute.anchor)
    component_paths = [current_path]
    for component in absolute.parts[1:]:
        current_path /= component
        component_paths.append(current_path)

    opened: list[_WindowsDirectoryComponent] = []
    try:
        for component_path in component_paths:
            handle_value = kernel32.CreateFileW(
                str(component_path),
                0x00000080,
                0x00000003,
                None,
                3,
                0x02000000 | 0x00200000,
                None,
            )
            if handle_value == ctypes.c_void_p(-1).value:
                error_number = ctypes.get_last_error()
                raise OSError(error_number, os.strerror(error_number))
            handle = int(handle_value)
            information = _WindowsFileInformation()
            if not kernel32.GetFileInformationByHandle(
                handle,
                ctypes.byref(information),
            ):
                error_number = ctypes.get_last_error()
                kernel32.CloseHandle(handle)
                raise OSError(error_number, os.strerror(error_number))
            inode = (information.file_index_high << 32) | information.file_index_low
            opened_component = _WindowsDirectoryComponent(
                path=component_path,
                handle=handle,
                inode=inode,
            )
            opened.append(opened_component)
            component_stat = os.lstat(component_path)
            if (
                not information.file_attributes & 0x00000010
                or information.file_attributes & 0x00000400
                or not stat.S_ISDIR(component_stat.st_mode)
                or _is_reparse_point(component_stat)
                or component_stat.st_ino != inode
            ):
                raise _LeaseDirectoryRedirectedError("lease directory component is redirected")
        directory_stat = os.lstat(absolute)
        verified = _VerifiedLeaseDirectory(
            directory_fd=None,
            directory_stat=directory_stat,
            windows_components=tuple(opened),
        )
        verified.verify()
        return verified
    except BaseException:
        for opened_component in opened:
            kernel32.CloseHandle(opened_component.handle)
        raise


def _open_verified_lease_directory(path: Path) -> _VerifiedLeaseDirectory:
    if os.name == "nt":
        return _open_verified_windows_directory(path)
    return _open_verified_posix_directory(path)


def _read_regular_file(
    path: Path,
    expected_stat: os.stat_result,
    *,
    max_bytes: int,
    directory_fd: int | None = None,
) -> bytes:
    if expected_stat.st_size > max_bytes:
        raise OverflowError("file exceeds configured size limit")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    if directory_fd is None:
        descriptor = os.open(path, flags)
    else:
        descriptor = os.open(path, flags, dir_fd=directory_fd)
    try:
        opened_stat = os.fstat(descriptor)
        if not stat.S_ISREG(opened_stat.st_mode) or _is_reparse_point(opened_stat):
            raise OSError("opened path is not a regular file")
        if directory_fd is None:
            final_path_stat = os.lstat(path)
        else:
            final_path_stat = os.stat(
                path,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
        if (
            not stat.S_ISREG(final_path_stat.st_mode)
            or _is_reparse_point(final_path_stat)
            or not _same_file_instance(opened_stat, expected_stat)
            or not _same_file_instance(opened_stat, final_path_stat)
        ):
            raise OSError("file changed while opening")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        final_stat = os.fstat(descriptor)
        if (final_stat.st_size, final_stat.st_mtime_ns) != (
            opened_stat.st_size,
            opened_stat.st_mtime_ns,
        ):
            raise OSError("file changed while reading")
        if len(data) > max_bytes:
            raise OverflowError("file exceeds configured size limit")
        return data
    finally:
        os.close(descriptor)


def _document_from_payload(
    payload: object,
    *,
    source_name: str,
    redact_resources: bool = True,
) -> LeaseDocument:
    envelope = LeaseEnvelope.model_validate(payload)
    heartbeat_at = _parse_timestamp(envelope.heartbeat_at)
    terminal_at = (
        _parse_timestamp(envelope.terminal_at) if envelope.terminal_at is not None else None
    )
    identity = ProcessIdentity(
        boot_id=envelope.identity.boot_id,
        pid=envelope.identity.pid,
        create_time=envelope.identity.create_time,
        executable=envelope.identity.executable,
        user=envelope.identity.user,
    )
    lifecycle = LeaseLifecycle(envelope.lifecycle)
    declared_state = {
        LeaseLifecycle.IDLE: AgentState.IDLE,
        LeaseLifecycle.COMPLETED: AgentState.COMPLETED,
        LeaseLifecycle.FAILED: AgentState.FAILED,
        LeaseLifecycle.CANCELLED: AgentState.CANCELLED,
    }.get(lifecycle, AgentState.HEALTHY)
    lease = Lease(
        agent_id=envelope.agent_id,
        registration_nonce=envelope.registration_nonce,
        identity=identity,
        heartbeat_at=heartbeat_at,
        heartbeat_timeout_seconds=envelope.heartbeat_timeout_seconds,
        expected_parent_pid=envelope.expected_parent_pid,
        expected_owner=envelope.expected_owner,
        detached=envelope.detached,
        declared_state=declared_state,
        terminal_at=terminal_at,
    )
    resources = tuple(
        resource.model_copy(
            update={
                "path": redact_text(resource.path, max_length=4096),
                "approved_root": redact_text(resource.approved_root, max_length=4096)
                if resource.approved_root is not None
                else None,
            }
        )
        if redact_resources
        else resource
        for resource in envelope.resources
    )
    return LeaseDocument(
        source_name=redact_text(source_name, max_length=256),
        lease=lease,
        provider=_display(envelope.provider),
        project=_display(envelope.project),
        role=_display(envelope.role),
        status=_display(envelope.status, max_length=2048),
        run_id=_display(envelope.run_id),
        lifecycle=lifecycle,
        terminal_at=terminal_at,
        resources=resources,
        counters={key: float(value) for key, value in envelope.counters.items()},
    )


def read_resource_registration(lease_dir: Path, agent_id: str) -> LeaseDocument:
    """Read exact SDK authority privately; display discovery remains redacted."""
    _require_safe_agent_id(agent_id)
    verified = _open_verified_lease_directory(lease_dir)
    try:
        verified.verify()
        name = Path(f"{agent_id}.json")
        if verified.directory_fd is None:
            candidate = lease_dir / name
            expected = candidate.lstat()
        else:
            candidate = name
            expected = os.stat(name, dir_fd=verified.directory_fd, follow_symlinks=False)
        data = _read_regular_file(
            candidate,
            expected,
            max_bytes=MAX_LEASE_BYTES,
            directory_fd=verified.directory_fd,
        )
        verified.verify()
        document = _document_from_payload(
            json.loads(data),
            source_name=str(name),
            redact_resources=False,
        )
        if document.lease.agent_id != agent_id:
            raise ValueError("resource registration filename and agent identity differ")
        return document
    finally:
        verified.close()


def _atomic_write_json(
    target: Path,
    payload: dict[str, object],
    *,
    temporary_prefix: str,
    before_replace: Callable[[], None] | None = None,
    after_replace: Callable[[], None] | None = None,
) -> None:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=temporary_prefix,
        suffix=".tmp",
        dir=target.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        if before_replace is not None:
            before_replace()
        os.replace(temporary, target)
        if after_replace is not None:
            after_replace()
    finally:
        with suppress(OSError):
            temporary.unlink()


def _prepare_verified_cancellation_directory(
    directory: Path,
) -> _VerifiedLeaseDirectory:
    if _has_redirected_component(directory):
        raise _LeaseDirectoryRedirectedError(
            "cancellation directory contains a link or reparse point"
        )
    if os.name == "nt":
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    else:
        descriptor = _open_directory_nofollow(directory, create=True)
        os.close(descriptor)
    if _has_redirected_component(directory):
        raise _LeaseDirectoryRedirectedError("cancellation directory changed during preparation")
    verified = _open_verified_lease_directory(directory)
    try:
        _restrict_verified_cancellation_directory(verified, directory)
        verified.verify()
    except BaseException:
        verified.close()
        raise
    return verified


def _restrict_verified_cancellation_directory(
    verified: _VerifiedLeaseDirectory,
    directory: Path,
) -> None:
    if verified.directory_fd is not None:
        current = os.fstat(verified.directory_fd)
        if current.st_uid != _effective_user_id():
            raise OSError("cancellation directory is not owned by the current user")
        os.fchmod(verified.directory_fd, 0o700)  # type: ignore[attr-defined]
        if stat.S_IMODE(os.fstat(verified.directory_fd).st_mode) != 0o700:
            raise OSError("cancellation directory permissions are not restrictive")
        return
    backend = WindowsPermissionBackend()
    backend.restrict(directory)
    verified.verify()
    backend.verify(directory)


def _verify_cancellation_directory_permissions(
    verified: _VerifiedLeaseDirectory,
    directory: Path,
) -> None:
    if verified.directory_fd is not None:
        current = os.fstat(verified.directory_fd)
        if current.st_uid != _effective_user_id() or stat.S_IMODE(current.st_mode) & 0o077:
            raise OSError("cancellation directory permissions are not restrictive")
        return
    verified.verify()
    WindowsPermissionBackend().verify(directory)
    verified.verify()


def _atomic_write_json_verified(
    verified: _VerifiedLeaseDirectory,
    directory: Path,
    target_name: str,
    payload: dict[str, object],
    *,
    temporary_prefix: str,
    before_replace: Callable[[], None] | None = None,
    after_replace: Callable[[], None] | None = None,
) -> None:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    verified.verify()
    if verified.directory_fd is None:

        def guarded_replace() -> None:
            verified.verify()
            if before_replace is not None:
                before_replace()
            verified.verify()

        _atomic_write_json(
            directory / target_name,
            payload,
            temporary_prefix=temporary_prefix,
            before_replace=guarded_replace,
            after_replace=after_replace,
        )
        verified.verify()
        return
    temporary_name = f"{temporary_prefix}{uuid.uuid4().hex}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(
        temporary_name,
        flags,
        0o600,
        dir_fd=verified.directory_fd,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        verified.verify()
        if before_replace is not None:
            before_replace()
        verified.verify()
        os.replace(
            temporary_name,
            target_name,
            src_dir_fd=verified.directory_fd,
            dst_dir_fd=verified.directory_fd,
        )
        if after_replace is not None:
            after_replace()
        verified.verify()
    finally:
        with suppress(OSError):
            os.unlink(temporary_name, dir_fd=verified.directory_fd)


def _restore_quarantined_file(
    quarantine: Path,
    target: Path,
    *,
    directory_fd: int | None,
) -> bool:
    try:
        if directory_fd is None:
            os.link(quarantine, target, follow_symlinks=False)
            quarantine.unlink()
        else:
            os.link(
                quarantine,
                target,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
            os.unlink(quarantine, dir_fd=directory_fd)
        return True
    except OSError:
        pass

    try:
        if os.name == "nt":
            os.rename(quarantine, target)
        elif directory_fd is not None and sys.platform.startswith("linux"):
            libc = ctypes.CDLL(None, use_errno=True)
            renameat2 = libc.renameat2
            result = renameat2(
                directory_fd,
                os.fsencode(quarantine),
                directory_fd,
                os.fsencode(target),
                1,
            )
            if result != 0:
                error_number = ctypes.get_errno()
                raise OSError(error_number, os.strerror(error_number))
        elif directory_fd is not None and sys.platform == "darwin":
            libc = ctypes.CDLL(None, use_errno=True)
            renameatx_np = libc.renameatx_np
            result = renameatx_np(
                directory_fd,
                os.fsencode(quarantine),
                directory_fd,
                os.fsencode(target),
                0x00000004,
            )
            if result != 0:
                error_number = ctypes.get_errno()
                raise OSError(error_number, os.strerror(error_number))
        else:
            return False
    except OSError:
        return False
    return True


def _cleanup_terminal_lease(
    lease_path: Path,
    source_name: str,
    expected_stat: os.stat_result,
    lease_data: bytes,
    *,
    directory_fd: int | None,
) -> bool:
    """Quarantine, revalidate, then delete only the exact parsed instance."""
    source = lease_path if directory_fd is None else Path(source_name)
    quarantine_name = f".terminal-quarantine-{uuid.uuid4().hex}.tmp"
    quarantine = (
        lease_path.with_name(quarantine_name) if directory_fd is None else Path(quarantine_name)
    )
    try:
        if directory_fd is None:
            current_stat = os.lstat(source)
        else:
            current_stat = os.stat(
                source,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
        if (
            not stat.S_ISREG(current_stat.st_mode)
            or _is_reparse_point(current_stat)
            or not _same_file_instance(expected_stat, current_stat)
        ):
            return False
        if directory_fd is None:
            os.replace(source, quarantine)
            quarantined_stat = os.lstat(quarantine)
        else:
            os.replace(
                source,
                quarantine,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            quarantined_stat = os.stat(
                quarantine,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
        quarantined_data = _read_regular_file(
            quarantine,
            quarantined_stat,
            max_bytes=MAX_LEASE_BYTES,
            directory_fd=directory_fd,
        )
        unchanged = _same_file_instance(expected_stat, quarantined_stat) and (
            hashlib.sha256(quarantined_data).digest() == hashlib.sha256(lease_data).digest()
        )
        if not unchanged:
            _restore_quarantined_file(
                quarantine,
                source,
                directory_fd=directory_fd,
            )
            return False
        if directory_fd is None:
            quarantine.unlink()
        else:
            os.unlink(quarantine, dir_fd=directory_fd)
    except OSError:
        _restore_quarantined_file(
            quarantine,
            source,
            directory_fd=directory_fd,
        )
        return False
    return True


def _discover_from_verified_directory(
    lease_dir: Path,
    verified_directory: _VerifiedLeaseDirectory,
    *,
    captured_at: datetime,
    max_bytes: int,
    terminal_retention_seconds: float,
    max_files: int,
    max_aggregate_bytes: int,
    max_warnings: int,
) -> LeaseDiscovery:
    warnings = _LeaseWarningCollector()
    candidate_malformed_count = 0
    candidates: list[tuple[str, Path, os.stat_result]] = []
    total_count = 0
    skipped_count = 0
    aggregate_bytes = 0
    file_budget_warned = False
    byte_budget_warned = False
    directory_fd = verified_directory.directory_fd
    verified_directory.verify()
    scan_target: Path | int = directory_fd if directory_fd is not None else lease_dir
    with os.scandir(scan_target) as iterator:
        for entry in iterator:
            if not entry.name.endswith(".json"):
                continue
            total_count += 1
            try:
                if directory_fd is None:
                    path_stat = os.lstat(entry.path)
                else:
                    path_stat = os.stat(
                        entry.name,
                        dir_fd=directory_fd,
                        follow_symlinks=False,
                    )
                if stat.S_ISLNK(path_stat.st_mode) or _is_reparse_point(path_stat):
                    candidate_malformed_count += 1
                    warnings.add(
                        _warning(
                            "LEASE_REDIRECTED",
                            entry.name,
                            "Redirected lease entry was ignored.",
                        )
                    )
                    continue
                if not stat.S_ISREG(path_stat.st_mode):
                    continue
            except OSError as error:
                candidate_malformed_count += 1
                warnings.add(
                    _warning(
                        "LEASE_READ_FAILED",
                        entry.name,
                        (f"Lease file disappeared during discovery ({type(error).__name__})."),
                    )
                )
                continue
            if len(candidates) >= max_files:
                skipped_count += 1
                if not file_budget_warned:
                    warnings.add(
                        _warning(
                            "LEASE_FILE_BUDGET_EXCEEDED",
                            lease_dir.name or "leases",
                            "Additional lease files were skipped after the file budget.",
                        )
                    )
                    file_budget_warned = True
                continue
            if (
                path_stat.st_size <= max_bytes
                and aggregate_bytes + path_stat.st_size > max_aggregate_bytes
            ):
                skipped_count += 1
                if not byte_budget_warned:
                    warnings.add(
                        _warning(
                            "LEASE_BYTE_BUDGET_EXCEEDED",
                            lease_dir.name or "leases",
                            "Additional lease files were skipped after the byte budget.",
                        )
                    )
                    byte_budget_warned = True
                continue
            candidates.append((entry.name, lease_dir / entry.name, path_stat))
            if path_stat.st_size <= max_bytes:
                aggregate_bytes += path_stat.st_size
    verified_directory.verify()
    candidates.sort(key=lambda item: item[0])

    leases: list[LeaseDocument] = []
    agent_ids: set[str] = set()
    malformed_count = candidate_malformed_count
    for source_name, path, path_stat in candidates:
        try:
            verified_directory.verify()
            data = _read_regular_file(
                path if directory_fd is None else Path(source_name),
                path_stat,
                max_bytes=max_bytes,
                directory_fd=directory_fd,
            )
            verified_directory.verify()
        except OverflowError:
            malformed_count += 1
            warnings.add(
                _warning(
                    "LEASE_TOO_LARGE",
                    source_name,
                    "Lease file exceeds the 128 KiB protocol limit.",
                )
            )
            continue
        except OSError as error:
            malformed_count += 1
            warnings.add(
                _warning(
                    "LEASE_READ_FAILED",
                    source_name,
                    f"Lease file could not be read ({type(error).__name__}).",
                )
            )
            continue
        try:
            payload = json.loads(data)
        except (json.JSONDecodeError, RecursionError, UnicodeDecodeError):
            malformed_count += 1
            warnings.add(
                _warning(
                    "LEASE_MALFORMED_JSON",
                    source_name,
                    "Lease file is not valid UTF-8 JSON.",
                )
            )
            continue
        try:
            document = _document_from_payload(payload, source_name=source_name)
        except (ValidationError, ValueError, OverflowError):
            malformed_count += 1
            warnings.add(
                _warning(
                    "LEASE_SCHEMA_INVALID",
                    source_name,
                    "Lease file does not match protocol version 1.",
                )
            )
            continue
        if document.lifecycle.terminal and document.terminal_at is not None:
            age = (captured_at - document.terminal_at).total_seconds()
            if age >= terminal_retention_seconds:
                try:
                    verified_directory.verify()
                    cleaned = _cleanup_terminal_lease(
                        path,
                        source_name,
                        path_stat,
                        data,
                        directory_fd=directory_fd,
                    )
                    verified_directory.verify()
                except OSError:
                    cleaned = False
                if not cleaned:
                    warnings.add(
                        _warning(
                            "LEASE_CLEANUP_FAILED",
                            source_name,
                            "Expired terminal lease could not be safely cleaned.",
                        )
                    )
                continue
        if document.lease.agent_id in agent_ids:
            malformed_count += 1
            warnings.add(
                _warning(
                    "LEASE_DUPLICATE_AGENT_ID",
                    source_name,
                    "A duplicate agent ID was ignored.",
                )
            )
            continue
        agent_ids.add(document.lease.agent_id)
        leases.append(document)
    return LeaseDiscovery(
        leases=tuple(leases),
        warnings=warnings.render(max_warnings=max_warnings),
        malformed_count=malformed_count,
        total_count=total_count,
        skipped_count=skipped_count,
    )


def discover_leases(
    lease_dir: Path,
    *,
    now: datetime | None = None,
    max_bytes: int = MAX_LEASE_BYTES,
    terminal_retention_seconds: float = DEFAULT_TERMINAL_RETENTION_SECONDS,
    max_files: int = MAX_LEASE_FILES,
    max_aggregate_bytes: int = MAX_AGGREGATE_LEASE_BYTES,
    max_warnings: int = MAX_LEASE_WARNINGS,
) -> LeaseDiscovery:
    """Read direct regular JSON children without following links or recursing."""
    captured_at = _utc_now(now)
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    if max_files <= 0:
        raise ValueError("max_files must be positive")
    if max_aggregate_bytes <= 0:
        raise ValueError("max_aggregate_bytes must be positive")
    if max_warnings <= 0:
        raise ValueError("max_warnings must be positive")
    if not math.isfinite(terminal_retention_seconds) or terminal_retention_seconds < 0:
        raise ValueError("terminal_retention_seconds must be finite and non-negative")

    try:
        verified_directory = _open_verified_lease_directory(lease_dir)
    except FileNotFoundError:
        return LeaseDiscovery(leases=(), warnings=(), malformed_count=0)
    except _LeaseDirectoryRedirectedError:
        warning = _warning(
            "LEASE_DIRECTORY_REDIRECTED",
            lease_dir.name or "leases",
            "Lease directory contains a redirected path component.",
        )
        return LeaseDiscovery(leases=(), warnings=(warning,), malformed_count=0)
    except (
        AttributeError,
        NotImplementedError,
        TypeError,
        _LeaseDirectoryUnverifiableError,
    ):
        warning = _warning(
            "LEASE_DIRECTORY_UNVERIFIABLE",
            lease_dir.name or "leases",
            "Lease directory cannot be verified without following redirects.",
        )
        return LeaseDiscovery(leases=(), warnings=(warning,), malformed_count=0)
    except OSError as error:
        warning = _warning(
            "LEASE_DIRECTORY_READ_FAILED",
            lease_dir.name or "leases",
            f"Could not inspect the lease directory ({type(error).__name__}).",
        )
        return LeaseDiscovery(leases=(), warnings=(warning,), malformed_count=0)

    try:
        try:
            return _discover_from_verified_directory(
                lease_dir,
                verified_directory,
                captured_at=captured_at,
                max_bytes=max_bytes,
                terminal_retention_seconds=terminal_retention_seconds,
                max_files=max_files,
                max_aggregate_bytes=max_aggregate_bytes,
                max_warnings=max_warnings,
            )
        except FileNotFoundError:
            return LeaseDiscovery(leases=(), warnings=(), malformed_count=0)
        except _LeaseDirectoryRedirectedError:
            warning = _warning(
                "LEASE_DIRECTORY_REDIRECTED",
                lease_dir.name or "leases",
                "Lease directory contains a redirected path component.",
            )
            return LeaseDiscovery(leases=(), warnings=(warning,), malformed_count=0)
        except OSError as error:
            warning = _warning(
                "LEASE_DIRECTORY_READ_FAILED",
                lease_dir.name or "leases",
                f"Could not inspect the lease directory ({type(error).__name__}).",
            )
            return LeaseDiscovery(leases=(), warnings=(warning,), malformed_count=0)
    finally:
        verified_directory.close()


def _cancellation_path(directory: Path, agent_id: str) -> Path:
    return directory / f"{_require_safe_agent_id(agent_id)}.json"


def cancellation_request_path(directory: Path, agent_id: str) -> Path:
    """Return the portable, traversal-safe path used by engine and SDK."""
    return _cancellation_path(directory, agent_id)


def _cancellation_acknowledgement_path(directory: Path, agent_id: str) -> Path:
    return directory / f"{_require_safe_agent_id(agent_id)}.cleared"


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _create_time_hash(value: float) -> str:
    if not math.isfinite(value) or value < 0:
        raise ValueError("process create time must be finite and non-negative")
    return hashlib.sha256(value.hex().encode("ascii")).hexdigest()


def _identity_hash(value: str | None, supplied: str | None) -> str | None:
    if supplied is not None:
        return supplied
    if value is None:
        return None
    normalized = value.casefold() if os.name == "nt" else value
    return hashlib.sha256(normalized.encode("utf-8", errors="strict")).hexdigest()


def cancellation_user_fingerprint(
    pid: int,
    user: str,
    *,
    platform_name: str | None = None,
) -> str:
    """Return the SDK/engine shared OS-authorized cancellation user fingerprint."""
    system = (platform_name or os.name).casefold()
    if not system.startswith("win") and system != "nt":
        try:
            if sys.platform == "linux":
                uid = os.stat(f"/proc/{pid}").st_uid
            elif pid == os.getpid():
                geteuid = getattr(os, "geteuid", None)
                if geteuid is None:
                    raise OSError("effective user ID is unavailable")
                uid = int(geteuid())
            else:
                import pwd

                uid = pwd.getpwnam(user).pw_uid  # type: ignore[attr-defined]
        except (ImportError, KeyError, OSError):
            return hashlib.sha256(user.encode("utf-8", errors="strict")).hexdigest()
        return hashlib.sha256(str(uid).encode("ascii")).hexdigest()
    if os.name != "nt":
        raise OSError("Windows identity APIs are unavailable")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32.OpenProcess.restype = ctypes.c_void_p
    process_handle = kernel32.OpenProcess(0x1000, False, pid)
    if not process_handle:
        raise OSError(ctypes.get_last_error(), "OpenProcess failed")
    token_handle = ctypes.c_void_p()
    rendered = ctypes.c_wchar_p()
    try:
        if not advapi32.OpenProcessToken(
            ctypes.c_void_p(process_handle),
            0x0008,
            ctypes.byref(token_handle),
        ):
            raise OSError(ctypes.get_last_error(), "OpenProcessToken failed")
        required = ctypes.c_ulong()
        advapi32.GetTokenInformation(token_handle, 1, None, 0, ctypes.byref(required))
        if required.value == 0:
            raise OSError(ctypes.get_last_error(), "GetTokenInformation size failed")
        buffer = ctypes.create_string_buffer(required.value)
        if not advapi32.GetTokenInformation(
            token_handle,
            1,
            buffer,
            required.value,
            ctypes.byref(required),
        ):
            raise OSError(ctypes.get_last_error(), "GetTokenInformation failed")
        token_user = ctypes.cast(buffer, ctypes.POINTER(_ProtocolTokenUser)).contents
        advapi32.ConvertSidToStringSidW.argtypes = (
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_wchar_p),
        )
        advapi32.ConvertSidToStringSidW.restype = ctypes.c_int
        if not advapi32.ConvertSidToStringSidW(
            token_user.user.sid,
            ctypes.byref(rendered),
        ):
            raise OSError(ctypes.get_last_error(), "SID conversion failed")
        sid = rendered.value
        if not sid:
            raise OSError("empty Windows SID")
        return hashlib.sha256(sid.encode("utf-8", errors="strict")).hexdigest()
    finally:
        if rendered.value:
            kernel32.LocalFree(rendered)
        if token_handle.value:
            kernel32.CloseHandle(token_handle)
        kernel32.CloseHandle(ctypes.c_void_p(process_handle))


def _cancellation_target(identity: ProcessIdentity) -> CancellationTarget:
    return CancellationTarget(
        boot_id=identity.boot_id,
        pid=identity.pid,
        create_time_hash=_create_time_hash(identity.create_time),
        executable_hash=_identity_hash(identity.executable, identity.executable_hash),
        user_hash=(
            identity.user_hash
            if identity.user_hash is not None
            else cancellation_user_fingerprint(identity.pid, identity.user)
            if identity.user is not None
            else None
        ),
    )


def _acknowledge_cancellation_generation(
    directory: Path,
    agent_id: str,
    request_id: str,
) -> None:
    verified = _prepare_verified_cancellation_directory(directory)
    try:
        _atomic_write_json_verified(
            verified,
            directory,
            _cancellation_acknowledgement_path(directory, agent_id).name,
            {
                "protocol_version": CANCELLATION_PROTOCOL_VERSION,
                "agent_id": agent_id,
                "request_id": request_id,
            },
            temporary_prefix=".cancel-clear-",
        )
    finally:
        verified.close()


def write_cancellation_request(
    directory: Path,
    agent_id: str,
    *,
    target_identity: ProcessIdentity,
    registration_nonce: str,
    plan_id: str,
    requested_at: datetime | None = None,
    expires_at: datetime,
    publication_guard: Callable[[], None] | None = None,
) -> Path:
    """Atomically publish one process- and registration-bound cancellation."""
    request_time = _utc_now(requested_at)
    expiry = _utc_now(expires_at)
    lifetime_seconds = (expiry - request_time).total_seconds()
    if not 0 < lifetime_seconds <= CANCELLATION_REQUEST_LIFETIME_SECONDS:
        raise ValueError("cancellation lifetime must be between zero and thirty seconds")
    if not registration_nonce.strip() or not plan_id.strip():
        raise ValueError("registration nonce and plan ID must be non-empty")
    target = _cancellation_path(directory, agent_id)
    request_id = uuid.uuid4().hex
    payload = {
        "protocol_version": CANCELLATION_PROTOCOL_VERSION,
        "agent_id": agent_id,
        "registration_nonce": registration_nonce,
        "plan_id": plan_id,
        "request_id": request_id,
        "target": _cancellation_target(target_identity).model_dump(mode="json"),
        "requested_at": _format_timestamp(request_time),
        "expires_at": _format_timestamp(expiry),
    }
    published = False

    def mark_published() -> None:
        nonlocal published
        published = True

    try:
        verified = _prepare_verified_cancellation_directory(directory)
    except OSError as error:
        raise CancellationNotPublishedError(
            "cancellation directory could not be prepared safely because of a "
            "redirect, reparse point, link, ownership, or permission failure"
        ) from error
    try:
        _atomic_write_json_verified(
            verified,
            directory,
            target.name,
            payload,
            temporary_prefix=".cancel-",
            before_replace=publication_guard,
            after_replace=mark_published,
        )
        if publication_guard is not None:
            publication_guard()
    except BaseException as error:
        if published:
            try:
                _acknowledge_cancellation_generation(directory, agent_id, request_id)
            except BaseException as acknowledgement_error:
                raise CancellationPublicationUncertainError(
                    "a published cancellation could not be acknowledged safely"
                ) from acknowledgement_error
            raise CancellationPublicationUncertainError(
                "a published cancellation required compensating acknowledgement"
            ) from error
        if isinstance(error, CancellationNotPublishedError):
            raise
        raise CancellationNotPublishedError(
            "cancellation request replacement failed before publication"
        ) from error
    finally:
        verified.close()
    return target


def _load_cancellation_request(
    directory: Path,
    agent_id: str,
) -> CancellationRequest | None:
    target = _cancellation_path(directory, agent_id)
    verified: _VerifiedLeaseDirectory | None = None
    try:
        verified = _open_verified_lease_directory(directory)
        _verify_cancellation_directory_permissions(verified, directory)
        verified.verify()
        path_stat = (
            os.stat(target.name, dir_fd=verified.directory_fd, follow_symlinks=False)
            if verified.directory_fd is not None
            else target.stat(follow_symlinks=False)
        )
        if not stat.S_ISREG(path_stat.st_mode):
            return None
        data = _read_regular_file(
            target if verified.directory_fd is None else Path(target.name),
            path_stat,
            max_bytes=MAX_CANCELLATION_BYTES,
            directory_fd=verified.directory_fd,
        )
        verified.verify()
        envelope = _DiskCancellationRequest.model_validate(json.loads(data))
        if envelope.agent_id != agent_id:
            return None
        return CancellationRequest(
            protocol_version=envelope.protocol_version,
            agent_id=envelope.agent_id,
            registration_nonce=envelope.registration_nonce,
            plan_id=envelope.plan_id,
            request_id=envelope.request_id,
            target=envelope.target,
            requested_at=_parse_timestamp(envelope.requested_at),
            expires_at=_parse_timestamp(envelope.expires_at),
        )
    except (
        FileNotFoundError,
        OSError,
        OverflowError,
        RecursionError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValidationError,
        ValueError,
    ):
        return None
    finally:
        if verified is not None:
            verified.close()


def _load_cancellation_acknowledgement(
    directory: Path,
    agent_id: str,
) -> _DiskCancellationAcknowledgement | None:
    target = _cancellation_acknowledgement_path(directory, agent_id)
    verified: _VerifiedLeaseDirectory | None = None
    try:
        verified = _open_verified_lease_directory(directory)
        _verify_cancellation_directory_permissions(verified, directory)
        verified.verify()
        path_stat = (
            os.stat(target.name, dir_fd=verified.directory_fd, follow_symlinks=False)
            if verified.directory_fd is not None
            else target.stat(follow_symlinks=False)
        )
        if not stat.S_ISREG(path_stat.st_mode):
            return None
        data = _read_regular_file(
            target if verified.directory_fd is None else Path(target.name),
            path_stat,
            max_bytes=MAX_CANCELLATION_BYTES,
            directory_fd=verified.directory_fd,
        )
        verified.verify()
        acknowledgement = _DiskCancellationAcknowledgement.model_validate(json.loads(data))
        if acknowledgement.agent_id != agent_id:
            return None
        return acknowledgement
    except (
        FileNotFoundError,
        OSError,
        OverflowError,
        RecursionError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValidationError,
        ValueError,
    ):
        return None
    finally:
        if verified is not None:
            verified.close()


def observe_cancellation_request(
    directory: Path,
    agent_id: str,
    *,
    observer_identity: ProcessIdentity,
    registration_nonce: str,
    now: datetime | None = None,
) -> CancellationRequest | None:
    """Return only a live request bound to this SDK registration and process."""
    request = _load_cancellation_request(directory, agent_id)
    if request is None:
        return None
    observed_at = _utc_now(now)
    if (
        request.registration_nonce != registration_nonce
        or request.target != _cancellation_target(observer_identity)
        or request.requested_at > observed_at
        or request.expires_at <= observed_at
        or request.expires_at <= request.requested_at
        or (request.expires_at - request.requested_at).total_seconds()
        > CANCELLATION_REQUEST_LIFETIME_SECONDS
    ):
        return None
    acknowledgement = _load_cancellation_acknowledgement(directory, agent_id)
    if acknowledgement is not None and acknowledgement.request_id == request.request_id:
        return None
    return request


def read_cancellation_request(
    directory: Path,
    agent_id: str,
    *,
    observer_identity: ProcessIdentity,
    registration_nonce: str,
    now: datetime | None = None,
) -> CancellationRequest | None:
    """Read a cooperative request using the same fail-closed observation policy."""
    return observe_cancellation_request(
        directory,
        agent_id,
        observer_identity=observer_identity,
        registration_nonce=registration_nonce,
        now=now,
    )


def clear_cancellation_request(
    directory: Path,
    agent_id: str,
    *,
    observer_identity: ProcessIdentity,
    registration_nonce: str,
    now: datetime | None = None,
) -> bool:
    """Atomically acknowledge one request generation without deleting a newer one."""
    request = observe_cancellation_request(
        directory,
        agent_id,
        observer_identity=observer_identity,
        registration_nonce=registration_nonce,
        now=now,
    )
    if request is None:
        return False
    try:
        _acknowledge_cancellation_generation(
            directory,
            agent_id,
            request.request_id,
        )
    except OSError:
        return False
    return True
