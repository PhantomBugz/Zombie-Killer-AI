"""Manifest-scoped, reversible quarantine with fail-closed path validation.

POSIX file descriptors pin identity but cannot exclude a same-user writer. Directory
moves therefore revalidate the retained inventory after rename and report an ambiguous
interruption without moving a possibly rebound name when concurrent change is detected.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import platform
import secrets
import stat
import sys
import threading
from collections.abc import Callable
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from functools import partial
from pathlib import Path
from typing import Annotated, Any, Literal, Protocol, Self

from pydantic import Field, StringConstraints, model_validator

from zombie_killer_engine.models import (
    DisplayText,
    DomainModel,
    HashText,
    IdentifierText,
    PathText,
    ProcessIdentity,
    UtcDatetime,
)
from zombie_killer_engine.paths import (
    AppPaths,
    PosixPermissionBackend,
    WindowsPermissionBackend,
    _has_redirected_component,
    _is_reparse_point,
)
from zombie_killer_engine.redaction import redact_text

_PLAN_LIFETIME = timedelta(seconds=30)
_DEFAULT_RETENTION = timedelta(days=30)
_DEFAULT_MAX_ENTRIES = 1024
_DEFAULT_MAX_BYTES = 64 * 1024 * 1024
_DEFAULT_MAX_DEPTH = 16
_MAX_PINNED_FDS = 2048
_BUFFER_SIZE = 1024 * 1024

DeclarationSource = Annotated[
    Literal["sdk", "wrapper"],
    StringConstraints(strip_whitespace=True),
]
CleanupPolicy = Literal["quarantine"]


class CleanupRejectedError(ValueError):
    """A declaration or path failed cleanup authorization policy."""


class QuarantineError(RuntimeError):
    """A planned quarantine or restore could not be completed safely."""


class _DirectoryInventoryRolledBack(QuarantineError):
    """A post-move mismatch was atomically returned to its original namespace."""


class _DirectoryRollbackAmbiguous(QuarantineError):
    """A post-move mismatch could not be proven safely rolled back."""


class ResourceType(StrEnum):
    FILE = "file"
    DIRECTORY = "directory"
    LISTENING_PORT = "listening_port"


class QuarantineState(StrEnum):
    PLANNED = "planned"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"
    INTERRUPTED = "interrupted"
    RESTORED = "restored"


class LegacyRecoveryReason(StrEnum):
    MISSING_MANIFEST_AUTHORITY = "missing_manifest_authority"
    CORRUPT_PLAN_JSON = "corrupt_plan_json"
    MISSING_QUARANTINE_ENTRY = "missing_quarantine_entry"


class QuarantineResult(StrEnum):
    QUARANTINED = "quarantined"
    RESTORED = "restored"
    ALREADY_RESTORED = "already_restored"
    FAILED = "failed"
    PARTIAL = "partial"
    INTERRUPTED = "interrupted"


class ResourceFingerprint(DomainModel):
    """Stable identity and bounded content evidence for one declared resource."""

    device: int = Field(ge=0)
    inode: int = Field(ge=0)
    owner: IdentifierText
    resource_type: ResourceType
    mode: int = Field(ge=0)
    size: int = Field(ge=0)
    mtime_ns: int = Field(ge=0)
    ctime_ns: int = Field(ge=0)
    attributes: int = Field(ge=0)
    link_count: int = Field(gt=0)
    sha256: HashText | None = None
    inventory_digest: HashText | None = None
    entry_count: int = Field(default=1, ge=0)
    total_bytes: int = Field(default=0, ge=0)


class PathComponentIdentity(DomainModel):
    """No-follow identity for one root or ancestor directory."""

    relative_path: str = Field(min_length=1, max_length=4096)
    device: int = Field(ge=0)
    inode: int = Field(ge=0)
    owner: IdentifierText
    mode: int = Field(ge=0)


class CleanupAuthority(DomainModel):
    """Exact key resolved against SDK/wrapper-owned registration state."""

    manifest_id: IdentifierText
    manifest_digest: HashText
    agent_id: IdentifierText
    creating_identity: ProcessIdentity
    approved_root: PathText
    target: PathText
    resource_type: ResourceType
    declaration_source: DeclarationSource
    cleanup_policy: CleanupPolicy
    created_at: UtcDatetime
    expires_at: UtcDatetime


class RegistrationResolver(Protocol):
    def __call__(self, authority: CleanupAuthority) -> bool: ...


class InMemoryCleanupRegistry:
    """Thread-safe authoritative registry suitable for SDK/wrapper integrations."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._keys: set[str] = set()

    @staticmethod
    def _key(authority: CleanupAuthority) -> str:
        return hashlib.sha256(
            json.dumps(
                authority.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()

    def register(self, manifest: CleanupManifest) -> None:
        authority = _authority_from_manifest(manifest)
        with self._lock:
            self._keys.add(self._key(authority))

    def unregister(self, manifest: CleanupManifest) -> None:
        authority = _authority_from_manifest(manifest)
        with self._lock:
            self._keys.discard(self._key(authority))

    def clear(self) -> None:
        with self._lock:
            self._keys.clear()

    def __call__(self, authority: CleanupAuthority) -> bool:
        with self._lock:
            return self._key(authority) in self._keys


def _canonical_payload(values: dict[str, Any]) -> bytes:
    immutable = {key: value for key, value in values.items() if key not in {"digest", "state"}}
    return json.dumps(
        immutable,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
        default=lambda value: value.isoformat() if isinstance(value, datetime) else str(value),
    ).encode("utf-8")


def _new_id() -> str:
    return secrets.token_urlsafe(24)


def _path_hash(kind: str, path: str | Path) -> str:
    canonical = os.path.normcase(os.path.abspath(os.fspath(path)))
    return hashlib.sha256(f"{kind}\0{canonical}".encode()).hexdigest()


class CleanupManifest(DomainModel):
    """An SDK/wrapper declaration granting narrow cleanup authority."""

    manifest_id: IdentifierText
    agent_id: IdentifierText
    creating_identity: ProcessIdentity
    approved_root: PathText
    target: PathText
    resource_type: ResourceType
    declaration_source: DeclarationSource
    cleanup_policy: CleanupPolicy = "quarantine"
    managed: bool
    created_at: UtcDatetime
    expires_at: UtcDatetime
    digest: HashText

    @model_validator(mode="after")
    def validate_authority(self) -> Self:
        if not self.managed:
            raise ValueError("only exact managed resource declarations are cleanable")
        if self.creating_identity.executable is None or self.creating_identity.user is None:
            raise ValueError("creating process identity is incomplete")
        if self.expires_at - self.created_at != _PLAN_LIFETIME:
            raise ValueError("cleanup manifest lifetime must be exactly thirty seconds")
        if not self.verify_digest():
            raise ValueError("cleanup manifest digest does not match immutable fields")
        return self

    def verify_digest(self) -> bool:
        expected = hashlib.sha256(_canonical_payload(self.model_dump(mode="json"))).hexdigest()
        return secrets.compare_digest(self.digest, expected)

    @classmethod
    def create(
        cls,
        *,
        agent_id: str,
        creating_identity: ProcessIdentity,
        approved_root: str | Path,
        target: str | Path,
        resource_type: ResourceType,
        declaration_source: DeclarationSource,
        cleanup_policy: CleanupPolicy = "quarantine",
        managed: bool,
        created_at: datetime | None = None,
        manifest_id: str | None = None,
    ) -> CleanupManifest:
        created = created_at or datetime.now(UTC)
        if created.tzinfo is None or created.utcoffset() is None:
            raise ValueError("created_at must be timezone-aware")
        values: dict[str, Any] = {
            "manifest_id": manifest_id or _new_id(),
            "agent_id": agent_id,
            "creating_identity": creating_identity,
            "approved_root": os.fspath(approved_root),
            "target": os.fspath(target),
            "resource_type": resource_type,
            "declaration_source": declaration_source,
            "cleanup_policy": cleanup_policy,
            "managed": managed,
            "created_at": created.astimezone(UTC),
            "expires_at": (created + _PLAN_LIFETIME).astimezone(UTC),
            "digest": "0" * 64,
        }
        unsigned = cls.model_construct(**values)
        values["digest"] = hashlib.sha256(
            _canonical_payload(unsigned.model_dump(mode="json"))
        ).hexdigest()
        return cls(**values)


def _authority_from_manifest(manifest: CleanupManifest) -> CleanupAuthority:
    return CleanupAuthority(
        manifest_id=manifest.manifest_id,
        manifest_digest=manifest.digest,
        agent_id=manifest.agent_id,
        creating_identity=manifest.creating_identity,
        approved_root=manifest.approved_root,
        target=manifest.target,
        resource_type=manifest.resource_type,
        declaration_source=manifest.declaration_source,
        cleanup_policy=manifest.cleanup_policy,
        created_at=manifest.created_at,
        expires_at=manifest.expires_at,
    )


class QuarantinePlan(DomainModel):
    """Short-lived, tamper-evident authorization for one exact resource."""

    plan_id: IdentifierText
    correlation_id: IdentifierText
    manifest_id: IdentifierText
    manifest_digest: HashText
    manifest_created_at: UtcDatetime
    manifest_expires_at: UtcDatetime
    agent_id: IdentifierText
    creating_identity: ProcessIdentity
    declaration_source: DeclarationSource
    cleanup_policy: CleanupPolicy
    resource_type: ResourceType
    approved_root: PathText
    target: PathText
    relative_path: PathText
    root_hash: HashText
    target_hash: HashText
    fingerprint: ResourceFingerprint
    root_chain: tuple[PathComponentIdentity, ...] = Field(min_length=1, max_length=128)
    max_entries: int = Field(gt=0, le=100_000)
    max_bytes: int = Field(gt=0, le=10 * 1024 * 1024 * 1024)
    max_depth: int = Field(gt=0, le=128)
    created_at: UtcDatetime
    expires_at: UtcDatetime
    state: QuarantineState = QuarantineState.PLANNED
    digest: HashText

    @model_validator(mode="after")
    def validate_plan(self) -> Self:
        if self.resource_type is ResourceType.LISTENING_PORT:
            raise ValueError("listening ports are informational and not cleanable")
        if self.expires_at - self.created_at != _PLAN_LIFETIME:
            raise ValueError("quarantine plan lifetime must be exactly thirty seconds")
        if self.manifest_expires_at - self.manifest_created_at != _PLAN_LIFETIME:
            raise ValueError("manifest authority lifetime must be exactly thirty seconds")
        if self.created_at < self.manifest_created_at:
            raise ValueError("quarantine plan cannot predate its manifest authority")
        if not self.verify_digest():
            raise ValueError("quarantine plan digest does not match immutable fields")
        return self

    def verify_digest(self) -> bool:
        expected = hashlib.sha256(_canonical_payload(self.model_dump(mode="json"))).hexdigest()
        return secrets.compare_digest(self.digest, expected)


class LegacyRestorePlan(DomainModel):
    """Validated v5 evidence usable only to restore an existing journal entry."""

    plan_id: IdentifierText
    correlation_id: IdentifierText
    manifest_id: IdentifierText
    manifest_digest: HashText
    agent_id: IdentifierText
    creating_identity: ProcessIdentity
    declaration_source: DeclarationSource
    cleanup_policy: CleanupPolicy
    resource_type: ResourceType
    approved_root: PathText
    target: PathText
    relative_path: PathText
    root_hash: HashText
    target_hash: HashText
    fingerprint: ResourceFingerprint
    root_chain: tuple[PathComponentIdentity, ...] = Field(min_length=1, max_length=128)
    max_entries: int = Field(gt=0, le=100_000)
    max_bytes: int = Field(gt=0, le=10 * 1024 * 1024 * 1024)
    max_depth: int = Field(gt=0, le=128)
    created_at: UtcDatetime
    expires_at: UtcDatetime
    state: QuarantineState = QuarantineState.PLANNED
    digest: HashText

    @model_validator(mode="after")
    def validate_legacy_evidence(self) -> Self:
        if self.resource_type is ResourceType.LISTENING_PORT:
            raise ValueError("legacy listening ports are not restoreable")
        if self.expires_at - self.created_at != _PLAN_LIFETIME:
            raise ValueError("legacy plan lifetime is invalid")
        if not self.verify_digest():
            raise ValueError("legacy plan digest does not match preserved evidence")
        return self

    def verify_digest(self) -> bool:
        expected = hashlib.sha256(_canonical_payload(self.model_dump(mode="json"))).hexdigest()
        return secrets.compare_digest(self.digest, expected)


RestorePlan = QuarantinePlan | LegacyRestorePlan


def _authority_from_plan(plan: QuarantinePlan) -> CleanupAuthority:
    return CleanupAuthority(
        manifest_id=plan.manifest_id,
        manifest_digest=plan.manifest_digest,
        agent_id=plan.agent_id,
        creating_identity=plan.creating_identity,
        approved_root=plan.approved_root,
        target=plan.target,
        resource_type=plan.resource_type,
        declaration_source=plan.declaration_source,
        cleanup_policy=plan.cleanup_policy,
        created_at=plan.manifest_created_at,
        expires_at=plan.manifest_expires_at,
    )


class QuarantineEntry(DomainModel):
    """Restricted local restore metadata; raw paths never enter generic audit data."""

    entry_id: IdentifierText
    plan_id: IdentifierText
    correlation_id: IdentifierText
    agent_id: IdentifierText
    creating_identity: ProcessIdentity
    resource_type: ResourceType
    approved_root: PathText
    original_path: PathText
    original_relative_path: PathText
    quarantine_path: PathText
    root_hash: HashText
    original_path_hash: HashText
    quarantine_path_hash: HashText
    fingerprint: ResourceFingerprint
    state: QuarantineState
    created_at: UtcDatetime
    updated_at: UtcDatetime
    retention_until: UtcDatetime
    receipt_ids: tuple[IdentifierText, ...] = Field(default=(), max_length=64)
    restored_at: UtcDatetime | None = None
    digest: HashText

    @model_validator(mode="after")
    def validate_digest(self) -> Self:
        if not self.verify_digest():
            raise ValueError("quarantine entry digest does not match immutable fields")
        return self

    def verify_digest(self) -> bool:
        immutable = self.immutable_fields()
        expected = hashlib.sha256(
            json.dumps(
                immutable,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        return secrets.compare_digest(self.digest, expected)

    def immutable_fields(self) -> dict[str, Any]:
        values = self.model_dump(mode="json")
        return {
            key: value
            for key, value in values.items()
            if key
            not in {
                "digest",
                "state",
                "updated_at",
                "receipt_ids",
                "restored_at",
            }
        }


class QuarantineReceipt(DomainModel):
    """Path-free allowlisted audit result for quarantine or restore."""

    receipt_id: IdentifierText
    audit_event_id: IdentifierText
    correlation_id: IdentifierText
    plan_id: IdentifierText
    entry_id: IdentifierText | None = None
    operation: Literal["quarantine", "restore"]
    result: QuarantineResult
    actor_hash: HashText
    session_hash: HashText
    agent_hash: HashText
    root_hash: HashText
    target_hash: HashText
    content_hash: HashText | None = None
    size: int = Field(ge=0)
    entry_count: int = Field(ge=0)
    started_at: UtcDatetime
    finished_at: UtcDatetime
    message: DisplayText

    @model_validator(mode="after")
    def timestamps_ordered(self) -> Self:
        if self.finished_at < self.started_at:
            raise ValueError("receipt finish time cannot precede start time")
        return self


class QuarantineStore(Protocol):
    session_id: str

    def save_quarantine_plan(self, plan: QuarantinePlan) -> None: ...

    def claim_quarantine_plan(self, plan_id: str, *, expected_digest: str) -> QuarantinePlan: ...

    def update_quarantine_plan_phase(self, plan_id: str, phase: str) -> None: ...

    def get_quarantine_entry_for_plan(self, plan_id: str) -> QuarantineEntry | None: ...

    def get_quarantine_entry(self, entry_id: str) -> QuarantineEntry | None: ...

    def claim_quarantine_restore(self, entry_id: str) -> QuarantineEntry: ...

    def preflight_quarantine_restore(self, entry_id: str) -> None: ...

    def release_quarantine_restore(self, entry_id: str) -> None: ...

    def get_quarantine_plan(self, plan_id: str) -> QuarantinePlan | None: ...

    def get_legacy_restore_plan(
        self, entry_id: str, *, expected_entry_digest: str
    ) -> tuple[LegacyRestorePlan, QuarantineEntry]: ...

    def get_quarantine_recovery(
        self, plan_id: str, *, expected_digest: str
    ) -> tuple[QuarantinePlan, str] | None: ...

    def reset_quarantine_plan_for_retry(
        self, plan_id: str, *, entry: QuarantineEntry | None
    ) -> None: ...

    def save_quarantine_entry(self, entry: QuarantineEntry) -> None: ...

    def get_quarantine_receipt_for_plan(
        self, plan_id: str, *, expected_digest: str
    ) -> QuarantineReceipt | None: ...

    def finish_quarantine_plan(
        self,
        plan_id: str,
        *,
        state: QuarantineState,
        receipt: QuarantineReceipt,
        entry: QuarantineEntry | None,
    ) -> None: ...

    def save_quarantine_receipt(
        self, receipt: QuarantineReceipt, *, entry: QuarantineEntry | None
    ) -> None: ...

    def get_quarantine_receipt_for_entry(
        self,
        entry_id: str,
        *,
        operation: Literal["quarantine", "restore"],
        result: QuarantineResult,
    ) -> QuarantineReceipt | None: ...


ReparseChecker = Callable[[Path, os.stat_result], bool]


def _default_reparse_checker(_path: Path, path_stat: os.stat_result) -> bool:
    return _is_reparse_point(path_stat)


def _reject_lexical_path(path: str | Path, *, platform_name: str) -> Path:
    raw = os.fspath(path)
    if not raw or "\x00" in raw:
        raise CleanupRejectedError("cleanup path is empty or invalid")
    parsed = Path(raw)
    if not parsed.is_absolute():
        raise CleanupRejectedError("cleanup paths must be absolute")
    if any(part == ".." for part in parsed.parts):
        raise CleanupRejectedError("cleanup paths cannot contain traversal")
    if any(character in raw for character in ("*", "?", "[", "]")):
        raise CleanupRejectedError("cleanup paths cannot contain glob syntax")
    if platform_name.casefold().startswith("win"):
        normalized = raw.replace("/", "\\")
        if normalized.startswith(("\\\\", "\\?\\", "\\.\\")):
            raise CleanupRejectedError("network and device paths are not cleanable")
        drive, tail = os.path.splitdrive(raw)
        if not drive or ":" in tail:
            raise CleanupRejectedError("alternate streams and non-local paths are rejected")
    return Path(os.path.abspath(raw))


def _strict_relative(target: Path, root: Path) -> Path:
    try:
        relative = target.relative_to(root)
    except ValueError as error:
        raise CleanupRejectedError("target is outside its approved root") from error
    if not relative.parts or relative == Path("."):
        raise CleanupRejectedError("the approved root itself cannot be quarantined")
    return relative


def _chain_to(path: Path) -> tuple[Path, ...]:
    absolute = Path(os.path.abspath(path))
    anchor = Path(absolute.anchor)
    components: list[Path] = [anchor]
    current = anchor
    for part in absolute.parts[1:]:
        current /= part
        components.append(current)
    return tuple(components)


def _validate_component_chain(
    path: Path,
    *,
    reparse_checker: ReparseChecker,
    must_exist: bool,
) -> tuple[os.stat_result, ...]:
    inspected: list[os.stat_result] = []
    for index, component in enumerate(_chain_to(path)):
        try:
            current = os.lstat(component)
        except FileNotFoundError as error:
            if not must_exist and index == len(_chain_to(path)) - 1:
                break
            raise CleanupRejectedError("cleanup path component does not exist") from error
        if stat.S_ISLNK(current.st_mode) or reparse_checker(component, current):
            raise CleanupRejectedError("redirected path components are rejected")
        inspected.append(current)
    return tuple(inspected)


def _validate_root(
    root: Path,
    *,
    reparse_checker: ReparseChecker,
) -> os.stat_result:
    _validate_component_chain(root, reparse_checker=reparse_checker, must_exist=True)
    try:
        root_stat = os.lstat(root)
    except OSError as error:
        raise CleanupRejectedError("approved root cannot be inspected") from error
    if not stat.S_ISDIR(root_stat.st_mode):
        raise CleanupRejectedError("approved root is not a direct directory")
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None:
        if root_stat.st_uid != int(geteuid()):
            raise CleanupRejectedError("approved root is not owned by the current user")
        if stat.S_IMODE(root_stat.st_mode) & 0o022:
            raise CleanupRejectedError("approved root is writable by another user")
    elif os.name == "nt" and not secrets.compare_digest(
        _windows_owner_sid(root, expected_inode=int(root_stat.st_ino)),
        _windows_current_user_sid(),
    ):
        raise CleanupRejectedError("approved root is not owned by the current user")
    if os.name == "nt":
        handle = _windows_open_handle(root, access=0x00020000)
        try:
            _windows_assert_root_acl(handle)
        finally:
            ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(handle)
    return root_stat


def _same_stat(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        left.st_mode,
        left.st_size,
        left.st_mtime_ns,
        left.st_nlink,
    ) == (
        right.st_dev,
        right.st_ino,
        right.st_mode,
        right.st_size,
        right.st_mtime_ns,
        right.st_nlink,
    )


def _hash_regular_file(path: Path, expected: os.stat_result, *, max_bytes: int) -> str:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not _same_stat(expected, opened) or not stat.S_ISREG(opened.st_mode):
            raise CleanupRejectedError("file identity changed while hashing")
        digest = hashlib.sha256()
        hashed = 0
        while chunk := os.read(descriptor, _BUFFER_SIZE):
            hashed += len(chunk)
            if hashed > max_bytes:
                raise CleanupRejectedError("file changed beyond its byte quota")
            digest.update(chunk)
        after = os.fstat(descriptor)
        if not _same_stat(opened, after):
            raise CleanupRejectedError("file changed while hashing")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _sid_text(sid: ctypes.c_void_p) -> str:
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    rendered = ctypes.c_wchar_p()
    advapi32.ConvertSidToStringSidW.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_wchar_p),
    )
    if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(rendered)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        value = rendered.value
        if not value:
            raise OSError("Windows owner SID is empty")
        return value
    finally:
        kernel32.LocalFree(rendered)


def _windows_owner_sid(path: Path, *, expected_inode: int | None = None) -> str:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32.CreateFileW.restype = ctypes.c_void_p
    handle = kernel32.CreateFileW(
        str(path),
        0x00020080,  # READ_CONTROL | FILE_READ_ATTRIBUTES
        0x00000007,
        None,
        3,
        0x02200000,  # BACKUP_SEMANTICS | OPEN_REPARSE_POINT
        None,
    )
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    owner = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    advapi32.GetSecurityInfo.argtypes = (
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    )
    try:
        result = advapi32.GetSecurityInfo(
            handle,
            1,  # SE_FILE_OBJECT
            1,  # OWNER_SECURITY_INFORMATION
            ctypes.byref(owner),
            None,
            None,
            None,
            ctypes.byref(descriptor),
        )
        if result != 0:
            raise ctypes.WinError(result)
        if _is_reparse_point(os.lstat(path)):
            raise CleanupRejectedError("owner handle resolved a reparse point")
        information = _windows_handle_information(int(handle))
        opened_inode = (information.file_index_high << 32) | information.file_index_low
        if expected_inode is not None and opened_inode != expected_inode:
            raise CleanupRejectedError("owner handle identity changed")
        return _sid_text(owner)
    finally:
        if descriptor:
            kernel32.LocalFree(descriptor)
        kernel32.CloseHandle(handle)


def _windows_current_user_sid() -> str:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    advapi32.OpenProcessToken.argtypes = (
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_void_p),
    )
    advapi32.GetTokenInformation.argtypes = (
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_ulong),
    )
    token = ctypes.c_void_p()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x00000008, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        size = ctypes.c_ulong()
        advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        if size.value == 0:
            raise ctypes.WinError(ctypes.get_last_error())
        buffer = ctypes.create_string_buffer(size.value)
        if not advapi32.GetTokenInformation(token, 1, buffer, size.value, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        sid = ctypes.c_void_p.from_buffer(buffer).value
        if sid is None:
            raise OSError("current user SID is unavailable")
        return _sid_text(ctypes.c_void_p(sid))
    finally:
        kernel32.CloseHandle(token)


def _owner(path: Path, path_stat: os.stat_result) -> str:
    if os.name == "nt":
        return _windows_owner_sid(path, expected_inode=int(path_stat.st_ino))
    return f"uid:{getattr(path_stat, 'st_uid', 0)}"


def _component_identity(path: Path, root: Path) -> PathComponentIdentity:
    path_stat = os.lstat(path)
    relative = "." if path == root else path.relative_to(root).as_posix()
    return PathComponentIdentity(
        relative_path=relative,
        device=int(path_stat.st_dev),
        inode=int(path_stat.st_ino),
        owner=_owner(path, path_stat),
        mode=int(path_stat.st_mode),
    )


def _file_fingerprint(
    path: Path, path_stat: os.stat_result, *, max_entries: int, max_bytes: int
) -> ResourceFingerprint:
    if not stat.S_ISREG(path_stat.st_mode):
        raise CleanupRejectedError("declared file is not a regular file")
    if path_stat.st_nlink != 1:
        raise CleanupRejectedError("hard-linked files are refused conservatively")
    if max_entries < 1:
        raise CleanupRejectedError("file entry quota exceeded")
    if int(path_stat.st_size) > max_bytes:
        raise CleanupRejectedError("file byte quota exceeded")
    digest = _hash_regular_file(path, path_stat, max_bytes=max_bytes)
    return ResourceFingerprint(
        device=int(path_stat.st_dev),
        inode=int(path_stat.st_ino),
        owner=_owner(path, path_stat),
        resource_type=ResourceType.FILE,
        mode=int(path_stat.st_mode),
        size=int(path_stat.st_size),
        mtime_ns=int(path_stat.st_mtime_ns),
        ctime_ns=int(path_stat.st_ctime_ns),
        attributes=int(getattr(path_stat, "st_file_attributes", 0)),
        link_count=int(path_stat.st_nlink),
        sha256=digest,
        entry_count=1,
        total_bytes=int(path_stat.st_size),
    )


def _directory_fingerprint(
    path: Path,
    path_stat: os.stat_result,
    *,
    root_device: int,
    reparse_checker: ReparseChecker,
    max_entries: int,
    max_bytes: int,
    max_depth: int,
) -> ResourceFingerprint:
    if not stat.S_ISDIR(path_stat.st_mode):
        raise CleanupRejectedError("declared directory is not a direct directory")
    handles: list[int] = []
    validators: list[Callable[[], None]] = []
    try:
        if os.name == "nt":
            directory_handle = _windows_open_handle(
                path,
                access=0x00020081,
                share=0x00000007,
            )
            handles.append(directory_handle)
            if _windows_inode(directory_handle) != int(path_stat.st_ino):
                raise CleanupRejectedError("directory identity changed during preview")
            inventory_device = int(
                _windows_handle_information(directory_handle).volume_serial_number
            )
        else:
            directory_handle = os.open(
                path,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
            handles.append(directory_handle)
            if not _same_stat(path_stat, os.fstat(directory_handle)):
                raise CleanupRejectedError("directory identity changed during preview")
            inventory_device = root_device
        inventory, total_bytes = _inventory_directory_handle(
            directory_handle,
            logical_root=path,
            root_device=inventory_device,
            max_entries=max_entries,
            max_bytes=max_bytes,
            max_depth=max_depth,
            handles=handles,
            validators=validators,
            windows_share=0x00000007,
            reparse_checker=reparse_checker,
        )
    finally:
        _close_native_handles(handles)
    inventory_digest = _inventory_digest(inventory)
    return ResourceFingerprint(
        device=int(path_stat.st_dev),
        inode=int(path_stat.st_ino),
        owner=_owner(path, path_stat),
        resource_type=ResourceType.DIRECTORY,
        mode=int(path_stat.st_mode),
        size=int(path_stat.st_size),
        mtime_ns=int(path_stat.st_mtime_ns),
        ctime_ns=int(path_stat.st_ctime_ns),
        attributes=int(getattr(path_stat, "st_file_attributes", 0)),
        link_count=int(path_stat.st_nlink),
        inventory_digest=inventory_digest,
        entry_count=len(inventory),
        total_bytes=total_bytes,
    )


def _fingerprint(
    path: Path,
    resource_type: ResourceType,
    *,
    root_device: int,
    reparse_checker: ReparseChecker,
    max_entries: int,
    max_bytes: int,
    max_depth: int,
) -> ResourceFingerprint:
    try:
        path_stat = os.lstat(path)
    except OSError as error:
        raise CleanupRejectedError("declared target cannot be inspected") from error
    if stat.S_ISLNK(path_stat.st_mode) or reparse_checker(path, path_stat):
        raise CleanupRejectedError("redirected targets are rejected")
    if int(path_stat.st_dev) != root_device or os.path.ismount(path):
        raise CleanupRejectedError("target crosses a mount boundary")
    if resource_type is ResourceType.FILE:
        return _file_fingerprint(
            path,
            path_stat,
            max_entries=max_entries,
            max_bytes=max_bytes,
        )
    if resource_type is ResourceType.DIRECTORY:
        return _directory_fingerprint(
            path,
            path_stat,
            root_device=root_device,
            reparse_checker=reparse_checker,
            max_entries=max_entries,
            max_bytes=max_bytes,
            max_depth=max_depth,
        )
    raise CleanupRejectedError("listening ports cannot be cleaned independently")


def _open_posix_preview_binding(
    root: Path,
    target: Path,
    root_stat: os.stat_result,
    resource_type: ResourceType,
) -> tuple[list[int], list[Callable[[], None]], int]:
    """Pin the preview namespace with openat2 and reject mount crossings."""
    handles: list[int] = []
    validators: list[Callable[[], None]] = []
    bindings: list[Callable[[], None]] = []
    expected_root = PathComponentIdentity(
        relative_path=".",
        device=int(root_stat.st_dev),
        inode=int(root_stat.st_ino),
        owner=_owner(root, root_stat),
        mode=int(root_stat.st_mode),
    )
    try:
        parent = _open_posix_directory_chain(
            target.parent,
            handles=handles,
            validators=validators,
            binding_validators=bindings,
            expected={root: expected_root},
            no_xdev_from=root,
            label="preview path",
        )
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        if resource_type is ResourceType.DIRECTORY:
            flags |= getattr(os, "O_DIRECTORY", 0)
        target_handle = _open_posix_child(
            parent,
            target.name,
            flags,
            no_xdev=True,
        )
        handles.append(target_handle)
        target_stat = os.fstat(target_handle)
        target_binding = partial(
            _assert_posix_name_binding,
            parent,
            target.name,
            int(target_stat.st_dev),
            int(target_stat.st_ino),
        )
        target_binding()
        validators.extend(bindings)
        validators.append(target_binding)
        return handles, validators, target_handle
    except BaseException:
        _close_native_handles(handles)
        raise


def _validate_posix_preview_binding(
    validators: list[Callable[[], None]],
    target_handle: int,
    fingerprint: ResourceFingerprint,
    max_bytes: int,
) -> None:
    for validator in validators:
        validator()
    observed = os.fstat(target_handle)
    if (
        int(observed.st_dev) != fingerprint.device
        or int(observed.st_ino) != fingerprint.inode
        or f"uid:{observed.st_uid}" != fingerprint.owner
        or int(observed.st_mode) != fingerprint.mode
        or int(observed.st_size) != fingerprint.size
        or int(observed.st_mtime_ns) != fingerprint.mtime_ns
        or int(observed.st_ctime_ns) != fingerprint.ctime_ns
        or int(observed.st_nlink) != fingerprint.link_count
    ):
        raise CleanupRejectedError("preview target changed during fingerprinting")
    if fingerprint.resource_type is ResourceType.FILE:
        _assert_posix_file_fingerprint(
            target_handle,
            fingerprint,
            max_bytes,
            True,
        )


class QuarantinePlanner:
    """Validate one managed declaration and fingerprint its exact resource."""

    def __init__(
        self,
        approved_roots: tuple[str | Path, ...],
        *,
        registration_resolver: RegistrationResolver,
        platform_name: str | None = None,
        reparse_checker: ReparseChecker | None = None,
        max_entries: int = _DEFAULT_MAX_ENTRIES,
        max_bytes: int = _DEFAULT_MAX_BYTES,
        max_depth: int = _DEFAULT_MAX_DEPTH,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not approved_roots:
            raise ValueError("at least one explicit approved root is required")
        if max_entries <= 0 or max_bytes <= 0 or max_depth <= 0:
            raise ValueError("directory inventory quotas must be positive")
        self._platform_name = platform_name or platform.system()
        self._registration_resolver = registration_resolver
        self._reparse_checker = reparse_checker or _default_reparse_checker
        self._max_entries = max_entries
        self._max_bytes = max_bytes
        self._max_depth = max_depth
        self._clock = clock or (lambda: datetime.now(UTC))
        self._approved_roots = tuple(
            _reject_lexical_path(root, platform_name=self._platform_name) for root in approved_roots
        )

    def create_plan(self, manifest: CleanupManifest) -> QuarantinePlan:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("clock must return timezone-aware timestamps")
        if not manifest.verify_digest() or now >= manifest.expires_at:
            raise CleanupRejectedError("cleanup manifest is invalid or expired")
        if manifest.created_at > now:
            raise CleanupRejectedError("cleanup manifest was created in the future")
        if not manifest.managed:
            raise CleanupRejectedError("unmanaged resources are informational only")
        if not self._registration_resolver(_authority_from_manifest(manifest)):
            raise CleanupRejectedError("authoritative resource registration is missing")
        if manifest.resource_type is ResourceType.LISTENING_PORT:
            raise CleanupRejectedError("ports are informational and not independently cleanable")
        root = _reject_lexical_path(manifest.approved_root, platform_name=self._platform_name)
        target = _reject_lexical_path(manifest.target, platform_name=self._platform_name)
        approved = any(
            os.path.normcase(os.fspath(root)) == os.path.normcase(os.fspath(candidate))
            for candidate in self._approved_roots
        )
        if not approved:
            raise CleanupRejectedError("manifest root is not explicitly approved")
        relative = _strict_relative(target, root)
        root_stat = _validate_root(root, reparse_checker=self._reparse_checker)
        _validate_component_chain(target, reparse_checker=self._reparse_checker, must_exist=True)
        preview_handles: list[int] = []
        preview_validators: list[Callable[[], None]] = []
        preview_target: int | None = None
        try:
            if os.name != "nt":
                (
                    preview_handles,
                    preview_validators,
                    preview_target,
                ) = _open_posix_preview_binding(
                    root,
                    target,
                    root_stat,
                    manifest.resource_type,
                )
            fingerprint = _fingerprint(
                target,
                manifest.resource_type,
                root_device=int(root_stat.st_dev),
                reparse_checker=self._reparse_checker,
                max_entries=self._max_entries,
                max_bytes=self._max_bytes,
                max_depth=self._max_depth,
            )
            if preview_target is not None:
                _validate_posix_preview_binding(
                    preview_validators,
                    preview_target,
                    fingerprint,
                    self._max_bytes,
                )
        finally:
            _close_native_handles(preview_handles)
        chain_paths = [root]
        current = root
        for part in target.parent.relative_to(root).parts:
            current /= part
            chain_paths.append(current)
        root_chain = tuple(_component_identity(component, root) for component in chain_paths)
        values: dict[str, Any] = {
            "plan_id": _new_id(),
            "correlation_id": _new_id(),
            "manifest_id": manifest.manifest_id,
            "manifest_digest": manifest.digest,
            "manifest_created_at": manifest.created_at,
            "manifest_expires_at": manifest.expires_at,
            "agent_id": manifest.agent_id,
            "creating_identity": manifest.creating_identity,
            "declaration_source": manifest.declaration_source,
            "cleanup_policy": manifest.cleanup_policy,
            "resource_type": manifest.resource_type,
            "approved_root": os.fspath(root),
            "target": os.fspath(target),
            "relative_path": os.fspath(relative),
            "root_hash": _path_hash("root", root),
            "target_hash": _path_hash("target", target),
            "fingerprint": fingerprint,
            "root_chain": root_chain,
            "max_entries": self._max_entries,
            "max_bytes": self._max_bytes,
            "max_depth": self._max_depth,
            "created_at": now.astimezone(UTC),
            "expires_at": (now + _PLAN_LIFETIME).astimezone(UTC),
            "state": QuarantineState.PLANNED,
            "digest": "0" * 64,
        }
        unsigned = QuarantinePlan.model_construct(**values)
        values["digest"] = hashlib.sha256(
            _canonical_payload(unsigned.model_dump(mode="json"))
        ).hexdigest()
        return QuarantinePlan(**values)


def _same_fingerprint(left: ResourceFingerprint, right: ResourceFingerprint) -> bool:
    return secrets.compare_digest(
        hashlib.sha256(
            json.dumps(left.model_dump(mode="json"), sort_keys=True).encode()
        ).hexdigest(),
        hashlib.sha256(
            json.dumps(right.model_dump(mode="json"), sort_keys=True).encode()
        ).hexdigest(),
    )


def _same_fingerprint_after_rename(left: ResourceFingerprint, right: ResourceFingerprint) -> bool:
    left_values = left.model_dump(mode="json")
    right_values = right.model_dump(mode="json")
    # POSIX rename may update ctime even though identity and content are unchanged.
    left_values["ctime_ns"] = 0
    right_values["ctime_ns"] = 0
    return secrets.compare_digest(
        hashlib.sha256(json.dumps(left_values, sort_keys=True).encode()).hexdigest(),
        hashlib.sha256(json.dumps(right_values, sort_keys=True).encode()).hexdigest(),
    )


class _WindowsFileInformation(ctypes.Structure):
    _fields_ = (
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
    )


def _windows_handle_information(handle: int) -> _WindowsFileInformation:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetFileInformationByHandle.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(_WindowsFileInformation),
    )
    information = _WindowsFileInformation()
    if not kernel32.GetFileInformationByHandle(handle, ctypes.byref(information)):
        raise ctypes.WinError(ctypes.get_last_error())
    return information


def _windows_open_handle(path: Path, *, access: int, share: int = 0x00000007) -> int:
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
    handle = kernel32.CreateFileW(
        str(path),
        access,
        share,
        None,
        3,
        0x02200000,
        None,
    )
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    information = _windows_handle_information(handle)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if information.file_attributes & reparse_flag:
        kernel32.CloseHandle(handle)
        raise CleanupRejectedError("pinned path handle is a reparse point")
    return int(handle)


def _windows_owner_sid_from_handle(handle: int) -> str:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    owner = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    advapi32.GetSecurityInfo.argtypes = (
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    )
    result = advapi32.GetSecurityInfo(
        handle, 1, 1, ctypes.byref(owner), None, None, None, ctypes.byref(descriptor)
    )
    if result != 0:
        raise ctypes.WinError(result)
    try:
        return _sid_text(owner)
    finally:
        kernel32.LocalFree(descriptor)


def _windows_assert_root_acl(handle: int) -> None:
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    required = ctypes.c_ulong()
    security_information = 0x00000005  # OWNER | DACL
    advapi32.GetKernelObjectSecurity(
        handle,
        security_information,
        None,
        0,
        ctypes.byref(required),
    )
    if required.value == 0:
        raise ctypes.WinError(ctypes.get_last_error())
    descriptor = ctypes.create_string_buffer(required.value)
    if not advapi32.GetKernelObjectSecurity(
        handle,
        security_information,
        descriptor,
        required.value,
        ctypes.byref(required),
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    rendered = ctypes.c_wchar_p()
    if not advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
        descriptor,
        1,
        0x00000004,
        ctypes.byref(rendered),
        None,
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        sddl = rendered.value or ""
    finally:
        kernel32.LocalFree(rendered)
    owner_sid = _windows_owner_sid_from_handle(handle)
    trusted = {
        owner_sid,
        "SY",
        "BA",
        "OW",
        "S-1-5-18",
        "S-1-5-32-544",
        "S-1-3-4",
    }
    dangerous_mask = (
        0x10000000  # GENERIC_ALL
        | 0x40000000  # GENERIC_WRITE
        | 0x10000  # DELETE
        | 0x40000  # WRITE_DAC
        | 0x80000  # WRITE_OWNER
        | 0x2  # FILE_ADD_FILE / FILE_WRITE_DATA
        | 0x4  # FILE_ADD_SUBDIRECTORY / FILE_APPEND_DATA
        | 0x10  # FILE_WRITE_EA
        | 0x40  # FILE_DELETE_CHILD
        | 0x100  # FILE_WRITE_ATTRIBUTES
    )
    dangerous_tokens = (
        "GA",
        "GW",
        "FA",
        "FW",
        "WD",
        "WO",
        "DC",
        "AD",
        "WEA",
        "WA",
    )
    for raw_ace in sddl.split("(")[1:]:
        fields = raw_ace.split(")", 1)[0].split(";")
        if len(fields) < 6 or fields[0] not in {"A", "OA", "XA", "ZA"}:
            continue
        rights = fields[2]
        dangerous = any(token in rights for token in dangerous_tokens)
        if rights.startswith("0x"):
            with suppress(ValueError):
                dangerous = dangerous or bool(int(rights, 16) & dangerous_mask)
        if dangerous and fields[5] not in trusted:
            raise CleanupRejectedError(
                "approved root ACL grants destructive access to an untrusted principal"
            )


class _WindowsUnicodeString(ctypes.Structure):
    _fields_ = (
        ("length", ctypes.c_ushort),
        ("maximum_length", ctypes.c_ushort),
        ("buffer", ctypes.c_wchar_p),
    )


class _WindowsObjectAttributes(ctypes.Structure):
    _fields_ = (
        ("length", ctypes.c_ulong),
        ("root_directory", ctypes.c_void_p),
        ("object_name", ctypes.POINTER(_WindowsUnicodeString)),
        ("attributes", ctypes.c_ulong),
        ("security_descriptor", ctypes.c_void_p),
        ("security_qos", ctypes.c_void_p),
    )


class _WindowsIoStatusBlock(ctypes.Structure):
    _fields_ = (("status", ctypes.c_void_p), ("information", ctypes.c_size_t))


class _WindowsFileIdBothDirectoryInfo(ctypes.Structure):
    _fields_ = (
        ("next_entry_offset", ctypes.c_ulong),
        ("file_index", ctypes.c_ulong),
        ("creation_time", ctypes.c_longlong),
        ("last_access_time", ctypes.c_longlong),
        ("last_write_time", ctypes.c_longlong),
        ("change_time", ctypes.c_longlong),
        ("end_of_file", ctypes.c_longlong),
        ("allocation_size", ctypes.c_longlong),
        ("file_attributes", ctypes.c_ulong),
        ("file_name_length", ctypes.c_ulong),
        ("ea_size", ctypes.c_ulong),
        ("short_name_length", ctypes.c_ubyte),
        ("short_name", ctypes.c_wchar * 12),
        ("file_id", ctypes.c_longlong),
        ("file_name", ctypes.c_wchar * 1),
    )


def _windows_error_from_status(status: int) -> OSError:
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    ntdll.RtlNtStatusToDosError.argtypes = (ctypes.c_long,)
    ntdll.RtlNtStatusToDosError.restype = ctypes.c_ulong
    return ctypes.WinError(int(ntdll.RtlNtStatusToDosError(status)))


def _windows_open_relative_handle(
    parent_handle: int,
    name: str,
    *,
    is_directory: bool,
    share: int,
) -> int:
    """Open one literal child relative to an already verified directory handle."""
    if not name or name in {".", ".."} or "\\" in name or "/" in name:
        raise CleanupRejectedError("directory inventory contains an invalid child name")
    rendered = ctypes.create_unicode_buffer(name)
    unicode_name = _WindowsUnicodeString(
        length=len(name.encode("utf-16-le")),
        maximum_length=len(name.encode("utf-16-le")) + 2,
        buffer=ctypes.cast(rendered, ctypes.c_wchar_p),
    )
    attributes = _WindowsObjectAttributes(
        length=ctypes.sizeof(_WindowsObjectAttributes),
        root_directory=parent_handle,
        object_name=ctypes.pointer(unicode_name),
        attributes=0x00000040,  # OBJ_CASE_INSENSITIVE
        security_descriptor=None,
        security_qos=None,
    )
    handle = ctypes.c_void_p()
    io_status = _WindowsIoStatusBlock()
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    ntdll.NtCreateFile.argtypes = (
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_ulong,
        ctypes.POINTER(_WindowsObjectAttributes),
        ctypes.POINTER(_WindowsIoStatusBlock),
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.c_ulong,
    )
    ntdll.NtCreateFile.restype = ctypes.c_long
    create_options = 0x00200020 | (0x00000001 if is_directory else 0x00000040)
    status = int(
        ntdll.NtCreateFile(
            ctypes.byref(handle),
            0x00120081,  # SYNCHRONIZE | READ_CONTROL | READ_DATA | READ_ATTRIBUTES
            ctypes.byref(attributes),
            ctypes.byref(io_status),
            None,
            0,
            share,
            1,  # FILE_OPEN
            create_options,  # no-follow, synchronous, exact expected type
            None,
            0,
        )
    )
    if status < 0 or handle.value is None:
        raise _windows_error_from_status(status)
    information = _windows_handle_information(int(handle.value))
    if information.file_attributes & 0x00000400:
        ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(handle)
        raise CleanupRejectedError("directory inventory contains a reparse point")
    return int(handle.value)


def _windows_directory_entries(
    directory_handle: int,
    *,
    limit: int = _MAX_PINNED_FDS,
) -> tuple[tuple[str, int, int, int, int], ...]:
    """Enumerate direct children from a directory handle with restart semantics."""
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    ntdll.NtQueryDirectoryFile.argtypes = (
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(_WindowsIoStatusBlock),
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_int,
        ctypes.c_ubyte,
        ctypes.c_void_p,
        ctypes.c_ubyte,
    )
    ntdll.NtQueryDirectoryFile.restype = ctypes.c_long
    entries: list[tuple[str, int, int, int, int]] = []
    restart = True
    while True:
        buffer = ctypes.create_string_buffer(64 * 1024)
        io_status = _WindowsIoStatusBlock()
        status = int(
            ntdll.NtQueryDirectoryFile(
                directory_handle,
                None,
                None,
                None,
                ctypes.byref(io_status),
                buffer,
                len(buffer),
                37,  # FileIdBothDirectoryInformation
                0,
                None,
                int(restart),
            )
        )
        restart = False
        if ctypes.c_ulong(status).value == 0x80000006:  # STATUS_NO_MORE_FILES
            break
        if status < 0:
            raise _windows_error_from_status(status)
        offset = 0
        while True:
            information = _WindowsFileIdBothDirectoryInfo.from_buffer(buffer, offset)
            name = ctypes.wstring_at(
                ctypes.addressof(buffer)
                + offset
                + _WindowsFileIdBothDirectoryInfo.file_name.offset,
                information.file_name_length // 2,
            )
            if name not in {".", ".."}:
                entries.append(
                    (
                        name,
                        int(information.file_attributes),
                        int(information.file_id) & 0xFFFFFFFFFFFFFFFF,
                        int(information.end_of_file),
                        int(information.last_write_time),
                    )
                )
                if len(entries) > limit:
                    raise CleanupRejectedError("directory enumeration exceeds its bounded budget")
            if information.next_entry_offset == 0:
                break
            offset += int(information.next_entry_offset)
    return tuple(sorted(entries, key=lambda entry: entry[0].casefold()))


def _windows_information_signature(
    information: _WindowsFileInformation,
) -> tuple[int, ...]:
    return (
        int(information.file_attributes),
        int(information.write_time_high),
        int(information.write_time_low),
        int(information.volume_serial_number),
        int(information.file_size_high),
        int(information.file_size_low),
        int(information.number_of_links),
        int(information.file_index_high),
        int(information.file_index_low),
    )


def _hash_windows_handle(handle: int, *, max_bytes: int) -> str:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.SetFilePointerEx.argtypes = (
        ctypes.c_void_p,
        ctypes.c_longlong,
        ctypes.POINTER(ctypes.c_longlong),
        ctypes.c_ulong,
    )
    kernel32.ReadFile.argtypes = (
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_ulong),
        ctypes.c_void_p,
    )
    if not kernel32.SetFilePointerEx(handle, 0, None, 0):
        raise ctypes.WinError(ctypes.get_last_error())
    digest = hashlib.sha256()
    buffer = ctypes.create_string_buffer(_BUFFER_SIZE)
    read = ctypes.c_ulong()
    hashed = 0
    while True:
        if not kernel32.ReadFile(handle, buffer, len(buffer), ctypes.byref(read), None):
            raise ctypes.WinError(ctypes.get_last_error())
        if read.value == 0:
            break
        hashed += int(read.value)
        if hashed > max_bytes:
            raise CleanupRejectedError("file changed beyond its byte quota")
        digest.update(buffer.raw[: read.value])
    return digest.hexdigest()


def _hash_posix_handle(descriptor: int, *, max_bytes: int) -> str:
    pread = getattr(os, "pread", None)
    if pread is None:
        raise CleanupRejectedError("handle-relative file hashing is unavailable")
    digest = hashlib.sha256()
    offset = 0
    while chunk := pread(descriptor, _BUFFER_SIZE, offset):
        if offset + len(chunk) > max_bytes:
            raise CleanupRejectedError("file changed beyond its byte quota")
        digest.update(chunk)
        offset += len(chunk)
    return digest.hexdigest()


class _LinuxOpenHow(ctypes.Structure):
    _fields_ = (
        ("flags", ctypes.c_ulonglong),
        ("mode", ctypes.c_ulonglong),
        ("resolve", ctypes.c_ulonglong),
    )


def _open_posix_child(
    parent_descriptor: int,
    name: str,
    flags: int,
    *,
    no_xdev: bool,
) -> int:
    if not name or name in {".", ".."} or "/" in name or "\x00" in name:
        raise CleanupRejectedError("invalid handle-relative path component")
    if not sys.platform.startswith("linux"):
        raise CleanupRejectedError(
            "safe handle-relative POSIX cleanup is unavailable on this platform"
        )
    syscall_number = {"x86_64": 437, "amd64": 437, "aarch64": 437}.get(
        platform.machine().casefold()
    )
    if syscall_number is None:
        raise CleanupRejectedError("openat2 syscall mapping is unavailable")
    resolve = 0x08 | 0x04 | 0x02  # BENEATH | NO_SYMLINKS | NO_MAGICLINKS
    if no_xdev:
        resolve |= 0x01
    how = _LinuxOpenHow(flags=flags, mode=0, resolve=resolve)
    libc = ctypes.CDLL(None, use_errno=True)
    result = int(
        libc.syscall(
            syscall_number,
            parent_descriptor,
            os.fsencode(name),
            ctypes.byref(how),
            ctypes.sizeof(how),
        )
    )
    if result < 0:
        error_number = ctypes.get_errno()
        if error_number in {errno.ENOSYS, errno.EINVAL}:
            raise CleanupRejectedError("required openat2 capability is unavailable")
        if error_number == errno.EXDEV:
            raise CleanupRejectedError("cleanup path crosses a mount or filesystem boundary")
        if error_number == errno.ELOOP:
            raise CleanupRejectedError("cleanup path contains a symbolic redirect")
        raise OSError(error_number, os.strerror(error_number), name)
    return result


def _posix_rename_noreplace(
    source_parent: int,
    source_name: str,
    destination_parent: int,
    destination_name: str,
) -> None:
    if not sys.platform.startswith("linux"):
        raise CleanupRejectedError("atomic no-replace rename is unavailable on this POSIX platform")
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise CleanupRejectedError("renameat2 capability is unavailable")
    result = renameat2(
        source_parent,
        os.fsencode(source_name),
        destination_parent,
        os.fsencode(destination_name),
        1,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number), destination_name)


def _close_native_handles(handles: list[int]) -> None:
    if os.name == "nt":
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        for handle in reversed(handles):
            kernel32.CloseHandle(handle)
    else:
        for descriptor in reversed(handles):
            os.close(descriptor)
    handles.clear()


def _inventory_digest(inventory: list[tuple[Any, ...]]) -> str:
    return hashlib.sha256(
        json.dumps(inventory, ensure_ascii=True, separators=(",", ":")).encode()
    ).hexdigest()


def _assert_posix_inventory_file(
    descriptor: int,
    expected: os.stat_result,
    expected_hash: str,
    max_bytes: int,
) -> None:
    before = os.fstat(descriptor)
    if not _same_stat(before, expected) or not stat.S_ISREG(before.st_mode):
        raise CleanupRejectedError("pinned directory file changed")
    if not secrets.compare_digest(
        _hash_posix_handle(descriptor, max_bytes=max_bytes), expected_hash
    ):
        raise CleanupRejectedError("pinned directory file content changed")
    if not _same_stat(before, os.fstat(descriptor)):
        raise CleanupRejectedError("pinned directory file changed while hashing")


def _assert_posix_file_fingerprint(
    descriptor: int,
    expected: ResourceFingerprint,
    max_bytes: int,
    check_ctime: bool,
) -> None:
    observed = os.fstat(descriptor)
    if (
        not stat.S_ISREG(observed.st_mode)
        or int(observed.st_dev) != expected.device
        or int(observed.st_ino) != expected.inode
        or f"uid:{observed.st_uid}" != expected.owner
        or int(observed.st_mode) != expected.mode
        or int(observed.st_size) != expected.size
        or int(observed.st_mtime_ns) != expected.mtime_ns
        or (check_ctime and int(observed.st_ctime_ns) != expected.ctime_ns)
        or int(observed.st_nlink) != 1
        or expected.sha256 is None
    ):
        raise CleanupRejectedError("pinned file fingerprint changed")
    if not secrets.compare_digest(
        _hash_posix_handle(descriptor, max_bytes=max_bytes), expected.sha256
    ):
        raise CleanupRejectedError("pinned file content changed")
    after = os.fstat(descriptor)
    if not _same_stat(observed, after) or int(after.st_ctime_ns) != int(observed.st_ctime_ns):
        raise CleanupRejectedError("pinned file changed while hashing")


def _windows_filetime_ns(high: int, low: int) -> int:
    value = (int(high) << 32) | int(low)
    return max(0, (value - 116_444_736_000_000_000) * 100)


def _assert_windows_file_fingerprint(
    handle: int,
    expected: ResourceFingerprint,
    max_bytes: int,
) -> None:
    information = _windows_handle_information(handle)
    inode = (information.file_index_high << 32) | information.file_index_low
    size = (information.file_size_high << 32) | information.file_size_low
    if (
        information.file_attributes & 0x10
        or inode != expected.inode
        or int(size) != expected.size
        or int(information.number_of_links) != 1
        or int(information.file_attributes) != expected.attributes
        or _windows_filetime_ns(information.write_time_high, information.write_time_low)
        != expected.mtime_ns
        or _windows_filetime_ns(information.creation_time_high, information.creation_time_low)
        != expected.ctime_ns
        or not secrets.compare_digest(_windows_owner_sid_from_handle(handle), expected.owner)
        or expected.sha256 is None
    ):
        raise CleanupRejectedError("pinned Windows file fingerprint changed")
    if not secrets.compare_digest(
        _hash_windows_handle(handle, max_bytes=max_bytes), expected.sha256
    ):
        raise CleanupRejectedError("pinned Windows file content changed")
    if _windows_information_signature(
        _windows_handle_information(handle)
    ) != _windows_information_signature(information):
        raise CleanupRejectedError("pinned Windows file changed while hashing")


def _assert_posix_directory_listing(descriptor: int, expected_names: tuple[str, ...]) -> None:
    if _bounded_posix_names(descriptor, limit=len(expected_names)) != expected_names:
        raise CleanupRejectedError("pinned directory membership changed")


def _bounded_posix_names(descriptor: int, *, limit: int) -> tuple[str, ...]:
    names: list[str] = []
    with os.scandir(descriptor) as iterator:
        for child in iterator:
            names.append(child.name)
            if len(names) > limit:
                raise CleanupRejectedError("directory enumeration exceeds its bounded budget")
    return tuple(sorted(names))


def _assert_windows_inventory_entry(
    handle: int,
    expected_information: tuple[int, ...],
    expected_owner: str,
    expected_hash: str | None,
    max_bytes: int,
) -> None:
    before = _windows_handle_information(handle)
    if _windows_information_signature(before) != expected_information:
        raise CleanupRejectedError("pinned Windows directory entry changed")
    if not secrets.compare_digest(_windows_owner_sid_from_handle(handle), expected_owner):
        raise CleanupRejectedError("pinned Windows directory entry owner changed")
    if expected_hash is not None and not secrets.compare_digest(
        _hash_windows_handle(handle, max_bytes=max_bytes), expected_hash
    ):
        raise CleanupRejectedError("pinned Windows directory file content changed")
    if _windows_information_signature(_windows_handle_information(handle)) != expected_information:
        raise CleanupRejectedError("pinned Windows directory entry changed")


def _assert_windows_directory_listing(
    handle: int, expected: tuple[tuple[str, int, int], ...]
) -> None:
    current = tuple(
        (name, attributes, file_id)
        for name, attributes, file_id, _size, _mtime in _windows_directory_entries(
            handle, limit=len(expected)
        )
    )
    if current != expected:
        raise CleanupRejectedError("pinned Windows directory membership changed")


def _inventory_directory_handle(
    directory_handle: int,
    *,
    logical_root: Path,
    root_device: int,
    max_entries: int,
    max_bytes: int,
    max_depth: int,
    handles: list[int],
    validators: list[Callable[[], None]],
    windows_share: int,
    reparse_checker: ReparseChecker,
) -> tuple[list[tuple[Any, ...]], int]:
    inventory: list[tuple[Any, ...]] = []
    total_bytes = 0

    def enforce_quotas() -> None:
        if len(inventory) > max_entries:
            raise CleanupRejectedError("directory inventory entry quota exceeded")
        if total_bytes > max_bytes:
            raise CleanupRejectedError("directory inventory byte quota exceeded")

    def walk_posix(parent: int, prefix: str, depth: int) -> None:
        nonlocal total_bytes
        if depth > max_depth:
            raise CleanupRejectedError("directory inventory depth exceeds its quota")
        try:
            names = _bounded_posix_names(
                parent,
                limit=max_entries - len(inventory),
            )
        except OSError as error:
            raise CleanupRejectedError("directory inventory cannot be read") from error
        validators.append(partial(_assert_posix_directory_listing, parent, names))
        for name in names:
            if len(handles) >= _MAX_PINNED_FDS:
                raise CleanupRejectedError("directory inventory file descriptor budget exceeded")
            try:
                classification = _open_posix_child(
                    parent,
                    name,
                    getattr(os, "O_PATH", os.O_RDONLY) | getattr(os, "O_NOFOLLOW", 0),
                    no_xdev=True,
                )
            except OSError as error:
                raise CleanupRejectedError(
                    "directory child cannot be opened without following links"
                ) from error
            classified = os.fstat(classification)
            if not (stat.S_ISREG(classified.st_mode) or stat.S_ISDIR(classified.st_mode)):
                os.close(classification)
                raise CleanupRejectedError("directory inventory contains a special file")
            child_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            if stat.S_ISDIR(classified.st_mode):
                child_flags |= getattr(os, "O_DIRECTORY", 0)
            try:
                child = _open_posix_child(
                    parent,
                    name,
                    child_flags,
                    no_xdev=True,
                )
            finally:
                os.close(classification)
            handles.append(child)
            child_stat = os.fstat(child)
            if (
                int(child_stat.st_dev),
                int(child_stat.st_ino),
                int(child_stat.st_mode),
            ) != (
                int(classified.st_dev),
                int(classified.st_ino),
                int(classified.st_mode),
            ):
                raise CleanupRejectedError("directory child changed during classification")
            relative = f"{prefix}/{name}" if prefix else name
            logical_path = logical_root / relative
            if reparse_checker(logical_path, child_stat):
                raise CleanupRejectedError("directory inventory contains a redirect")
            if int(child_stat.st_dev) != root_device:
                raise CleanupRejectedError("directory inventory crosses a mount boundary")
            owner = f"uid:{child_stat.st_uid}"
            child_hash: str | None = None
            if stat.S_ISREG(child_stat.st_mode):
                if child_stat.st_nlink != 1:
                    raise CleanupRejectedError("directory inventory contains a hard link")
                if total_bytes + int(child_stat.st_size) > max_bytes:
                    raise CleanupRejectedError("directory inventory byte quota exceeded")
                child_hash = _hash_posix_handle(child, max_bytes=max_bytes)
                total_bytes += int(child_stat.st_size)
                kind = "file"
                validators.append(
                    partial(
                        _assert_posix_inventory_file,
                        child,
                        child_stat,
                        child_hash,
                        max_bytes,
                    )
                )
            elif stat.S_ISDIR(child_stat.st_mode):
                kind = "directory"
                validators.append(
                    partial(
                        _assert_posix_snapshot,
                        child,
                        child_stat,
                        "pinned directory changed",
                    )
                )
            else:
                raise CleanupRejectedError("directory inventory contains a special file")
            inventory.append(
                (
                    relative,
                    kind,
                    int(child_stat.st_dev),
                    int(child_stat.st_ino),
                    owner,
                    int(child_stat.st_mode),
                    int(child_stat.st_size),
                    int(child_stat.st_mtime_ns),
                    int(child_stat.st_nlink),
                    child_hash,
                )
            )
            enforce_quotas()
            if kind == "directory":
                walk_posix(child, relative, depth + 1)

    def walk_windows(parent: int, prefix: str, depth: int) -> None:
        nonlocal total_bytes
        if depth > max_depth:
            raise CleanupRejectedError("directory inventory depth exceeds its quota")
        entries = _windows_directory_entries(
            parent,
            limit=max_entries - len(inventory),
        )
        expected_listing = tuple(
            (name, attributes, file_id) for name, attributes, file_id, _size, _mtime in entries
        )
        validators.append(partial(_assert_windows_directory_listing, parent, expected_listing))
        for name, attributes, listed_id, _listed_size, _listed_mtime in entries:
            if len(handles) >= _MAX_PINNED_FDS:
                raise CleanupRejectedError("directory inventory handle budget exceeded")
            if attributes & 0x00000400:
                raise CleanupRejectedError("directory inventory contains a redirect")
            is_directory = bool(attributes & 0x00000010)
            relative = f"{prefix}/{name}" if prefix else name
            logical_path = logical_root / Path(relative)
            if reparse_checker is not _default_reparse_checker:
                try:
                    logical_stat = os.lstat(logical_path)
                except OSError as error:
                    raise CleanupRejectedError("directory child cannot be inspected") from error
                if reparse_checker(logical_path, logical_stat):
                    raise CleanupRejectedError("directory inventory contains a redirect")
            child = _windows_open_relative_handle(
                parent,
                name,
                is_directory=is_directory,
                share=windows_share,
            )
            handles.append(child)
            information = _windows_handle_information(child)
            child_id = (information.file_index_high << 32) | information.file_index_low
            if child_id != listed_id:
                raise CleanupRejectedError("directory child identity changed while opening")
            if int(information.volume_serial_number) != root_device:
                raise CleanupRejectedError("directory inventory crosses a volume boundary")
            if not is_directory and int(information.number_of_links) != 1:
                raise CleanupRejectedError("directory inventory contains a hard link")
            if not is_directory and attributes & 0x00000040:
                raise CleanupRejectedError("directory inventory contains a device")
            owner = _windows_owner_sid_from_handle(child)
            size = (information.file_size_high << 32) | information.file_size_low
            mtime = (information.write_time_high << 32) | information.write_time_low
            if not is_directory and total_bytes + int(size) > max_bytes:
                raise CleanupRejectedError("directory inventory byte quota exceeded")
            child_hash = None if is_directory else _hash_windows_handle(child, max_bytes=max_bytes)
            if not is_directory:
                total_bytes += int(size)
            kind = "directory" if is_directory else "file"
            signature = _windows_information_signature(information)
            validators.append(
                partial(
                    _assert_windows_inventory_entry,
                    child,
                    signature,
                    owner,
                    child_hash,
                    max_bytes,
                )
            )
            inventory.append(
                (
                    relative,
                    kind,
                    int(information.volume_serial_number),
                    int(child_id),
                    owner,
                    int(attributes),
                    int(size),
                    int(mtime),
                    int(information.number_of_links),
                    child_hash,
                )
            )
            enforce_quotas()
            if is_directory:
                walk_windows(child, relative, depth + 1)

    if os.name == "nt":
        walk_windows(directory_handle, "", 0)
    else:
        walk_posix(directory_handle, "", 0)
    inventory.sort(key=lambda entry: str(entry[0]))
    return inventory, total_bytes


def _validate_posix_moved_directory(
    destination_parent: int,
    destination_name: str,
    destination_path: Path,
    plan: RestorePlan,
    reparse_checker: ReparseChecker,
    handles: list[int],
) -> None:
    """Reacquire and inventory the moved namespace immediately after rename.

    POSIX descriptors do not prevent a same-UID peer from mutating names.  The
    caller therefore keeps the original descriptor inventory pinned and also
    performs this fresh handle-relative, no-mount-crossing inventory before it
    records success.  A peer can still race after the final verification; that
    same-user limitation cannot be eliminated with portable file permissions.
    """
    moved = _open_posix_child(
        destination_parent,
        destination_name,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0),
        no_xdev=True,
    )
    handles.append(moved)
    moved_stat = os.fstat(moved)
    if (int(moved_stat.st_dev), int(moved_stat.st_ino)) != (
        plan.fingerprint.device,
        plan.fingerprint.inode,
    ):
        raise CleanupRejectedError("moved directory name binding changed")
    inventory, total_bytes = _inventory_directory_handle(
        moved,
        logical_root=destination_path,
        root_device=plan.fingerprint.device,
        max_entries=plan.max_entries,
        max_bytes=plan.max_bytes,
        max_depth=plan.max_depth,
        handles=handles,
        validators=[],
        windows_share=0,
        reparse_checker=reparse_checker,
    )
    if (
        plan.fingerprint.inventory_digest is None
        or not secrets.compare_digest(
            _inventory_digest(inventory), plan.fingerprint.inventory_digest
        )
        or len(inventory) != plan.fingerprint.entry_count
        or total_bytes != plan.fingerprint.total_bytes
    ):
        raise CleanupRejectedError("moved directory inventory changed")


def _release_windows_descendant_handles(handles: list[int], descendants: tuple[int, ...]) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    for descendant in reversed(descendants):
        if not kernel32.CloseHandle(descendant):
            raise ctypes.WinError(ctypes.get_last_error())
        handles.remove(descendant)


def _windows_rename_handle(
    source_handle: int,
    destination_parent_handle: int,
    destination_name: str,
) -> None:
    """Rename one pinned handle relative to a pinned parent without replacement."""
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    name = destination_name.encode("utf-16-le")

    class RenameInfoEx(ctypes.Structure):
        _fields_ = (
            ("flags", ctypes.c_ulong),
            ("root_directory", ctypes.c_void_p),
            ("file_name_length", ctypes.c_ulong),
            ("file_name", ctypes.c_wchar * 1),
        )

    offset = RenameInfoEx.file_name.offset
    buffer = ctypes.create_string_buffer(ctypes.sizeof(RenameInfoEx) + len(name))
    info = ctypes.cast(buffer, ctypes.POINTER(RenameInfoEx)).contents
    info.flags = 0x00000002  # POSIX semantics, never replace
    info.root_directory = destination_parent_handle
    info.file_name_length = len(name)
    ctypes.memmove(ctypes.addressof(buffer) + offset, name, len(name))
    if kernel32.SetFileInformationByHandle(source_handle, 22, buffer, len(buffer)):
        return

    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    io_status = _WindowsIoStatusBlock()
    ntdll.NtSetInformationFile.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(_WindowsIoStatusBlock),
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_int,
    )
    status = int(
        ntdll.NtSetInformationFile(
            source_handle,
            ctypes.byref(io_status),
            buffer,
            len(buffer),
            65,  # FileRenameInformationEx
        )
    )
    if status >= 0:
        return

    class RenameInfo(ctypes.Structure):
        _fields_ = (
            ("replace_if_exists", ctypes.c_ubyte),
            ("root_directory", ctypes.c_void_p),
            ("file_name_length", ctypes.c_ulong),
            ("file_name", ctypes.c_wchar * 1),
        )

    legacy_offset = RenameInfo.file_name.offset
    legacy_buffer = ctypes.create_string_buffer(ctypes.sizeof(RenameInfo) + len(name))
    legacy = ctypes.cast(legacy_buffer, ctypes.POINTER(RenameInfo)).contents
    legacy.replace_if_exists = 0
    legacy.root_directory = destination_parent_handle
    legacy.file_name_length = len(name)
    ctypes.memmove(
        ctypes.addressof(legacy_buffer) + legacy_offset,
        name,
        len(name),
    )
    if kernel32.SetFileInformationByHandle(source_handle, 3, legacy_buffer, len(legacy_buffer)):
        return
    io_status = _WindowsIoStatusBlock()
    status = int(
        ntdll.NtSetInformationFile(
            source_handle,
            ctypes.byref(io_status),
            legacy_buffer,
            len(legacy_buffer),
            10,  # FileRenameInformation
        )
    )
    if status < 0:
        raise _windows_error_from_status(status)


def _validate_windows_moved_directory(
    destination_parent_handle: int,
    destination: Path,
    plan: RestorePlan,
    reparse_checker: ReparseChecker,
) -> None:
    handles: list[int] = []
    validators: list[Callable[[], None]] = []
    try:
        top = _windows_open_relative_handle(
            destination_parent_handle,
            destination.name,
            is_directory=True,
            share=0x00000005,
        )
        handles.append(top)
        information = _windows_handle_information(top)
        inode = (information.file_index_high << 32) | information.file_index_low
        if inode != plan.fingerprint.inode or not secrets.compare_digest(
            _windows_owner_sid_from_handle(top), plan.fingerprint.owner
        ):
            raise CleanupRejectedError("moved directory identity changed")
        inventory, total_bytes = _inventory_directory_handle(
            top,
            logical_root=destination,
            root_device=int(information.volume_serial_number),
            max_entries=plan.max_entries,
            max_bytes=plan.max_bytes,
            max_depth=plan.max_depth,
            handles=handles,
            validators=validators,
            windows_share=0x00000001,
            reparse_checker=reparse_checker,
        )
        if (
            plan.fingerprint.inventory_digest is None
            or not secrets.compare_digest(
                _inventory_digest(inventory), plan.fingerprint.inventory_digest
            )
            or len(inventory) != plan.fingerprint.entry_count
            or total_bytes != plan.fingerprint.total_bytes
        ):
            raise CleanupRejectedError("moved directory inventory changed")
        for validator in validators:
            validator()
    finally:
        _close_native_handles(handles)


def _validate_windows_moved_file(
    destination_parent_handle: int,
    destination: Path,
    plan: RestorePlan,
) -> None:
    moved = _windows_open_relative_handle(
        destination_parent_handle,
        destination.name,
        is_directory=False,
        share=0x00000005,
    )
    try:
        _assert_windows_file_fingerprint(moved, plan.fingerprint, plan.max_bytes)
    finally:
        ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(moved)


def _verify_windows_rollback_binding(
    source_parent_handle: int,
    source: Path,
    destination_parent_handle: int,
    destination: Path,
    expected_inode: int,
    *,
    is_directory: bool,
) -> None:
    restored = _windows_open_relative_handle(
        source_parent_handle,
        source.name,
        is_directory=is_directory,
        share=0x00000005,
    )
    try:
        if _windows_inode(restored) != expected_inode:
            raise _DirectoryRollbackAmbiguous("rollback restored the wrong identity")
    finally:
        ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(restored)
    destination_names = {
        name.casefold()
        for name, _attributes, _file_id, _size, _mtime in _windows_directory_entries(
            destination_parent_handle
        )
    }
    if destination.name.casefold() in destination_names:
        raise _DirectoryRollbackAmbiguous("rollback destination is still present")


class _PinnedMove:
    def __init__(
        self,
        *,
        source: Path,
        destination: Path,
        handles: list[int],
        validators: list[Callable[[], None]],
        mover: Callable[[], None],
        post_move_validators: list[Callable[[], None]] | None = None,
        rollback: Callable[[], None] | None = None,
    ) -> None:
        self.source = source
        self.destination = destination
        self._handles = handles
        self._validators = validators
        self._mover = mover
        self._post_move_validators = post_move_validators or []
        self._rollback = rollback

    def validate(self) -> None:
        for validator in self._validators:
            validator()

    def move(self) -> None:
        self.validate()
        self._mover()

    def validate_post_move(self) -> None:
        for validator in self._post_move_validators:
            validator()

    def rollback(self) -> None:
        if self._rollback is None:
            raise QuarantineError("atomic rollback is unavailable")
        self._rollback()

    def close(self) -> None:
        if os.name == "nt":
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            for handle in reversed(self._handles):
                kernel32.CloseHandle(handle)
        else:
            for descriptor in reversed(self._handles):
                os.close(descriptor)
        self._handles.clear()


def _assert_posix_component(descriptor: int, expected: PathComponentIdentity) -> None:
    observed = os.fstat(descriptor)
    if (
        int(observed.st_dev),
        int(observed.st_ino),
        int(observed.st_mode),
        f"uid:{observed.st_uid}",
    ) != (expected.device, expected.inode, expected.mode, expected.owner):
        raise CleanupRejectedError("pinned path component identity changed")


def _assert_posix_target(descriptor: int, device: int, inode: int) -> None:
    observed = os.fstat(descriptor)
    if (int(observed.st_dev), int(observed.st_ino)) != (device, inode):
        raise CleanupRejectedError("pinned target identity changed")


def _assert_posix_name_binding(
    parent_descriptor: int,
    name: str,
    device: int,
    inode: int,
) -> None:
    try:
        observed = os.stat(
            name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except OSError as error:
        raise CleanupRejectedError("pinned target name binding changed") from error
    if (int(observed.st_dev), int(observed.st_ino)) != (device, inode):
        raise CleanupRejectedError("pinned target name binding changed")


def _assert_posix_snapshot(descriptor: int, expected: os.stat_result, message: str) -> None:
    if not _same_stat(os.fstat(descriptor), expected):
        raise CleanupRejectedError(message)


def _windows_inode(handle: int) -> int:
    information = _windows_handle_information(handle)
    return int((information.file_index_high << 32) | information.file_index_low)


def _assert_windows_inode(handle: int, expected: int, message: str) -> None:
    if _windows_inode(handle) != expected:
        raise CleanupRejectedError(message)


def _open_posix_directory_chain(
    path: Path,
    *,
    handles: list[int],
    validators: list[Callable[[], None]],
    binding_validators: list[Callable[[], None]],
    expected: dict[Path, PathComponentIdentity] | None = None,
    no_xdev_from: Path | None = None,
    label: str,
) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    absolute = Path(os.path.abspath(path))
    descriptor = os.open(absolute.anchor, flags)
    handles.append(descriptor)
    current_path = Path(absolute.anchor)
    initial = os.fstat(descriptor)
    validators.append(
        partial(_assert_posix_snapshot, descriptor, initial, f"pinned {label} changed")
    )
    binding_validators.append(
        partial(
            _assert_posix_target,
            descriptor,
            int(initial.st_dev),
            int(initial.st_ino),
        )
    )
    for component in absolute.parts[1:]:
        parent = descriptor
        strict = no_xdev_from is not None and (
            current_path == no_xdev_from or no_xdev_from in current_path.parents
        )
        child = _open_posix_child(parent, component, flags, no_xdev=strict)
        handles.append(child)
        descriptor = child
        child_stat = os.fstat(descriptor)
        binding = partial(
            _assert_posix_name_binding,
            parent,
            component,
            int(child_stat.st_dev),
            int(child_stat.st_ino),
        )
        binding()
        validators.append(binding)
        binding_validators.append(binding)
        current_path /= component
        expected_component = expected.get(current_path) if expected else None
        if expected_component is not None:
            _assert_posix_component(descriptor, expected_component)
            validators.append(partial(_assert_posix_component, descriptor, expected_component))
        else:
            initial = os.fstat(descriptor)
            validators.append(
                partial(
                    _assert_posix_snapshot,
                    descriptor,
                    initial,
                    f"pinned {label} changed",
                )
            )
    return descriptor


def _pin_posix_move(
    plan: RestorePlan,
    source: Path,
    destination: Path,
    *,
    source_is_original: bool,
    reparse_checker: ReparseChecker,
) -> _PinnedMove:
    handles: list[int] = []
    validators: list[Callable[[], None]] = []
    post_move_validators: list[Callable[[], None]] = []
    namespace_binding_validators: list[Callable[[], None]] = []
    try:
        expected = {
            (
                Path(plan.approved_root)
                if component.relative_path == "."
                else Path(plan.approved_root) / component.relative_path
            ): component
            for component in plan.root_chain
        }
        original_parent = _open_posix_directory_chain(
            Path(plan.target).parent,
            handles=handles,
            validators=validators,
            binding_validators=namespace_binding_validators,
            expected=expected,
            no_xdev_from=Path(plan.approved_root),
            label="approved path",
        )
        source_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        if plan.resource_type is ResourceType.DIRECTORY:
            source_flags |= getattr(os, "O_DIRECTORY", 0)
        if source_is_original:
            source_parent = original_parent
        else:
            source_parent = _open_posix_directory_chain(
                source.parent,
                handles=handles,
                validators=validators,
                binding_validators=namespace_binding_validators,
                no_xdev_from=source.parent.parent,
                label="Graveyard source",
            )
        source_handle = _open_posix_child(
            source_parent,
            source.name,
            source_flags,
            no_xdev=True,
        )
        handles.append(source_handle)
        source_stat = os.fstat(source_handle)
        if (int(source_stat.st_dev), int(source_stat.st_ino)) != (
            plan.fingerprint.device,
            plan.fingerprint.inode,
        ):
            raise CleanupRejectedError("pinned target identity changed")
        validators.append(
            partial(
                _assert_posix_target,
                source_handle,
                plan.fingerprint.device,
                plan.fingerprint.inode,
            )
        )
        if plan.resource_type is ResourceType.FILE:
            validators.append(
                partial(
                    _assert_posix_file_fingerprint,
                    source_handle,
                    plan.fingerprint,
                    plan.max_bytes,
                    source_is_original,
                )
            )
            post_move_validators.append(
                partial(
                    _assert_posix_file_fingerprint,
                    source_handle,
                    plan.fingerprint,
                    plan.max_bytes,
                    False,
                )
            )
        validators.append(
            partial(
                _assert_posix_name_binding,
                source_parent,
                source.name,
                plan.fingerprint.device,
                plan.fingerprint.inode,
            )
        )
        if plan.resource_type is ResourceType.DIRECTORY:
            inventory_validators: list[Callable[[], None]] = []
            inventory, total_bytes = _inventory_directory_handle(
                source_handle,
                logical_root=source,
                root_device=plan.fingerprint.device,
                max_entries=plan.max_entries,
                max_bytes=plan.max_bytes,
                max_depth=plan.max_depth,
                handles=handles,
                validators=inventory_validators,
                windows_share=0,
                reparse_checker=reparse_checker,
            )
            validators.extend(inventory_validators)
            post_move_validators.extend(inventory_validators)
            if (
                plan.fingerprint.inventory_digest is None
                or not secrets.compare_digest(
                    _inventory_digest(inventory), plan.fingerprint.inventory_digest
                )
                or len(inventory) != plan.fingerprint.entry_count
                or total_bytes != plan.fingerprint.total_bytes
            ):
                raise CleanupRejectedError("directory inventory changed after preview")
        if source_is_original:
            destination_parent = _open_posix_directory_chain(
                destination.parent,
                handles=handles,
                validators=validators,
                binding_validators=namespace_binding_validators,
                no_xdev_from=destination.parent.parent,
                label="Graveyard destination",
            )
        else:
            destination_parent = original_parent
        post_move_validators.extend(namespace_binding_validators)
        post_move_validators.append(
            partial(
                _assert_posix_name_binding,
                destination_parent,
                destination.name,
                plan.fingerprint.device,
                plan.fingerprint.inode,
            )
        )
        if plan.resource_type is ResourceType.DIRECTORY:
            post_move_validators.append(
                partial(
                    _validate_posix_moved_directory,
                    destination_parent,
                    destination.name,
                    destination,
                    plan,
                    reparse_checker,
                    handles,
                )
            )

        def move() -> None:
            _posix_rename_noreplace(
                source_parent,
                source.name,
                destination_parent,
                destination.name,
            )

        return _PinnedMove(
            source=source,
            destination=destination,
            handles=handles,
            validators=validators,
            mover=move,
            post_move_validators=post_move_validators,
        )
    except BaseException:
        for descriptor in reversed(handles):
            os.close(descriptor)
        raise


def _pin_windows_move(
    plan: RestorePlan,
    source: Path,
    destination: Path,
    *,
    reparse_checker: ReparseChecker,
) -> _PinnedMove:
    handles: list[int] = []
    validators: list[Callable[[], None]] = []
    source_parent_handle: int | None = None
    try:
        for component in plan.root_chain:
            path = (
                Path(plan.approved_root)
                if component.relative_path == "."
                else Path(plan.approved_root) / component.relative_path
            )
            handle = _windows_open_handle(path, access=0x00020080)
            handles.append(handle)
            if os.path.normcase(os.fspath(path)) == os.path.normcase(os.fspath(source.parent)):
                source_parent_handle = handle
            info = _windows_handle_information(handle)
            inode = (info.file_index_high << 32) | info.file_index_low
            if inode != component.inode or not secrets.compare_digest(
                _windows_owner_sid_from_handle(handle), component.owner
            ):
                raise CleanupRejectedError("pinned Windows ancestor identity changed")
            validators.append(
                partial(
                    _assert_windows_inode,
                    handle,
                    inode,
                    "pinned Windows ancestor identity changed",
                )
            )
        source_is_original = os.path.normcase(os.fspath(source)) == os.path.normcase(plan.target)
        if not source_is_original:
            for component_path in _chain_to(source.parent):
                handle = _windows_open_handle(component_path, access=0x00020080)
                handles.append(handle)
                source_parent_handle = handle
                inode = _windows_inode(handle)
                validators.append(
                    partial(
                        _assert_windows_inode,
                        handle,
                        inode,
                        "pinned Graveyard source identity changed",
                    )
                )
        if source_parent_handle is None:
            raise CleanupRejectedError("source parent could not be pinned")
        source_handle = _windows_open_handle(
            source,
            access=0x00030081,  # DELETE | READ_CONTROL | READ_DATA | READ_ATTRIBUTES
            share=(0x00000001 if plan.resource_type is ResourceType.FILE else 0x00000005),
        )
        handles.append(source_handle)
        source_info = _windows_handle_information(source_handle)
        source_inode = (source_info.file_index_high << 32) | source_info.file_index_low
        if source_inode != plan.fingerprint.inode or not secrets.compare_digest(
            _windows_owner_sid_from_handle(source_handle), plan.fingerprint.owner
        ):
            raise CleanupRejectedError("pinned Windows target identity changed")
        validators.append(
            partial(
                _assert_windows_inode,
                source_handle,
                source_inode,
                "pinned Windows target identity changed",
            )
        )
        if plan.resource_type is ResourceType.FILE:
            validators.append(
                partial(
                    _assert_windows_file_fingerprint,
                    source_handle,
                    plan.fingerprint,
                    plan.max_bytes,
                )
            )
        descendant_handles: tuple[int, ...] = ()
        if plan.resource_type is ResourceType.DIRECTORY:
            descendant_start = len(handles)
            inventory, total_bytes = _inventory_directory_handle(
                source_handle,
                logical_root=source,
                root_device=int(source_info.volume_serial_number),
                max_entries=plan.max_entries,
                max_bytes=plan.max_bytes,
                max_depth=plan.max_depth,
                handles=handles,
                validators=validators,
                windows_share=0x00000001,
                reparse_checker=reparse_checker,
            )
            descendant_handles = tuple(handles[descendant_start:])
            if (
                plan.fingerprint.inventory_digest is None
                or not secrets.compare_digest(
                    _inventory_digest(inventory), plan.fingerprint.inventory_digest
                )
                or len(inventory) != plan.fingerprint.entry_count
                or total_bytes != plan.fingerprint.total_bytes
            ):
                raise CleanupRejectedError("directory inventory changed after preview")
        destination_handles: list[int] = []
        destination_chain = _chain_to(destination.parent)
        for index, component_path in enumerate(destination_chain):
            destination_handle = _windows_open_handle(
                component_path,
                access=(0x00030081 if index == len(destination_chain) - 1 else 0x00020080),
                share=0x00000003,  # Keep destination names pinned; deny delete/rename sharing.
            )
            handles.append(destination_handle)
            destination_handles.append(destination_handle)
            destination_inode = _windows_inode(destination_handle)
            validators.append(
                partial(
                    _assert_windows_inode,
                    destination_handle,
                    destination_inode,
                    "pinned destination identity changed",
                )
            )
        destination_handle = destination_handles[-1]

        # A retained handle proves an object's identity, not that its public
        # namespace still names it. Recheck the entire no-follow destination
        # chain against the pinned identities at every mutation boundary.
        def validate_destination_binding() -> None:
            _validate_component_chain(
                destination.parent,
                reparse_checker=reparse_checker,
                must_exist=True,
            )
            temporary: list[int] = []
            try:
                for component_path, retained in zip(
                    destination_chain,
                    destination_handles,
                    strict=True,
                ):
                    current = _windows_open_handle(component_path, access=0x00020080)
                    temporary.append(current)
                    current_info = _windows_handle_information(current)
                    retained_info = _windows_handle_information(retained)
                    if (
                        _windows_inode(current) != _windows_inode(retained)
                        or current_info.volume_serial_number != retained_info.volume_serial_number
                    ):
                        raise CleanupRejectedError("pinned destination namespace changed")
            finally:
                _close_native_handles(temporary)

        validators.append(validate_destination_binding)

        def move() -> None:
            # Windows will not rename a directory while descendant handles are
            # open.  They remain pinned through the final validation; the
            # already-pinned top directory denies namespace writes during this
            # minimal release-to-rename boundary.
            _release_windows_descendant_handles(handles, descendant_handles)
            _windows_rename_handle(source_handle, destination_handle, destination.name)

        def validate_post_move() -> None:
            if plan.resource_type is ResourceType.DIRECTORY:
                _validate_windows_moved_directory(
                    destination_handle,
                    destination,
                    plan,
                    reparse_checker,
                )
            else:
                _validate_windows_moved_file(
                    destination_handle,
                    destination,
                    plan,
                )

        def rollback() -> None:
            try:
                _windows_rename_handle(
                    source_handle,
                    source_parent_handle,
                    source.name,
                )
                _verify_windows_rollback_binding(
                    source_parent_handle,
                    source,
                    destination_handle,
                    destination,
                    source_inode,
                    is_directory=plan.resource_type is ResourceType.DIRECTORY,
                )
            except Exception as error:
                if isinstance(error, _DirectoryRollbackAmbiguous):
                    raise
                raise _DirectoryRollbackAmbiguous(
                    "Windows directory rollback could not be verified"
                ) from error

        return _PinnedMove(
            source=source,
            destination=destination,
            handles=handles,
            validators=validators,
            mover=move,
            post_move_validators=[validate_post_move],
            rollback=rollback,
        )
    except BaseException:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        for handle in reversed(handles):
            kernel32.CloseHandle(handle)
        raise


def _pin_move(
    plan: RestorePlan,
    source: Path,
    destination: Path,
    *,
    reparse_checker: ReparseChecker,
) -> _PinnedMove:
    if os.name == "nt":
        return _pin_windows_move(
            plan,
            source,
            destination,
            reparse_checker=reparse_checker,
        )
    source_is_original = os.path.normcase(os.fspath(source)) == os.path.normcase(plan.target)
    return _pin_posix_move(
        plan,
        source,
        destination,
        source_is_original=source_is_original,
        reparse_checker=reparse_checker,
    )


class QuarantineExecutor:
    """Claim, revalidate, atomically quarantine, and restore exact resources."""

    def __init__(
        self,
        store: QuarantineStore,
        paths: AppPaths,
        *,
        actor: str,
        registration_resolver: RegistrationResolver,
        platform_name: str | None = None,
        reparse_checker: ReparseChecker | None = None,
        clock: Callable[[], datetime] | None = None,
        device_resolver: Callable[[Path], int] | None = None,
        before_move: Callable[[QuarantinePlan], None] | None = None,
        after_move: Callable[[QuarantinePlan, Path], None] | None = None,
        before_restore: Callable[[QuarantineEntry], None] | None = None,
        after_restore: Callable[[QuarantineEntry, Path], None] | None = None,
        restore_expires_at: datetime | None = None,
        retention: timedelta = _DEFAULT_RETENTION,
    ) -> None:
        if not actor.strip():
            raise ValueError("actor must be non-empty")
        if retention <= timedelta(0):
            raise ValueError("retention must be positive")
        self._store = store
        self._paths = paths
        self._actor = actor
        self._platform_name = platform_name or platform.system()
        self._reparse_checker = reparse_checker or _default_reparse_checker
        self._registration_resolver = registration_resolver
        self._clock = clock or (lambda: datetime.now(UTC))
        self._device_resolver = device_resolver or (lambda path: int(os.lstat(path).st_dev))
        self._before_move = before_move
        self._after_move = after_move
        self._before_restore = before_restore
        self._after_restore = after_restore
        self._retention = retention
        if restore_expires_at is not None and (
            restore_expires_at.tzinfo is None or restore_expires_at.utcoffset() is None
        ):
            raise ValueError("restore expiry must be timezone-aware")
        self._restore_expires_at = restore_expires_at

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("clock must return timezone-aware timestamps")
        return value.astimezone(UTC)

    def _prepare_graveyard(self, entry_id: str, *, allow_existing: bool = False) -> Path:
        warnings = self._paths.ensure(platform_name=self._platform_name)
        graveyard = Path(os.path.abspath(self._paths.graveyard_dir))
        if any(Path(warning.path).name == graveyard.name for warning in warnings):
            raise QuarantineError("secure Graveyard preparation failed")
        if _has_redirected_component(graveyard):
            raise QuarantineError("Graveyard contains a redirected component")
        backend = (
            WindowsPermissionBackend()
            if self._platform_name.casefold().startswith("win")
            else PosixPermissionBackend()
        )
        backend.verify(graveyard)
        namespace = graveyard / entry_id
        try:
            namespace.mkdir(mode=0o700)
        except FileExistsError:
            if not allow_existing:
                raise
        else:
            backend.restrict(namespace)
        backend.verify(namespace)
        return namespace

    def _verify_graveyard(self) -> Path:
        graveyard = Path(os.path.abspath(self._paths.graveyard_dir))
        if _has_redirected_component(graveyard):
            raise QuarantineError("Graveyard contains a redirected component")
        backend = (
            WindowsPermissionBackend()
            if self._platform_name.casefold().startswith("win")
            else PosixPermissionBackend()
        )
        backend.verify(graveyard)
        return graveyard

    def _fingerprint_plan_target(self, plan: RestorePlan, path: Path) -> ResourceFingerprint:
        root = Path(plan.approved_root)
        root_stat = _validate_root(root, reparse_checker=self._reparse_checker)
        _strict_relative(path, root)
        _validate_component_chain(path, reparse_checker=self._reparse_checker, must_exist=True)
        return _fingerprint(
            path,
            plan.resource_type,
            root_device=int(root_stat.st_dev),
            reparse_checker=self._reparse_checker,
            max_entries=plan.max_entries,
            max_bytes=plan.max_bytes,
            max_depth=plan.max_depth,
        )

    def _revalidate_plan(self, plan: QuarantinePlan) -> None:
        now = self._now()
        if not (
            plan.created_at <= now < plan.expires_at
            and plan.manifest_created_at <= now < plan.manifest_expires_at
        ):
            raise CleanupRejectedError(
                "quarantine plan or manifest authority lifetime is not current"
            )
        if not plan.verify_digest() or not self._registration_resolver(_authority_from_plan(plan)):
            raise CleanupRejectedError("resource registration no longer matches")
        current = self._fingerprint_plan_target(plan, Path(plan.target))
        if not _same_fingerprint(plan.fingerprint, current):
            raise CleanupRejectedError("resource changed after preview")

    def _receipt(
        self,
        *,
        plan: RestorePlan,
        entry_id: str | None,
        operation: Literal["quarantine", "restore"],
        result: QuarantineResult,
        started_at: datetime,
        message: str,
    ) -> QuarantineReceipt:
        receipt_id = _new_id()
        return QuarantineReceipt(
            receipt_id=receipt_id,
            audit_event_id=_new_id(),
            correlation_id=plan.correlation_id,
            plan_id=plan.plan_id,
            entry_id=entry_id,
            operation=operation,
            result=result,
            actor_hash=hashlib.sha256(f"actor\0{self._actor}".encode()).hexdigest(),
            session_hash=hashlib.sha256(f"session\0{self._store.session_id}".encode()).hexdigest(),
            agent_hash=hashlib.sha256(f"agent\0{plan.agent_id}".encode()).hexdigest(),
            root_hash=plan.root_hash,
            target_hash=plan.target_hash,
            content_hash=plan.fingerprint.sha256 or plan.fingerprint.inventory_digest,
            size=plan.fingerprint.total_bytes,
            entry_count=plan.fingerprint.entry_count,
            started_at=started_at,
            finished_at=self._now(),
            message=redact_text(message, max_length=2048),
        )

    def _plan_from_entry(self, entry: QuarantineEntry) -> QuarantinePlan:
        loaded = self._store.get_quarantine_plan(entry.plan_id)
        if loaded is None:
            raise QuarantineError("quarantine plan is missing")
        if not entry.verify_digest() or not loaded.verify_digest():
            raise QuarantineError("quarantine restore metadata digest is invalid")
        expected_binding = (
            loaded.plan_id,
            loaded.correlation_id,
            loaded.agent_id,
            loaded.creating_identity,
            loaded.resource_type,
            loaded.approved_root,
            loaded.target,
            loaded.relative_path,
            loaded.root_hash,
            loaded.target_hash,
            loaded.fingerprint,
        )
        entry_binding = (
            entry.plan_id,
            entry.correlation_id,
            entry.agent_id,
            entry.creating_identity,
            entry.resource_type,
            entry.approved_root,
            entry.original_path,
            entry.original_relative_path,
            entry.root_hash,
            entry.original_path_hash,
            entry.fingerprint,
        )
        if expected_binding != entry_binding:
            raise QuarantineError("quarantine entry does not match its original plan")
        return loaded

    def _entry_for_plan(
        self, plan: QuarantinePlan, entry_id: str, now: datetime
    ) -> QuarantineEntry:
        namespace = Path(os.path.abspath(self._paths.graveyard_dir)) / entry_id
        destination = namespace / Path(plan.target).name
        values: dict[str, Any] = {
            "entry_id": entry_id,
            "plan_id": plan.plan_id,
            "correlation_id": plan.correlation_id,
            "agent_id": plan.agent_id,
            "creating_identity": plan.creating_identity,
            "resource_type": plan.resource_type,
            "approved_root": plan.approved_root,
            "original_path": plan.target,
            "original_relative_path": plan.relative_path,
            "quarantine_path": os.fspath(destination),
            "root_hash": plan.root_hash,
            "original_path_hash": plan.target_hash,
            "quarantine_path_hash": _path_hash("quarantine", destination),
            "fingerprint": plan.fingerprint,
            "state": QuarantineState.PLANNED,
            "created_at": now,
            "updated_at": now,
            "retention_until": now + self._retention,
            "digest": "0" * 64,
        }
        unsigned = QuarantineEntry.model_construct(**values)
        immutable = {
            key: value
            for key, value in unsigned.model_dump(mode="json").items()
            if key
            not in {
                "digest",
                "state",
                "updated_at",
                "receipt_ids",
                "restored_at",
            }
        }
        values["digest"] = hashlib.sha256(
            json.dumps(
                immutable,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        return QuarantineEntry(**values)

    def _finish_success(
        self,
        plan: QuarantinePlan,
        entry: QuarantineEntry,
        started_at: datetime,
    ) -> QuarantineReceipt:
        receipt = self._receipt(
            plan=plan,
            entry_id=entry.entry_id,
            operation="quarantine",
            result=QuarantineResult.QUARANTINED,
            started_at=started_at,
            message="Declared resource moved to the per-user Graveyard.",
        )
        finished = entry.model_copy(
            update={
                "state": QuarantineState.SUCCEEDED,
                "updated_at": receipt.finished_at,
                "receipt_ids": (*entry.receipt_ids, receipt.receipt_id),
            }
        )
        self._store.finish_quarantine_plan(
            plan.plan_id,
            state=QuarantineState.SUCCEEDED,
            receipt=receipt,
            entry=finished,
        )
        return receipt

    def _moved_matches(self, plan: QuarantinePlan, entry: QuarantineEntry) -> bool:
        source = Path(entry.original_path)
        destination = Path(entry.quarantine_path)
        if os.path.lexists(source) or not os.path.lexists(destination):
            return False
        try:
            current = _fingerprint(
                destination,
                plan.resource_type,
                root_device=self._device_resolver(destination),
                reparse_checker=self._reparse_checker,
                max_entries=plan.max_entries,
                max_bytes=plan.max_bytes,
                max_depth=plan.max_depth,
            )
        except (OSError, CleanupRejectedError):
            return False
        return _same_fingerprint_after_rename(plan.fingerprint, current)

    def execute(self, plan_id: str, *, expected_digest: str) -> QuarantineReceipt:
        existing_receipt = self._store.get_quarantine_receipt_for_plan(
            plan_id, expected_digest=expected_digest
        )
        if existing_receipt is not None:
            return existing_receipt
        recovery = self._store.get_quarantine_recovery(plan_id, expected_digest=expected_digest)
        if recovery is not None:
            interrupted_plan, _phase = recovery
            journaled = self._store.get_quarantine_entry_for_plan(plan_id)
            if journaled is not None and self._moved_matches(interrupted_plan, journaled):
                return self._finish_success(
                    interrupted_plan,
                    journaled,
                    journaled.updated_at,
                )
            source_valid = False
            with suppress(OSError, CleanupRejectedError):
                source_valid = _same_fingerprint(
                    interrupted_plan.fingerprint,
                    self._fingerprint_plan_target(interrupted_plan, Path(interrupted_plan.target)),
                )
            destination_absent = journaled is None or not os.path.lexists(journaled.quarantine_path)
            if source_valid and destination_absent:
                retry_entry = (
                    journaled.model_copy(
                        update={
                            "state": QuarantineState.PLANNED,
                            "updated_at": self._now(),
                        }
                    )
                    if journaled is not None
                    else None
                )
                self._store.reset_quarantine_plan_for_retry(plan_id, entry=retry_entry)
            else:
                started_at = journaled.updated_at if journaled else self._now()
                receipt = self._receipt(
                    plan=interrupted_plan,
                    entry_id=journaled.entry_id if journaled else None,
                    operation="quarantine",
                    result=QuarantineResult.INTERRUPTED,
                    started_at=started_at,
                    message="Dead-owner quarantine state was ambiguous and was not retried.",
                )
                interrupted_entry = (
                    journaled.model_copy(
                        update={
                            "state": QuarantineState.INTERRUPTED,
                            "updated_at": receipt.finished_at,
                            "receipt_ids": (*journaled.receipt_ids, receipt.receipt_id),
                        }
                    )
                    if journaled is not None
                    else None
                )
                self._store.finish_quarantine_plan(
                    plan_id,
                    state=QuarantineState.INTERRUPTED,
                    receipt=receipt,
                    entry=interrupted_entry,
                )
                return receipt
        plan = self._store.claim_quarantine_plan(plan_id, expected_digest=expected_digest)
        started_at = self._now()
        entry: QuarantineEntry | None = None
        try:
            self._store.update_quarantine_plan_phase(plan.plan_id, "validating")
            self._revalidate_plan(plan)
            entry = self._store.get_quarantine_entry_for_plan(plan.plan_id)
            if entry is None:
                entry_id = _new_id()
                entry = self._entry_for_plan(plan, entry_id, started_at)
                self._store.save_quarantine_entry(entry)
            else:
                entry_id = entry.entry_id
            self._store.update_quarantine_plan_phase(plan.plan_id, "journaled")
            namespace = self._prepare_graveyard(entry_id, allow_existing=True)
            self._store.update_quarantine_plan_phase(plan.plan_id, "graveyard_prepared")
            destination = namespace / Path(plan.target).name
            if self._device_resolver(Path(plan.target)) != self._device_resolver(namespace):
                raise QuarantineError("target and Graveyard are on different filesystems")
            entry = entry.model_copy(
                update={"state": QuarantineState.RUNNING, "updated_at": self._now()}
            )
            self._store.save_quarantine_entry(entry)
            self._store.update_quarantine_plan_phase(plan.plan_id, "running")
            self._revalidate_plan(plan)
            pinned = _pin_move(
                plan,
                Path(plan.target),
                destination,
                reparse_checker=self._reparse_checker,
            )
            try:
                if self._before_move is not None:
                    self._before_move(plan)
                if not self._registration_resolver(_authority_from_plan(plan)):
                    raise CleanupRejectedError("authoritative resource registration changed")
                _validate_component_chain(
                    Path(plan.target),
                    reparse_checker=self._reparse_checker,
                    must_exist=True,
                )
                pinned.validate()
                mutation_time = self._now()
                if mutation_time >= plan.expires_at or mutation_time >= plan.manifest_expires_at:
                    raise CleanupRejectedError(
                        "quarantine authority expired before the mutation boundary"
                    )
                if os.path.lexists(destination):
                    raise QuarantineError("Graveyard destination already exists")
                self._store.update_quarantine_plan_phase(plan.plan_id, "rename_issuing")
                # The journal write may block behind another SQLite owner.  Repeat
                # every mutation-boundary check after that wait, with all handles
                # still pinned, immediately before issuing the native rename.
                pinned.validate()
                if not self._registration_resolver(_authority_from_plan(plan)):
                    raise CleanupRejectedError("authoritative resource registration changed")
                mutation_time = self._now()
                if mutation_time >= plan.expires_at or mutation_time >= plan.manifest_expires_at:
                    raise CleanupRejectedError(
                        "quarantine authority expired before the mutation boundary"
                    )
                if os.path.lexists(destination):
                    raise QuarantineError("Graveyard destination already exists")
                pinned.move()
                hook_error: Exception | None = None
                try:
                    if self._after_move is not None:
                        self._after_move(plan, destination)
                except Exception as error:
                    hook_error = error
                try:
                    pinned.validate_post_move()
                except Exception as mismatch:
                    try:
                        pinned.rollback()
                    except Exception as rollback_error:
                        if isinstance(rollback_error, _DirectoryRollbackAmbiguous):
                            raise
                        raise _DirectoryRollbackAmbiguous(
                            "post-move resource changed and rollback is ambiguous"
                        ) from rollback_error
                    raise _DirectoryInventoryRolledBack(
                        "post-move resource changed and was rolled back"
                    ) from mismatch
                if hook_error is not None:
                    raise hook_error
            finally:
                pinned.close()
            self._store.update_quarantine_plan_phase(plan.plan_id, "renamed")
            if not self._moved_matches(plan, entry):
                raise QuarantineError("quarantined resource failed post-move verification")
            return self._finish_success(plan, entry, started_at)
        except Exception as error:
            if (
                not isinstance(
                    error,
                    (_DirectoryInventoryRolledBack, _DirectoryRollbackAmbiguous),
                )
                and entry is not None
                and self._moved_matches(plan, entry)
            ):
                return self._finish_success(plan, entry, started_at)
            source_exists = os.path.lexists(plan.target)
            destination_exists = entry is not None and os.path.lexists(entry.quarantine_path)
            if isinstance(error, (_DirectoryInventoryRolledBack, _DirectoryRollbackAmbiguous)):
                result = QuarantineResult.INTERRUPTED
                terminal_state = QuarantineState.INTERRUPTED
                summary = (
                    "Concurrent directory mutation was rolled back safely"
                    if isinstance(error, _DirectoryInventoryRolledBack)
                    else "Directory rollback outcome is ambiguous and requires inspection"
                )
            elif destination_exists:
                result = QuarantineResult.PARTIAL
                terminal_state = QuarantineState.PARTIAL
                summary = "Quarantine moved material but verification was incomplete"
            elif entry is not None and entry.state is QuarantineState.RUNNING and not source_exists:
                result = QuarantineResult.INTERRUPTED
                terminal_state = QuarantineState.INTERRUPTED
                summary = "Quarantine outcome is interrupted and requires inspection"
            else:
                result = QuarantineResult.FAILED
                terminal_state = QuarantineState.FAILED
                summary = "Quarantine failed safely"
            receipt = self._receipt(
                plan=plan,
                entry_id=entry.entry_id if entry is not None else None,
                operation="quarantine",
                result=result,
                started_at=started_at,
                message=f"{summary} ({type(error).__name__}).",
            )
            failed_entry = (
                entry.model_copy(
                    update={
                        "state": terminal_state,
                        "updated_at": receipt.finished_at,
                        "receipt_ids": (*entry.receipt_ids, receipt.receipt_id),
                    }
                )
                if entry is not None
                else None
            )
            self._store.finish_quarantine_plan(
                plan.plan_id,
                state=terminal_state,
                receipt=receipt,
                entry=failed_entry,
            )
            return receipt

    def _restore_success(
        self,
        plan: RestorePlan,
        entry: QuarantineEntry,
        started_at: datetime,
    ) -> QuarantineReceipt:
        receipt = self._receipt(
            plan=plan,
            entry_id=entry.entry_id,
            operation="restore",
            result=QuarantineResult.RESTORED,
            started_at=started_at,
            message="Exact quarantined resource restored without overwrite.",
        )
        restored = entry.model_copy(
            update={
                "state": QuarantineState.RESTORED,
                "updated_at": receipt.finished_at,
                "restored_at": receipt.finished_at,
                "receipt_ids": (*entry.receipt_ids, receipt.receipt_id),
            }
        )
        try:
            self._store.save_quarantine_receipt(receipt, entry=restored)
        except Exception:
            with suppress(Exception):
                self._store.release_quarantine_restore(entry.entry_id)
            raise
        return receipt

    def _restored_matches(
        self,
        plan: RestorePlan,
        entry: QuarantineEntry,
        source: Path,
        destination: Path,
    ) -> bool:
        if os.path.lexists(source) or not os.path.lexists(destination):
            return False
        try:
            current = self._fingerprint_plan_target(plan, destination)
        except (OSError, CleanupRejectedError):
            return False
        return _same_fingerprint_after_rename(entry.fingerprint, current)

    def restore(self, entry_id: str) -> QuarantineReceipt:
        entry = self._store.get_quarantine_entry(entry_id)
        if entry is None:
            raise QuarantineError("quarantine entry was not found")
        plan = self._plan_from_entry(entry)
        return self._restore_bound(plan, entry, require_registration=True)

    def restore_legacy(self, entry_id: str, *, expected_entry_digest: str) -> QuarantineReceipt:
        """Restore one classified v5 entry without granting cleanup authority."""
        try:
            plan, entry = self._store.get_legacy_restore_plan(
                entry_id,
                expected_entry_digest=expected_entry_digest,
            )
        except Exception as error:
            raise QuarantineError("legacy restore evidence or entry digest is invalid") from error
        return self._restore_bound(plan, entry, require_registration=False)

    def _restore_bound(
        self,
        plan: RestorePlan,
        entry: QuarantineEntry,
        *,
        require_registration: bool,
    ) -> QuarantineReceipt:
        restore_claimed = entry.state is not QuarantineState.RESTORED
        claimed_entry = (
            self._store.claim_quarantine_restore(entry.entry_id)
            if restore_claimed
            else self._store.get_quarantine_entry(entry.entry_id)
        )
        if claimed_entry is None:
            raise QuarantineError("quarantine entry was not found")
        if (
            not secrets.compare_digest(entry.digest, claimed_entry.digest)
            or entry.immutable_fields() != claimed_entry.immutable_fields()
            or (not restore_claimed and claimed_entry.state is not QuarantineState.RESTORED)
        ):
            if restore_claimed:
                self._store.release_quarantine_restore(entry.entry_id)
            raise QuarantineError("quarantine entry changed before restore claim")
        entry = claimed_entry
        if restore_claimed:
            try:
                self._store.preflight_quarantine_restore(entry.entry_id)
            except Exception as error:
                with suppress(Exception):
                    self._store.release_quarantine_restore(entry.entry_id)
                raise QuarantineError("restore journal schema preflight failed") from error
        started_at = self._now()
        if entry.state is QuarantineState.RESTORED:
            source = Path(entry.quarantine_path)
            destination = Path(entry.original_path)
            valid = self._restored_matches(plan, entry, source, destination)
            result = QuarantineResult.ALREADY_RESTORED if valid else QuarantineResult.FAILED
            existing = self._store.get_quarantine_receipt_for_entry(
                entry.entry_id,
                operation="restore",
                result=result,
            )
            if existing is not None:
                return existing
            receipt = self._receipt(
                plan=plan,
                entry_id=entry.entry_id,
                operation="restore",
                result=result,
                started_at=started_at,
                message=(
                    "Resource was already restored; no overwrite was attempted."
                    if valid
                    else "Restored resource no longer matches its protected identity."
                ),
            )
            self._store.save_quarantine_receipt(receipt, entry=None)
            return receipt
        source = Path(entry.quarantine_path)
        destination = Path(entry.original_path)
        try:
            graveyard = self._verify_graveyard()
            _strict_relative(source, graveyard)
            _validate_component_chain(
                source, reparse_checker=self._reparse_checker, must_exist=True
            )
            current = _fingerprint(
                source,
                entry.resource_type,
                root_device=self._device_resolver(source),
                reparse_checker=self._reparse_checker,
                max_entries=plan.max_entries,
                max_bytes=plan.max_bytes,
                max_depth=plan.max_depth,
            )
            if not _same_fingerprint_after_rename(entry.fingerprint, current):
                raise QuarantineError("Graveyard entry changed after quarantine")
            root = _reject_lexical_path(entry.approved_root, platform_name=self._platform_name)
            expected = root / entry.original_relative_path
            if os.path.normcase(os.fspath(expected)) != os.path.normcase(os.fspath(destination)):
                raise QuarantineError("stored restore path is inconsistent")
            _validate_root(root, reparse_checker=self._reparse_checker)
            _validate_component_chain(
                destination.parent,
                reparse_checker=self._reparse_checker,
                must_exist=True,
            )
            _strict_relative(destination, root)
            if os.path.lexists(destination):
                raise QuarantineError("restore destination already exists")
            if self._device_resolver(source) != self._device_resolver(destination.parent):
                raise QuarantineError("restore destination is on a different filesystem")
            pinned_restore = _pin_move(
                plan,
                source,
                destination,
                reparse_checker=self._reparse_checker,
            )
            try:
                if self._before_restore is not None:
                    self._before_restore(entry)
                _validate_component_chain(
                    destination.parent,
                    reparse_checker=self._reparse_checker,
                    must_exist=True,
                )
                if os.path.lexists(destination):
                    raise QuarantineError("restore destination appeared after validation")
                pinned_restore.validate()
                if require_registration and (
                    not isinstance(plan, QuarantinePlan)
                    or not self._registration_resolver(_authority_from_plan(plan))
                ):
                    raise CleanupRejectedError("authoritative resource registration changed")
                if self._restore_expires_at is not None and self._now() >= self._restore_expires_at:
                    raise CleanupRejectedError("restore authority expired before mutation boundary")
                pinned_restore.move()
                hook_error: Exception | None = None
                try:
                    if self._after_restore is not None:
                        self._after_restore(entry, destination)
                except Exception as error:
                    hook_error = error
                try:
                    pinned_restore.validate_post_move()
                except Exception as mismatch:
                    try:
                        pinned_restore.rollback()
                    except Exception as rollback_error:
                        if isinstance(rollback_error, _DirectoryRollbackAmbiguous):
                            raise
                        raise _DirectoryRollbackAmbiguous(
                            "restore resource changed and rollback is ambiguous"
                        ) from rollback_error
                    raise _DirectoryInventoryRolledBack(
                        "restore resource changed and returned to Graveyard"
                    ) from mismatch
                if hook_error is not None:
                    raise hook_error
            finally:
                pinned_restore.close()
            restored_fingerprint = self._fingerprint_plan_target(plan, destination)
            if not _same_fingerprint_after_rename(entry.fingerprint, restored_fingerprint):
                raise QuarantineError("restored resource failed identity verification")
            return self._restore_success(plan, entry, started_at)
        except Exception as error:
            if not isinstance(
                error,
                (_DirectoryInventoryRolledBack, _DirectoryRollbackAmbiguous),
            ) and self._restored_matches(plan, entry, source, destination):
                return self._restore_success(plan, entry, started_at)
            interrupted = isinstance(
                error, (_DirectoryInventoryRolledBack, _DirectoryRollbackAmbiguous)
            ) or not os.path.lexists(source)
            result = QuarantineResult.INTERRUPTED if interrupted else QuarantineResult.FAILED
            existing = self._store.get_quarantine_receipt_for_entry(
                entry.entry_id,
                operation="restore",
                result=result,
            )
            if existing is not None:
                self._store.release_quarantine_restore(entry.entry_id)
                return existing
            receipt = self._receipt(
                plan=plan,
                entry_id=entry.entry_id,
                operation="restore",
                result=result,
                started_at=started_at,
                message=(
                    f"Restore was interrupted and its final state requires inspection "
                    f"({type(error).__name__})."
                    if interrupted
                    else f"Restore failed safely ({type(error).__name__})."
                ),
            )
            recovery_entry = (
                entry.model_copy(
                    update={
                        "state": QuarantineState.INTERRUPTED,
                        "updated_at": receipt.finished_at,
                        "receipt_ids": (*entry.receipt_ids, receipt.receipt_id),
                    }
                )
                if interrupted
                else None
            )
            self._store.save_quarantine_receipt(receipt, entry=recovery_entry)
            return receipt


__all__ = [
    "CleanupAuthority",
    "CleanupManifest",
    "CleanupRejectedError",
    "InMemoryCleanupRegistry",
    "LegacyRecoveryReason",
    "LegacyRestorePlan",
    "PathComponentIdentity",
    "QuarantineEntry",
    "QuarantineError",
    "QuarantineExecutor",
    "QuarantinePlan",
    "QuarantinePlanner",
    "QuarantineReceipt",
    "QuarantineResult",
    "QuarantineState",
    "RegistrationResolver",
    "ResourceFingerprint",
    "ResourceType",
]
