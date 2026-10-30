"""Strict contracts and hostile-file primitives for local Memory Vault adapters."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import secrets
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Literal, Protocol, TypeAlias

from pydantic import Field, SecretStr, field_validator, model_validator

from zombie_killer_engine.models import (
    CodeText,
    DomainModel,
    HashText,
    IdentifierText,
    PathText,
    UtcDatetime,
)
from zombie_killer_engine.paths import (
    WindowsPermissionBackend,
    _has_redirected_component,
    _is_reparse_point,
)

JsonScalar: TypeAlias = str | int | float | bool | None
# Recursive aliases currently make Pydantic's strict schema generator recurse forever.
# Runtime parsers below enforce the complete bounded JSON tree before model creation.
JsonValue: TypeAlias = object

PLAN_LIFETIME = timedelta(seconds=30)
_WINDOWS_RESERVED_BASENAMES = {
    "AUX",
    "CLOCK$",
    "CON",
    "CONIN$",
    "CONOUT$",
    "NUL",
    "PRN",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}


class MemoryError(RuntimeError):
    """A vault operation could not be proven safe and was rejected."""


class MemoryJournalError(MemoryError):
    """The durable vault journal is unavailable and requires reconciliation."""


@dataclass(frozen=True, slots=True)
class SourceFileSecurity:
    mode: int
    uid: int
    gid: int
    posix_acl: bytes | None = None
    windows_descriptor: bytes | None = None
    windows_sddl: str | None = None
    windows_control: int | None = None


class VaultFormat(StrEnum):
    JSON = "json"
    JSONL = "jsonl"
    SQLITE = "sqlite"
    CHROMA = "chroma"
    FAISS = "faiss"
    UNSUPPORTED = "unsupported"


class MutationKind(StrEnum):
    UPDATE_CONTENT = "update_content"
    UPDATE_FIELD = "update_field"
    UPDATE_METADATA = "update_metadata"
    EXCLUDE = "exclude_from_retrieval"
    QUARANTINE = "quarantine"
    RESTORE_RECORD = "restore_record"


class SnapshotStatus(StrEnum):
    VERIFIED = "verified"
    RESTORED = "restored"
    INVALID = "invalid"


class VaultCapabilities(DomainModel):
    readable: bool = True
    queryable: bool = True
    editable: bool = False
    snapshot: bool = False
    restore: bool = False
    reason: str | None = Field(default=None, max_length=512)


class FileIdentity(DomainModel):
    device: int = Field(ge=0)
    inode: int = Field(ge=0)
    size: int = Field(ge=0)
    mtime_ns: int = Field(ge=0)
    ctime_ns: int = Field(ge=0)
    mode: int = Field(ge=0)


class VaultSource(DomainModel):
    source_id: IdentifierText
    path: PathText
    format: VaultFormat
    capabilities: VaultCapabilities
    revision: HashText


class ProbeResult(DomainModel):
    format: VaultFormat
    recognized: bool
    capabilities: VaultCapabilities
    reason: str | None = Field(default=None, max_length=512)


class QueryFilter(DomainModel):
    text: str | None = Field(default=None, max_length=1024)
    ids: tuple[IdentifierText, ...] = Field(default=(), max_length=256)
    tags: tuple[str, ...] = Field(default=(), max_length=64)
    metadata: dict[str, JsonScalar] = Field(default_factory=dict, max_length=64)


class MemoryRecord(DomainModel):
    record_id: IdentifierText
    namespace: IdentifierText
    content: str = Field(max_length=65_536)
    metadata: dict[str, JsonValue] = Field(default_factory=dict, max_length=256)
    embedding_present: bool = False
    source_revision: HashText


class QueryPage(DomainModel):
    records: tuple[MemoryRecord, ...]
    next_cursor: str | None = Field(default=None, max_length=64)
    total: int = Field(ge=0)


class FieldDiff(DomainModel):
    field_name: CodeText
    old_hash: HashText
    new_hash: HashText
    old_preview: Literal["[REDACTED]"] = "[REDACTED]"
    new_preview: Literal["[REDACTED]"] = "[REDACTED]"


class MutationOperation(DomainModel):
    kind: MutationKind
    record_id: IdentifierText
    field: str | None = Field(default=None, min_length=1, max_length=128)
    metadata_key: str | None = Field(default=None, min_length=1, max_length=128)
    value: JsonScalar | SecretStr = None

    @field_validator("field", "metadata_key")
    @classmethod
    def _safe_field(cls, value: str | None) -> str | None:
        if value is not None and (not value.replace("_", "a").isalnum()):
            raise ValueError("field names must contain only letters, digits, and underscore")
        return value

    @model_validator(mode="after")
    def _shape_matches_kind(self) -> MutationOperation:
        if self.kind is MutationKind.UPDATE_FIELD and self.field is None:
            raise ValueError("update_field requires a field")
        if self.kind is MutationKind.UPDATE_METADATA and self.metadata_key is None:
            raise ValueError("update_metadata requires a metadata_key")
        if self.kind not in {MutationKind.UPDATE_FIELD, MutationKind.UPDATE_METADATA} and (
            self.field is not None or self.metadata_key is not None
        ):
            raise ValueError("this operation does not accept a field name")
        return self

    def unsealed_value(self) -> JsonScalar:
        return self.value.get_secret_value() if isinstance(self.value, SecretStr) else self.value


class MutationPlan(DomainModel):
    plan_id: IdentifierText
    source_id: IdentifierText
    source_revision: HashText
    source_identity: FileIdentity
    operation_kind: MutationKind
    record_id: IdentifierText
    record_hash: HashText
    operation_field: CodeText | None = None
    operation_metadata_key: CodeText | None = None
    proposed_value_hash: HashText
    proposed_value_type: CodeText
    field_name: CodeText
    expected_old_hash: HashText
    old_store_hash: HashText
    new_store_hash: HashText
    diff: tuple[FieldDiff, ...] = Field(min_length=1, max_length=8)
    created_at: UtcDatetime
    expires_at: UtcDatetime
    digest: HashText
    operation: MutationOperation = Field(exclude=True)

    @model_validator(mode="after")
    def _fixed_expiry(self) -> MutationPlan:
        if self.expires_at - self.created_at != PLAN_LIFETIME:
            raise ValueError("mutation plans have a fixed 30 second lifetime")
        return self


class MemoryPlanAuthority(DomainModel):
    plan_id: IdentifierText
    source_id: IdentifierText
    digest: HashText
    source_revision: HashText
    source_identity: FileIdentity
    operation_kind: MutationKind
    record_id: IdentifierText
    record_hash: HashText
    operation_field: CodeText | None = None
    operation_metadata_key: CodeText | None = None
    proposed_value_hash: HashText
    proposed_value_type: CodeText
    field_names: tuple[CodeText, ...]
    diff: tuple[FieldDiff, ...]
    expected_old_hash: HashText
    old_store_hash: HashText
    new_store_hash: HashText
    status: CodeText
    phase: CodeText
    snapshot_id: IdentifierText | None = None
    created_at: UtcDatetime
    expires_at: UtcDatetime


class Snapshot(DomainModel):
    snapshot_id: IdentifierText
    source_id: IdentifierText
    source_path_binding: HashText
    source_revision: HashText
    source_identity: FileIdentity
    digest: HashText
    size: int = Field(ge=0)
    backup_identity: FileIdentity
    backup_path: PathText
    status: SnapshotStatus = SnapshotStatus.VERIFIED
    created_at: UtcDatetime


class MemoryReceipt(DomainModel):
    receipt_id: IdentifierText
    plan_id: IdentifierText | None = None
    restore_plan_id: IdentifierText | None = None
    snapshot_id: IdentifierText
    source_id: IdentifierText
    operation: CodeText
    field_names: tuple[CodeText, ...] = Field(default=(), max_length=8)
    before_revision: HashText
    after_revision: HashText
    created_at: UtcDatetime


class RestorePlan(DomainModel):
    restore_plan_id: IdentifierText
    restore_key: HashText
    source_id: IdentifierText
    snapshot_id: IdentifierText
    snapshot_digest: HashText
    expected_revision: HashText
    source_identity: FileIdentity
    before_hash: HashText
    target_hash: HashText
    created_at: UtcDatetime
    expires_at: UtcDatetime
    digest: HashText

    @model_validator(mode="after")
    def _fixed_expiry(self) -> RestorePlan:
        if self.expires_at - self.created_at != PLAN_LIFETIME:
            raise ValueError("restore plans have a fixed 30 second lifetime")
        return self


class RestoreAuthority(RestorePlan):
    status: CodeText
    phase: CodeText
    rollback_snapshot_id: IdentifierText | None = None


class NamespaceInventory(DomainModel):
    name: IdentifierText
    kind: Literal["table", "view"]
    columns: tuple[CodeText, ...]
    primary_key: CodeText | None = None
    editable: bool = False
    reason: str | None = Field(default=None, max_length=256)


class MemoryAdapter(Protocol):
    @classmethod
    def probe(cls, path: Path) -> ProbeResult: ...
    def open(self, *, read_only: bool) -> MemoryAdapter: ...
    def list_namespaces(self) -> tuple[str, ...]: ...
    def query(
        self,
        *,
        cursor: str | None = None,
        limit: int = 100,
        filter: QueryFilter | None = None,
        namespace: str | None = None,
    ) -> QueryPage: ...
    def get(self, record_id: str) -> MemoryRecord: ...
    def current_revision(self) -> str: ...
    def plan_mutation(
        self, operation: MutationOperation, *, expected_revision: str
    ) -> MutationPlan: ...
    def backup(self, *, expected_revision: str) -> Snapshot: ...
    def apply(self, plan: MutationPlan) -> MemoryReceipt: ...
    def healthcheck(self) -> None: ...
    def restore(
        self,
        snapshot_id: str,
        *,
        expected_snapshot_digest: str,
        expected_revision: str,
        reviewed_expires_at: datetime | None = None,
    ) -> MemoryReceipt: ...


class MemoryStateStore(Protocol):
    def register_vault_source(self, source: VaultSource) -> None: ...
    def save_memory_plan(self, plan: MutationPlan) -> None: ...
    def claim_memory_plan(self, plan_id: str, *, expected_digest: str) -> MemoryPlanAuthority: ...
    def update_memory_plan_phase(
        self, plan_id: str, phase: str, *, snapshot_id: str | None = None
    ) -> None: ...
    def finish_memory_plan(self, receipt: MemoryReceipt) -> None: ...
    def fail_memory_plan(self, plan_id: str, *, interrupted: bool) -> None: ...
    def list_memory_reconciliation(self, source_id: str) -> tuple[MemoryPlanAuthority, ...]: ...
    def finish_memory_reconciliation(self, receipt: MemoryReceipt, *, succeeded: bool) -> None: ...
    def save_memory_snapshot(self, snapshot: Snapshot) -> None: ...
    def get_memory_snapshot(self, snapshot_id: str) -> Snapshot | None: ...
    def save_memory_receipt(self, receipt: MemoryReceipt) -> None: ...
    def save_memory_restore_plan(self, plan: RestorePlan) -> RestoreAuthority: ...
    def claim_memory_restore(
        self, restore_plan_id: str, *, expected_digest: str
    ) -> RestoreAuthority: ...
    def update_memory_restore_phase(
        self,
        restore_plan_id: str,
        phase: str,
        *,
        rollback_snapshot_id: str | None = None,
    ) -> None: ...
    def finish_memory_restore(self, receipt: MemoryReceipt) -> None: ...
    def fail_memory_restore(self, restore_plan_id: str, *, interrupted: bool) -> None: ...
    def list_memory_restore_reconciliation(
        self, source_id: str
    ) -> tuple[RestoreAuthority, ...]: ...
    def get_memory_restore_receipt(self, restore_plan_id: str) -> MemoryReceipt | None: ...


def utc_now() -> datetime:
    return datetime.now(UTC)


def validate_write_deadline(expires_at: datetime | None) -> datetime | None:
    """Normalize optional reviewed authority without accepting naive or non-date values."""
    if expires_at is None:
        return None
    if not isinstance(expires_at, datetime):
        raise MemoryError("memory write deadline must be an aware datetime")
    try:
        if expires_at.utcoffset() is None:
            raise ValueError("naive datetime")
        return expires_at.astimezone(UTC)
    except (OverflowError, TypeError, ValueError) as error:
        raise MemoryError("memory write deadline must be an aware datetime") from error


def verify_write_deadline(expires_at: datetime | None, *, now: datetime | None = None) -> None:
    """Check after slow preparation, immediately before the actual write boundary."""
    deadline = validate_write_deadline(expires_at)
    if deadline is not None and (now or utc_now()) >= deadline:
        raise MemoryError("memory write deadline expired")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_hash(value: object) -> str:
    try:
        encoded = json.dumps(
            value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise MemoryError("value is not bounded canonical JSON") from error
    return sha256_bytes(encoded)


def path_binding(path: Path) -> str:
    return sha256_bytes(os.path.normcase(str(path.absolute())).encode("utf-8"))


def source_id(path: Path) -> str:
    return "vault-" + path_binding(path)[:32]


def _current_user_id() -> int:
    getter = getattr(os, "geteuid", None)
    return int(getter()) if getter is not None else 0


def _verify_posix_ancestors(path: Path) -> None:
    current = path.parent
    while True:
        try:
            current_stat = os.lstat(current)
        except OSError as error:
            raise MemoryError("vault path ancestry could not be verified") from error
        if not stat.S_ISDIR(current_stat.st_mode):
            raise MemoryError("vault path ancestor is not a directory")
        mode = stat.S_IMODE(current_stat.st_mode)
        sticky_root_boundary = (
            current_stat.st_uid == 0 and bool(mode & stat.S_ISVTX) and bool(mode & 0o002)
        )
        if mode & 0o022 and not sticky_root_boundary:
            raise MemoryError("vault path ancestor grants unsafe write access")
        parent = current.parent
        if parent == current:
            return
        current = parent


def validate_local_path_lexical(path: Path) -> None:
    text = str(path)
    if text != text.strip():
        raise MemoryError("vault path has leading or trailing whitespace")
    lexical_parts = text.replace("\\", "/").split("/")
    if any(part in {".", ".."} for part in lexical_parts):
        raise MemoryError("vault path contains a lexical dot segment")
    for part in lexical_parts:
        if not part or (len(part) == 2 and part[1] == ":"):
            continue
        if part.endswith((".", " ")):
            raise MemoryError("vault path contains a Windows-normalized component")
        basename = part.split(".", maxsplit=1)[0].rstrip(" .").upper()
        if basename in _WINDOWS_RESERVED_BASENAMES:
            raise MemoryError("vault path contains a reserved Windows device name")
    if not path.is_absolute():
        raise MemoryError("vault path must be absolute")
    normalized = text.replace("/", "\\")
    if normalized.startswith(("\\\\", "\\?\\", "\\.\\")):
        raise MemoryError("device, UNC, and network paths are not allowed")
    drive, tail = os.path.splitdrive(text)
    if ":" in tail:
        raise MemoryError("alternate data stream paths are not allowed")


def validate_local_file_path(path: Path) -> None:
    validate_local_path_lexical(path)
    try:
        if _has_redirected_component(path):
            raise MemoryError("vault path contains a link or reparse point")
        current = os.lstat(path)
    except FileNotFoundError as error:
        raise MemoryError("vault source does not exist") from error
    except OSError as error:
        raise MemoryError("vault path ancestry could not be verified") from error
    if stat.S_ISLNK(current.st_mode) or _is_reparse_point(current):
        raise MemoryError("vault source is a link or reparse point")
    if not stat.S_ISREG(current.st_mode):
        raise MemoryError("vault source must be a regular file")
    if os.name != "nt":
        _verify_posix_ancestors(path)
        if current.st_uid != _current_user_id():
            raise MemoryError("vault source is not owned by the current user")
        if stat.S_IMODE(current.st_mode) & 0o022:
            raise MemoryError("vault source grants unsafe write access")


def prepare_backup_directory(path: Path) -> None:
    if not path.is_absolute():
        raise MemoryError("backup directory must be absolute")
    try:
        if _has_redirected_component(path):
            raise MemoryError("backup path contains a link or reparse point")
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        current = os.lstat(path)
    except OSError as error:
        raise MemoryError("backup directory could not be secured") from error
    if not stat.S_ISDIR(current.st_mode) or stat.S_ISLNK(current.st_mode):
        raise MemoryError("backup path is not a direct directory")
    if os.name != "nt":
        _verify_posix_ancestors(path / ".zombie-killer-boundary")
        if current.st_uid != _current_user_id():
            raise MemoryError("backup directory is not owned by the current user")
        os.chmod(path, 0o700)
    else:
        try:
            WindowsPermissionBackend().restrict(path)
        except OSError as error:
            raise MemoryError("backup directory DACL could not be secured") from error


def secure_created_file(path: Path) -> None:
    if os.name != "nt":
        os.chmod(path, 0o600, follow_symlinks=False)
        return
    try:
        from zombie_killer_engine.store import _restrict_windows_database_file

        _restrict_windows_database_file(path)
    except Exception as error:
        raise MemoryError("created file DACL could not be secured") from error


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


def _windows_security_handle(path: Path, *, write_dacl: bool) -> tuple[object, int]:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.restype = ctypes.c_void_p
    access = 0x00020000 | (0x00040000 if write_dacl else 0)
    handle = kernel32.CreateFileW(
        str(path),
        access,
        0x00000007,
        None,
        3,
        0x00200000,
        None,
    )
    if handle == ctypes.c_void_p(-1).value:
        raise MemoryError("file security handle could not be opened")
    information = _WindowsFileInformation()
    if not kernel32.GetFileInformationByHandle(handle, ctypes.byref(information)):
        kernel32.CloseHandle(handle)
        raise MemoryError("file security identity could not be read")
    inode = (information.file_index_high << 32) | information.file_index_low
    return handle, inode


def _windows_descriptor(handle: object) -> tuple[bytes, str, int]:
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    required = ctypes.c_ulong()
    security_information = 0x00000001 | 0x00000004
    advapi32.GetKernelObjectSecurity(handle, security_information, None, 0, ctypes.byref(required))
    if required.value == 0:
        raise MemoryError("file security descriptor size could not be read")
    buffer = ctypes.create_string_buffer(required.value)
    if not advapi32.GetKernelObjectSecurity(
        handle,
        security_information,
        buffer,
        required.value,
        ctypes.byref(required),
    ):
        raise MemoryError("file security descriptor could not be read")
    control = ctypes.c_ushort()
    revision = ctypes.c_ulong()
    if not advapi32.GetSecurityDescriptorControl(
        buffer, ctypes.byref(control), ctypes.byref(revision)
    ):
        raise MemoryError("file security descriptor control could not be read")
    rendered = ctypes.c_wchar_p()
    if not advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
        buffer,
        1,
        security_information,
        ctypes.byref(rendered),
        None,
    ):
        raise MemoryError("file security descriptor could not be normalized")
    try:
        sddl = rendered.value or ""
    finally:
        ctypes.WinDLL("kernel32", use_last_error=True).LocalFree(rendered)
    return bytes(buffer.raw[: required.value]), sddl, int(control.value)


def capture_file_security(path: Path) -> SourceFileSecurity:
    """Capture source permissions through a no-follow, identity-checked handle."""
    try:
        named = os.lstat(path)
        if os.name == "nt":
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            handle, inode = _windows_security_handle(path, write_dacl=False)
            try:
                if inode != named.st_ino:
                    raise MemoryError("file changed while capturing security")
                descriptor, sddl, control = _windows_descriptor(handle)
            finally:
                kernel32.CloseHandle(handle)
            return SourceFileSecurity(
                mode=stat.S_IMODE(named.st_mode),
                uid=named.st_uid,
                gid=named.st_gid,
                windows_descriptor=descriptor,
                windows_sddl=sddl,
                windows_control=control,
            )
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor_fd = os.open(path, flags)
        try:
            opened = os.fstat(descriptor_fd)
            if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
                raise MemoryError("file changed while capturing security")
            acl: bytes | None = None
            try:
                acl = os.getxattr(  # type: ignore[attr-defined]
                    descriptor_fd, "system.posix_acl_access"
                )
            except OSError as error:
                if error.errno not in {
                    errno.ENODATA,
                    errno.ENOTSUP,
                    getattr(errno, "EOPNOTSUPP", errno.ENOTSUP),
                }:
                    raise
            return SourceFileSecurity(
                mode=stat.S_IMODE(opened.st_mode),
                uid=opened.st_uid,
                gid=opened.st_gid,
                posix_acl=acl,
            )
        finally:
            os.close(descriptor_fd)
    except MemoryError:
        raise
    except OSError as error:
        raise MemoryError("file security could not be captured") from error


def apply_file_security(
    path: Path,
    descriptor_fd: int,
    security: SourceFileSecurity,
) -> None:
    """Apply captured permissions to a pinned replacement and verify equivalence."""
    try:
        expected = os.fstat(descriptor_fd)
        if os.name == "nt":
            if (
                security.windows_descriptor is None
                or security.windows_sddl is None
                or security.windows_control is None
            ):
                raise MemoryError("Windows source security authority is incomplete")
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
            handle, inode = _windows_security_handle(path, write_dacl=True)
            try:
                if inode != expected.st_ino:
                    raise MemoryError("replacement changed while applying security")
                source_descriptor = ctypes.create_string_buffer(security.windows_descriptor)
                dacl_present = ctypes.c_int()
                dacl_defaulted = ctypes.c_int()
                dacl = ctypes.c_void_p()
                if (
                    not advapi32.GetSecurityDescriptorDacl(
                        source_descriptor,
                        ctypes.byref(dacl_present),
                        ctypes.byref(dacl),
                        ctypes.byref(dacl_defaulted),
                    )
                    or not dacl_present.value
                ):
                    raise MemoryError("selected source DACL could not be read")
                protected = bool(security.windows_control & 0x1000)
                auto_inherited = bool(security.windows_control & 0x0400)

                def set_dacl(security_information: int) -> None:
                    result = advapi32.SetSecurityInfo(
                        handle,
                        1,
                        security_information,
                        None,
                        None,
                        dacl,
                        None,
                    )
                    if result != 0:
                        raise MemoryError("replacement DACL could not be preserved")

                if auto_inherited:
                    set_dacl(0x00000004 | 0x20000000)
                    if protected:
                        set_dacl(0x00000004 | 0x80000000)
                elif protected:
                    set_dacl(0x00000004 | 0x80000000)
                elif not advapi32.SetKernelObjectSecurity(handle, 0x00000004, source_descriptor):
                    raise MemoryError("replacement DACL could not be preserved")
                _descriptor, rendered, observed_control = _windows_descriptor(handle)
                relevant_control = 0x0100 | 0x0400 | 0x1000
                if (
                    rendered != security.windows_sddl
                    or observed_control & relevant_control
                    != security.windows_control & relevant_control
                ):
                    raise MemoryError("replacement DACL differs from selected source")
            finally:
                kernel32.CloseHandle(handle)
            return
        os.fchown(descriptor_fd, security.uid, security.gid)  # type: ignore[attr-defined]
        os.fchmod(descriptor_fd, security.mode)  # type: ignore[attr-defined]
        if security.posix_acl is None:
            try:
                os.removexattr(  # type: ignore[attr-defined]
                    descriptor_fd, "system.posix_acl_access"
                )
            except OSError as error:
                if error.errno not in {
                    errno.ENODATA,
                    errno.ENOTSUP,
                    getattr(errno, "EOPNOTSUPP", errno.ENOTSUP),
                }:
                    raise
        else:
            os.setxattr(  # type: ignore[attr-defined]
                descriptor_fd, "system.posix_acl_access", security.posix_acl
            )
        observed = capture_file_security(path)
        if observed != security:
            raise MemoryError("replacement permissions differ from selected source")
    except MemoryError:
        raise
    except OSError as error:
        raise MemoryError("replacement permissions could not be preserved") from error


def identity_from_stat(value: os.stat_result) -> FileIdentity:
    return FileIdentity(
        device=value.st_dev,
        inode=value.st_ino,
        size=value.st_size,
        mtime_ns=value.st_mtime_ns,
        ctime_ns=value.st_ctime_ns,
        mode=value.st_mode,
    )


def same_identity(left: FileIdentity, right: FileIdentity, *, content_change: bool) -> bool:
    if (left.device, left.inode, left.mode) != (right.device, right.inode, right.mode):
        return False
    return content_change or left == right


def read_pinned(path: Path, *, max_bytes: int) -> tuple[bytes, FileIdentity]:
    validate_local_file_path(path)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise MemoryError("vault source could not be opened safely") from error
    try:
        opened = os.fstat(descriptor)
        named = os.lstat(path)
        if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
            raise MemoryError("vault source changed while opening")
        if opened.st_size > max_bytes:
            raise MemoryError("vault source exceeds configured size limit")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > max_bytes:
            raise MemoryError("vault source exceeds configured size limit")
        after = os.fstat(descriptor)
        if identity_from_stat(opened) != identity_from_stat(after):
            raise MemoryError("vault source changed during read")
        validate_local_file_path(path)
        # Windows CRT fstat and path stat expose different ctime semantics;
        # compare each observation through the same API while retaining the
        # device/inode binding between the handle and the name.
        if identity_from_stat(os.lstat(path)) != identity_from_stat(named):
            raise MemoryError("vault named source changed during read")
        return data, identity_from_stat(after)
    finally:
        os.close(descriptor)


def read_prefix_pinned(path: Path, *, prefix_bytes: int) -> tuple[bytes, FileIdentity]:
    validate_local_file_path(path)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise MemoryError("vault source could not be opened safely") from error
    try:
        before = os.fstat(descriptor)
        named = os.lstat(path)
        if (before.st_dev, before.st_ino) != (named.st_dev, named.st_ino):
            raise MemoryError("vault source changed while probing")
        prefix = os.read(descriptor, prefix_bytes)
        after = os.fstat(descriptor)
        if identity_from_stat(before) != identity_from_stat(after):
            raise MemoryError("vault source changed during probe")
        validate_local_file_path(path)
        if identity_from_stat(os.lstat(path)) != identity_from_stat(named):
            raise MemoryError("vault named source changed during probe")
        return prefix, identity_from_stat(after)
    finally:
        os.close(descriptor)


def plan_digest(plan: MutationPlan) -> str:
    payload = plan.model_dump(mode="json", exclude={"digest", "operation"})
    return canonical_hash(payload)


def authority_plan_digest(authority: MemoryPlanAuthority) -> str:
    if len(authority.field_names) != 1:
        raise MemoryError("persisted mutation authority has invalid fields")
    payload = {
        "plan_id": authority.plan_id,
        "source_id": authority.source_id,
        "source_revision": authority.source_revision,
        "source_identity": authority.source_identity.model_dump(mode="json"),
        "operation_kind": authority.operation_kind.value,
        "record_id": authority.record_id,
        "record_hash": authority.record_hash,
        "operation_field": authority.operation_field,
        "operation_metadata_key": authority.operation_metadata_key,
        "proposed_value_hash": authority.proposed_value_hash,
        "proposed_value_type": authority.proposed_value_type,
        "field_name": authority.field_names[0],
        "expected_old_hash": authority.expected_old_hash,
        "old_store_hash": authority.old_store_hash,
        "new_store_hash": authority.new_store_hash,
        "diff": [item.model_dump(mode="json") for item in authority.diff],
        "created_at": authority.created_at.isoformat().replace("+00:00", "Z"),
        "expires_at": authority.expires_at.isoformat().replace("+00:00", "Z"),
    }
    return canonical_hash(payload)


def restore_plan_digest(plan: RestorePlan) -> str:
    return canonical_hash(plan.model_dump(mode="json", exclude={"digest"}))


def new_restore_plan(
    *,
    source: Path,
    snapshot: Snapshot,
    expected_revision: str,
    source_identity: FileIdentity,
    before_hash: str,
    target_hash: str,
    now: datetime | None = None,
) -> RestorePlan:
    created = now or utc_now()
    key = canonical_hash(
        {
            "source_id": source_id(source),
            "snapshot_id": snapshot.snapshot_id,
            "snapshot_digest": snapshot.digest,
            "expected_revision": expected_revision,
        }
    )
    temporary = RestorePlan(
        restore_plan_id="memory-restore-" + secrets.token_hex(16),
        restore_key=key,
        source_id=source_id(source),
        snapshot_id=snapshot.snapshot_id,
        snapshot_digest=snapshot.digest,
        expected_revision=expected_revision,
        source_identity=source_identity,
        before_hash=before_hash,
        target_hash=target_hash,
        created_at=created,
        expires_at=created + PLAN_LIFETIME,
        digest="0" * 64,
    )
    return temporary.model_copy(update={"digest": restore_plan_digest(temporary)})


def new_plan(
    *,
    source: Path,
    revision: str,
    identity: FileIdentity,
    operation: MutationOperation,
    record_hash: str,
    field_name: str,
    old_hash: str,
    old_store_hash: str,
    new_hash: str,
    new_store_hash: str,
    now: datetime | None = None,
) -> MutationPlan:
    created = now or utc_now()
    temporary = MutationPlan(
        plan_id="memory-plan-" + secrets.token_hex(16),
        source_id=source_id(source),
        source_revision=revision,
        source_identity=identity,
        operation_kind=operation.kind,
        record_id=operation.record_id,
        record_hash=record_hash,
        operation_field=operation.field,
        operation_metadata_key=operation.metadata_key,
        proposed_value_hash=canonical_hash(operation.unsealed_value()),
        proposed_value_type=_scalar_type(operation.unsealed_value()),
        field_name=field_name,
        expected_old_hash=old_hash,
        old_store_hash=old_store_hash,
        new_store_hash=new_store_hash,
        diff=(FieldDiff(field_name=field_name, old_hash=old_hash, new_hash=new_hash),),
        created_at=created,
        expires_at=created + PLAN_LIFETIME,
        digest="0" * 64,
        operation=operation,
    )
    return temporary.model_copy(update={"digest": plan_digest(temporary)})


def verify_plan(plan: MutationPlan, *, now: datetime | None = None) -> None:
    if not secrets.compare_digest(plan.digest, plan_digest(plan)):
        raise MemoryError("mutation plan was tampered")
    if (now or utc_now()) >= plan.expires_at:
        raise MemoryError("mutation plan expired")
    operation = plan.operation
    if (
        operation.kind is not plan.operation_kind
        or operation.record_id != plan.record_id
        or operation.field != plan.operation_field
        or operation.metadata_key != plan.operation_metadata_key
        or canonical_hash(operation.unsealed_value()) != plan.proposed_value_hash
        or _scalar_type(operation.unsealed_value()) != plan.proposed_value_type
    ):
        raise MemoryError("mutation plan operation was tampered")


def verify_authority(plan: MutationPlan, authority: MemoryPlanAuthority) -> None:
    expected = (
        plan.plan_id,
        plan.source_id,
        plan.digest,
        plan.source_revision,
        plan.source_identity,
        plan.operation_kind,
        plan.record_id,
        plan.record_hash,
        plan.operation_field,
        plan.operation_metadata_key,
        plan.proposed_value_hash,
        plan.proposed_value_type,
        tuple(item.field_name for item in plan.diff),
        plan.diff,
        plan.expected_old_hash,
        plan.old_store_hash,
        plan.new_store_hash,
        plan.created_at,
        plan.expires_at,
    )
    persisted = (
        authority.plan_id,
        authority.source_id,
        authority.digest,
        authority.source_revision,
        authority.source_identity,
        authority.operation_kind,
        authority.record_id,
        authority.record_hash,
        authority.operation_field,
        authority.operation_metadata_key,
        authority.proposed_value_hash,
        authority.proposed_value_type,
        authority.field_names,
        authority.diff,
        authority.expected_old_hash,
        authority.old_store_hash,
        authority.new_store_hash,
        authority.created_at,
        authority.expires_at,
    )
    if expected != persisted:
        raise MemoryError("persisted mutation authority was tampered")


def _scalar_type(value: JsonScalar) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "real"
    return "string"


@contextmanager
def exclusive_file_lock(path: Path) -> Iterator[None]:
    lock_path = path.with_name(path.name + ".zombie-killer.lock")
    flags = os.O_RDWR | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= os.O_CREAT
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as error:
        raise MemoryError("vault lock could not be opened safely") from error
    try:
        secure_created_file(lock_path)
        if os.name == "nt":
            import msvcrt

            if os.fstat(descriptor).st_size == 0:
                os.write(descriptor, b"0")
                os.fsync(descriptor)
            lock_offset = 0
            os.lseek(descriptor, 0, os.SEEK_SET)
            try:
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            except OSError as error:
                raise MemoryError("vault source has an active writer") from error
            try:
                yield
            finally:
                os.lseek(descriptor, lock_offset, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            try:
                fcntl.flock(  # type: ignore[attr-defined]
                    descriptor,
                    fcntl.LOCK_EX | fcntl.LOCK_NB,  # type: ignore[attr-defined]
                )
            except OSError as error:
                raise MemoryError("vault source has an active writer") from error
            try:
                yield
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)  # type: ignore[attr-defined]
    finally:
        os.close(descriptor)


def fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise MemoryError("directory durability could not be verified") from error


class UnsupportedReadOnlyAdapter:
    """Explicit recognition result for undocumented Chroma/FAISS internals."""

    def __init__(self, path: Path, *, format: VaultFormat, reason: str) -> None:
        validate_local_file_path(path)
        self.path = path
        self.format = format
        self.reason = reason

    @classmethod
    def probe(cls, path: Path) -> ProbeResult:
        prefix, _identity = read_prefix_pinned(path, prefix_bytes=16)
        recognized = path.suffix.casefold() in {".faiss", ".index"} and prefix.startswith(
            (b"IxF", b"IwF", b"IL")
        )
        reason = (
            "recognized FAISS index is inventory-only; undocumented internals are not loaded"
            if recognized
            else "file is not a recognized supported read-only vector index"
        )
        return ProbeResult(
            format=VaultFormat.FAISS if recognized else VaultFormat.UNSUPPORTED,
            recognized=recognized,
            capabilities=VaultCapabilities(
                readable=recognized,
                queryable=False,
                editable=False,
                snapshot=False,
                restore=False,
                reason=reason,
            ),
            reason=reason,
        )

    def open(self, *, read_only: bool) -> UnsupportedReadOnlyAdapter:
        if not read_only:
            raise MemoryError(self.reason)
        return self

    def capabilities(self) -> VaultCapabilities:
        readable = self.format in {VaultFormat.CHROMA, VaultFormat.FAISS}
        return VaultCapabilities(
            readable=readable,
            queryable=False,
            editable=False,
            snapshot=False,
            restore=False,
            reason=self.reason,
        )

    def list_namespaces(self) -> tuple[str, ...]:
        return ()

    def query(
        self,
        *,
        cursor: str | None = None,
        limit: int = 100,
        filter: QueryFilter | None = None,
        namespace: str | None = None,
    ) -> QueryPage:
        del cursor, limit, filter, namespace
        raise MemoryError("recognized read-only format does not support record queries")

    def get(self, record_id: str) -> MemoryRecord:
        del record_id
        raise MemoryError("recognized read-only format does not support record queries")

    def current_revision(self) -> str:
        data, _identity = read_pinned(self.path, max_bytes=512 * 1024 * 1024)
        return sha256_bytes(data)

    def plan_mutation(
        self, operation: MutationOperation, *, expected_revision: str
    ) -> MutationPlan:
        del operation, expected_revision
        raise MemoryError("recognized format is read-only and mutation is unsupported")

    def backup(self, *, expected_revision: str) -> Snapshot:
        del expected_revision
        raise MemoryError("recognized format is read-only and snapshots are unsupported")

    def apply(self, plan: MutationPlan) -> MemoryReceipt:
        del plan
        raise MemoryError("recognized format is read-only and mutation is unsupported")

    def healthcheck(self) -> None:
        self.current_revision()

    def restore(
        self,
        snapshot_id: str,
        *,
        expected_snapshot_digest: str,
        expected_revision: str,
        reviewed_expires_at: datetime | None = None,
    ) -> MemoryReceipt:
        del snapshot_id, expected_snapshot_digest, expected_revision, reviewed_expires_at
        raise MemoryError("recognized format is read-only and restore is unsupported")


__all__ = [
    "FieldDiff",
    "FileIdentity",
    "MemoryAdapter",
    "MemoryError",
    "MemoryPlanAuthority",
    "MemoryReceipt",
    "MemoryRecord",
    "MemoryStateStore",
    "MutationKind",
    "MutationOperation",
    "MutationPlan",
    "NamespaceInventory",
    "ProbeResult",
    "QueryFilter",
    "QueryPage",
    "RestoreAuthority",
    "RestorePlan",
    "Snapshot",
    "SnapshotStatus",
    "UnsupportedReadOnlyAdapter",
    "VaultCapabilities",
    "VaultFormat",
    "VaultSource",
]
