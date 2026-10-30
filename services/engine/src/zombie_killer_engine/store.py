"""SQLite persistence for short-lived plans, receipts, and bounded audit data."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import secrets
import sqlite3
import stat
import threading
import time
import weakref
from collections.abc import Callable, Mapping
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

import psutil  # type: ignore[import-untyped]
from pydantic import Field, TypeAdapter, field_validator

from zombie_killer_engine.actions import (
    ActionPlan,
    ActionReceipt,
    ActionResult,
    PlanStatus,
)
from zombie_killer_engine.models import (
    CodeText,
    DomainModel,
    IdentifierText,
    UtcDatetime,
)
from zombie_killer_engine.paths import (
    AppPaths,
    PosixPermissionBackend,
    WindowsPermissionBackend,
    _open_directory_nofollow,
)
from zombie_killer_engine.redaction import redact_mapping, redact_text

if TYPE_CHECKING:
    from zombie_killer_engine.memory import (
        MemoryPlanAuthority,
        MemoryReceipt,
        MutationPlan,
        RestoreAuthority,
        RestorePlan,
        Snapshot,
        VaultSource,
    )
    from zombie_killer_engine.quarantine import (
        LegacyRecoveryReason,
        LegacyRestorePlan,
        QuarantineEntry,
        QuarantinePlan,
        QuarantineReceipt,
        QuarantineResult,
        QuarantineState,
    )


_SCHEMA_VERSION = 13
_DEFAULT_BUSY_TIMEOUT_MS = 5_000
_DEFAULT_MAX_JSON_BYTES = 65_536
_IDENTIFIER_ADAPTER = TypeAdapter(IdentifierText)
_MEMORY_HEARTBEAT_LIFETIME = timedelta(seconds=60)
_PROCESS_MEMORY_SESSION_LOCK = threading.Lock()
_PROCESS_MEMORY_SESSIONS: set[str] = set()
_WORKFLOW_RECEIPT_KINDS = {
    "quarantine_execution": "quarantine",
    "quarantine_restore": "quarantine",
    "memory_mutation": "memory",
    "memory_restore": "memory",
    "diagnostics_export": "diagnostics",
}


def _discard_process_memory_session(session_nonce: str) -> None:
    with _PROCESS_MEMORY_SESSION_LOCK:
        _PROCESS_MEMORY_SESSIONS.discard(session_nonce)


class StoreError(RuntimeError):
    """Base error for state transitions that cannot safely be completed."""


class SettingsRevisionConflict(StoreError):
    """A settings compare-and-swap used a stale persisted revision."""


class PlanClaimError(StoreError):
    pass


class ExpiredPlanError(PlanClaimError):
    pass


class StorePathError(StoreError):
    pass


@dataclass(frozen=True, slots=True)
class QuarantineEntryListing:
    entry: QuarantineEntry
    restoring: bool


def _is_memory_journal_unavailable(error: Exception) -> bool:
    if isinstance(error, (StorePathError, PermissionError, OSError)):
        return True
    if not isinstance(error, sqlite3.Error):
        return False
    code = getattr(error, "sqlite_errorcode", None)
    if not isinstance(code, int):
        return False
    primary_code = code & 0xFF
    return primary_code in {
        sqlite3.SQLITE_AUTH,
        sqlite3.SQLITE_BUSY,
        sqlite3.SQLITE_CANTOPEN,
        sqlite3.SQLITE_CORRUPT,
        sqlite3.SQLITE_FULL,
        sqlite3.SQLITE_INTERRUPT,
        sqlite3.SQLITE_IOERR,
        sqlite3.SQLITE_LOCKED,
        sqlite3.SQLITE_NOTADB,
        sqlite3.SQLITE_PERM,
        sqlite3.SQLITE_PROTOCOL,
        sqlite3.SQLITE_READONLY,
    }


class StoreSecurityBackend(Protocol):
    """Fail-closed path preparation and database permission boundary."""

    def prepare_state_directory(self, path: Path) -> None: ...

    def secure_database(self, path: Path, *, allow_missing: bool) -> None: ...


class AuditEventDetails(DomainModel):
    """The only caller-supplied fields permitted in a generic audit event."""

    result: CodeText
    target_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    resource_ids: tuple[IdentifierText, ...] = Field(default=(), max_length=64)
    metadata_hashes: tuple[str, ...] = Field(
        default=(),
        max_length=64,
    )

    @field_validator("result", mode="before")
    @classmethod
    def _sanitize_result(cls, value: object) -> str:
        cleaned = redact_text(value, max_length=128).strip()
        return cleaned or "[REDACTED]"

    @field_validator("resource_ids", mode="before")
    @classmethod
    def _sanitize_resource_ids(cls, values: object) -> object:
        if not isinstance(values, (tuple, list)):
            return values
        return tuple(redact_text(value, max_length=256).strip() or "[REDACTED]" for value in values)

    @field_validator("metadata_hashes")
    @classmethod
    def _validate_metadata_hashes(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(
            len(value) != 64 or any(character not in "0123456789abcdef" for character in value)
            for value in values
        ):
            raise ValueError("metadata hashes must be lowercase SHA-256 values")
        return values


class _AuditEventEnvelope(DomainModel):
    event_id: IdentifierText
    correlation_id: IdentifierText
    event_type: CodeText
    details: AuditEventDetails
    created_at: UtcDatetime


class _StoreSidAndAttributes(ctypes.Structure):
    _fields_ = (("sid", ctypes.c_void_p), ("attributes", ctypes.c_ulong))


class _StoreTokenUser(ctypes.Structure):
    _fields_ = (("user", _StoreSidAndAttributes),)


def _is_reparse_point(path_stat: os.stat_result) -> bool:
    attributes = getattr(path_stat, "st_file_attributes", 0)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(attributes & flag)


def _reject_redirected_ancestry(path: Path) -> None:
    current = path.absolute()
    while True:
        try:
            current_stat = os.lstat(current)
        except FileNotFoundError:
            pass
        except OSError as error:
            raise StorePathError("application path ancestry could not be verified") from error
        else:
            if stat.S_ISLNK(current_stat.st_mode) or _is_reparse_point(current_stat):
                raise StorePathError("application path contains a link or reparse point")
        parent = current.parent
        if parent == current:
            return
        current = parent


def _restrict_windows_database_file(path: Path) -> None:
    if os.name != "nt":
        raise StorePathError("Windows file security APIs are unavailable")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32.CreateFileW.restype = ctypes.c_void_p
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
    advapi32.OpenProcessToken.argtypes = (
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_void_p),
    )
    advapi32.EqualSid.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
    advapi32.EqualSid.restype = ctypes.c_int
    advapi32.GetKernelObjectSecurity.argtypes = (
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_ulong),
    )
    advapi32.SetKernelObjectSecurity.argtypes = (
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_void_p,
    )
    handle = kernel32.CreateFileW(
        str(path),
        0x00020000 | 0x00040000,
        0x00000007,
        None,
        3,
        0x00200000,
        None,
    )
    if handle == ctypes.c_void_p(-1).value:
        raise StorePathError("database file security handle could not be opened")
    descriptor = ctypes.c_void_p()
    try:
        owner_size = ctypes.c_ulong()
        advapi32.GetKernelObjectSecurity(
            handle,
            0x00000001,
            None,
            0,
            ctypes.byref(owner_size),
        )
        if owner_size.value == 0:
            raise StorePathError("database owner could not be read")
        owner_descriptor = ctypes.create_string_buffer(owner_size.value)
        if not advapi32.GetKernelObjectSecurity(
            handle,
            0x00000001,
            owner_descriptor,
            owner_size.value,
            ctypes.byref(owner_size),
        ):
            raise StorePathError("database owner could not be read")
        owner_sid = ctypes.c_void_p()
        owner_defaulted = ctypes.c_int()
        if not advapi32.GetSecurityDescriptorOwner(
            owner_descriptor,
            ctypes.byref(owner_sid),
            ctypes.byref(owner_defaulted),
        ):
            raise StorePathError("database owner SID could not be read")
        token_handle = ctypes.c_void_p()
        if not advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(),
            0x0008,
            ctypes.byref(token_handle),
        ):
            raise StorePathError("current user token could not be opened")
        try:
            token_size = ctypes.c_ulong()
            advapi32.GetTokenInformation(
                token_handle,
                1,
                None,
                0,
                ctypes.byref(token_size),
            )
            if token_size.value == 0:
                raise StorePathError("current owner SID size could not be read")
            token_buffer = ctypes.create_string_buffer(token_size.value)
            if not advapi32.GetTokenInformation(
                token_handle,
                1,
                token_buffer,
                token_size.value,
                ctypes.byref(token_size),
            ):
                raise StorePathError("current owner SID could not be read")
            token_user = ctypes.cast(
                token_buffer,
                ctypes.POINTER(_StoreTokenUser),
            ).contents
            if not advapi32.EqualSid(owner_sid, token_user.user.sid):
                raise StorePathError("database file is not owned by the current user")
        finally:
            kernel32.CloseHandle(token_handle)
        if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            "D:P(A;;FA;;;OW)(A;;FA;;;SY)",
            1,
            ctypes.byref(descriptor),
            None,
        ):
            raise StorePathError("database security descriptor could not be created")
        if not advapi32.SetKernelObjectSecurity(
            handle,
            0x00000004 | 0x80000000,
            descriptor,
        ):
            raise StorePathError("database DACL could not be restricted")
        required = ctypes.c_ulong()
        advapi32.GetKernelObjectSecurity(
            handle,
            0x00000004,
            None,
            0,
            ctypes.byref(required),
        )
        if required.value == 0:
            raise StorePathError("database DACL size could not be read")
        current = ctypes.create_string_buffer(required.value)
        if not advapi32.GetKernelObjectSecurity(
            handle,
            0x00000004,
            current,
            required.value,
            ctypes.byref(required),
        ):
            raise StorePathError("database DACL could not be read")
        control = ctypes.c_ushort()
        revision = ctypes.c_ulong()
        if (
            not advapi32.GetSecurityDescriptorControl(
                current,
                ctypes.byref(control),
                ctypes.byref(revision),
            )
            or not control.value & 0x1000
        ):
            raise StorePathError("database DACL inheritance remains enabled")
    finally:
        if descriptor.value:
            kernel32.LocalFree(descriptor)
        kernel32.CloseHandle(handle)


class DefaultStoreSecurityBackend:
    """Restrict and verify store paths before every SQLite open."""

    def prepare_state_directory(self, path: Path) -> None:
        _reject_redirected_ancestry(path)
        try:
            if os.name == "nt":
                path.mkdir(mode=0o700, parents=True, exist_ok=True)
            else:
                descriptor = _open_directory_nofollow(path, create=True)
                os.close(descriptor)
        except OSError as error:
            raise StorePathError("state directory could not be created safely") from error
        _reject_redirected_ancestry(path)
        path_stat = os.lstat(path)
        if not stat.S_ISDIR(path_stat.st_mode) or _is_reparse_point(path_stat):
            raise StorePathError("state path is not a direct directory")
        backend = WindowsPermissionBackend() if os.name == "nt" else PosixPermissionBackend()
        try:
            backend.restrict(path)
        except OSError as error:
            raise StorePathError("state directory permissions could not be restricted") from error
        self._verify_directory_permissions(path)

    def secure_database(self, path: Path, *, allow_missing: bool) -> None:
        _reject_redirected_ancestry(path)
        try:
            path_stat = os.lstat(path)
        except FileNotFoundError:
            if allow_missing:
                return
            raise StorePathError("database file does not exist") from None
        except OSError as error:
            raise StorePathError("database file could not be inspected") from error
        if not stat.S_ISREG(path_stat.st_mode) or _is_reparse_point(path_stat):
            raise StorePathError("database path is not an owned regular direct file")
        self._verify_directory_permissions(path.parent)
        if os.name != "nt":
            geteuid = getattr(os, "geteuid", None)
            if geteuid is None or path_stat.st_uid != int(geteuid()):
                raise StorePathError("database file is not owned by the current user")
            try:
                os.chmod(path, 0o600, follow_symlinks=False)
            except OSError as error:
                raise StorePathError("database file permissions could not be restricted") from error
            restricted = os.lstat(path)
            if restricted.st_mode & 0o077:
                raise StorePathError("database file permissions are not restrictive")
        else:
            try:
                WindowsPermissionBackend().restrict(path.parent)
            except OSError as error:
                raise StorePathError("database DACL ancestry could not be verified") from error
            _restrict_windows_database_file(path)
        _reject_redirected_ancestry(path)

    @staticmethod
    def _verify_directory_permissions(path: Path) -> None:
        directory_stat = os.lstat(path)
        if not stat.S_ISDIR(directory_stat.st_mode) or _is_reparse_point(directory_stat):
            raise StorePathError("database parent is not a direct directory")
        if os.name != "nt":
            geteuid = getattr(os, "geteuid", None)
            if geteuid is None or directory_stat.st_uid != int(geteuid()):
                raise StorePathError("database parent is not owned by the current user")
            if directory_stat.st_mode & 0o077:
                raise StorePathError("database parent permissions are not restrictive")


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _require_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(UTC)


def _utc_text(value: datetime) -> str:
    return _require_utc(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_utc(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    return _require_utc(datetime.fromisoformat(normalized))


def _session_fingerprint(value: str) -> str:
    return "session-" + hashlib.sha256(f"session\0{value}".encode()).hexdigest()


class SQLiteStateStore:
    """Open-per-operation SQLite store with transactional state transitions."""

    schema_version = _SCHEMA_VERSION

    def __init__(
        self,
        paths: AppPaths,
        *,
        busy_timeout_ms: int = _DEFAULT_BUSY_TIMEOUT_MS,
        max_json_bytes: int = _DEFAULT_MAX_JSON_BYTES,
        security_backend: StoreSecurityBackend | None = None,
        clock: Callable[[], datetime] | None = None,
        session_id: str | None = None,
        is_session_alive: Callable[[str], bool] | None = None,
    ) -> None:
        if busy_timeout_ms < 0 or busy_timeout_ms > 120_000:
            raise ValueError("busy_timeout_ms must be between 0 and 120000")
        if max_json_bytes < 256 or max_json_bytes > 1_048_576:
            raise ValueError("max_json_bytes must be between 256 and 1048576")
        self.database_path = paths.state_dir / "zombie-killer.sqlite3"
        self._state_dir = paths.state_dir
        self._backups_dir = paths.backups_dir
        self._busy_timeout_ms = busy_timeout_ms
        self._max_json_bytes = max_json_bytes
        self._security_backend = security_backend or DefaultStoreSecurityBackend()
        self._clock = clock or _utc_now
        self.session_id = session_id or secrets.token_urlsafe(24)
        if not self.session_id.strip() or len(self.session_id) > 256:
            raise ValueError("session_id must be non-empty and bounded")
        self._session_fingerprint = _session_fingerprint(self.session_id)
        self._memory_session_nonce = "memory-session-" + secrets.token_hex(24)
        with _PROCESS_MEMORY_SESSION_LOCK:
            _PROCESS_MEMORY_SESSIONS.add(self._memory_session_nonce)
        self._memory_session_finalizer = weakref.finalize(
            self, _discard_process_memory_session, self._memory_session_nonce
        )
        self._is_session_alive = is_session_alive
        self._owner_pid = os.getpid()
        self._owner_create_time = psutil.Process(self._owner_pid).create_time()
        self._session_cleanup_needed = False
        self._initialized = False
        self._closed = False

    def _connect(self, *, allow_missing: bool = False) -> sqlite3.Connection:
        self._security_backend.secure_database(
            self.database_path,
            allow_missing=allow_missing,
        )
        try:
            connection = sqlite3.connect(
                self.database_path,
                timeout=self._busy_timeout_ms / 1000,
                isolation_level=None,
            )
        except sqlite3.Error:
            raise
        try:
            self._security_backend.secure_database(
                self.database_path,
                allow_missing=False,
            )
        except BaseException:
            connection.close()
            raise
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(f"PRAGMA busy_timeout = {self._busy_timeout_ms}")
        return connection

    def initialize(self, *, now: datetime | None = None) -> None:
        if self._closed:
            raise StoreError("closed state store cannot be initialized")
        initialized_at = _require_utc(now or _utc_now())
        self._security_backend.prepare_state_directory(self._state_dir)
        with closing(self._connect(allow_missing=True)) as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._ensure_version_table(connection)
                current = self._current_version(connection)
                if current > _SCHEMA_VERSION:
                    raise StoreError("database schema is newer than this application")
                for version in range(current + 1, _SCHEMA_VERSION + 1):
                    self._apply_migration(connection, version)
                    connection.execute(
                        "INSERT OR IGNORE INTO schema_versions(version, applied_at) VALUES (?, ?)",
                        (version, _utc_text(initialized_at)),
                    )
                    connection.execute(f"PRAGMA user_version = {version}")
                self._register_memory_session(connection, initialized_at)
                self._reconcile_running(
                    connection,
                    now=initialized_at,
                    check_owner=True,
                )
                self._reconcile_memory_running(connection)
                self._reconcile_memory_restore_running(connection)
                self._session_cleanup_needed = True
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
        self._security_backend.secure_database(
            self.database_path,
            allow_missing=False,
        )
        self._initialized = True

    def close(self) -> None:
        """Unregister this process-owned journal session exactly once."""
        if self._closed:
            return
        failure: BaseException | None = None
        try:
            if self._session_cleanup_needed:
                with closing(self._connect()) as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    try:
                        connection.execute(
                            "DELETE FROM memory_sessions WHERE session_nonce = ? "
                            "AND owner_pid = ? AND owner_create_time = ?",
                            (
                                self._memory_session_nonce,
                                self._owner_pid,
                                self._owner_create_time,
                            ),
                        )
                        connection.commit()
                        self._session_cleanup_needed = False
                    except BaseException:
                        connection.rollback()
                        raise
        except BaseException as error:
            failure = error
        finally:
            self._memory_session_finalizer()
            self._closed = True
        if failure is not None:
            raise StoreError("state store session could not be unregistered") from None

    def __enter__(self) -> SQLiteStateStore:
        return self

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc_value: BaseException | None,
        _traceback: object | None,
    ) -> None:
        self.close()

    @staticmethod
    def _ensure_version_table(connection: sqlite3.Connection) -> None:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS schema_versions ("
            "version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
        )

    @staticmethod
    def _current_version(connection: sqlite3.Connection) -> int:
        user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        row = connection.execute("SELECT MAX(version) FROM schema_versions").fetchone()
        recorded = int(row[0]) if row is not None and row[0] is not None else 0
        if user_version and recorded and user_version != recorded:
            raise StoreError("database schema version markers disagree")
        return max(user_version, recorded)

    @staticmethod
    def _apply_migration(connection: sqlite3.Connection, version: int) -> None:
        if version == 1:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS settings ("
                "key TEXT PRIMARY KEY, value_json TEXT NOT NULL, updated_at TEXT NOT NULL)"
            )
            return
        if version == 3:
            for statement in (
                "ALTER TABLE action_plans ADD COLUMN claim_owner TEXT",
                "ALTER TABLE action_plans ADD COLUMN claimed_at TEXT",
                "ALTER TABLE action_plans ADD COLUMN phase TEXT",
            ):
                connection.execute(statement)
            return
        if version == 4:
            for statement in (
                "ALTER TABLE action_plans ADD COLUMN claim_owner_pid INTEGER",
                "ALTER TABLE action_plans ADD COLUMN claim_owner_create_time REAL",
            ):
                connection.execute(statement)
            return
        if version == 5:
            for statement in (
                """CREATE TABLE IF NOT EXISTS quarantine_plans (
                    plan_id TEXT PRIMARY KEY,
                    digest TEXT NOT NULL,
                    plan_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    started_at TEXT,
                    finished_at TEXT,
                    claim_owner TEXT,
                    claim_owner_pid INTEGER,
                    claim_owner_create_time REAL
                )""",
                """CREATE INDEX IF NOT EXISTS quarantine_plans_status_idx
                    ON quarantine_plans(status, expires_at)""",
                "ALTER TABLE quarantine_entries ADD COLUMN plan_id TEXT",
                "ALTER TABLE quarantine_entries ADD COLUMN status TEXT",
                "ALTER TABLE quarantine_entries ADD COLUMN updated_at TEXT",
                """CREATE UNIQUE INDEX IF NOT EXISTS quarantine_entries_plan_idx
                    ON quarantine_entries(plan_id)""",
                """CREATE TABLE IF NOT EXISTS quarantine_receipts (
                    receipt_id TEXT PRIMARY KEY,
                    plan_id TEXT NOT NULL REFERENCES quarantine_plans(plan_id),
                    entry_id TEXT,
                    operation TEXT NOT NULL,
                    result TEXT NOT NULL,
                    receipt_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )""",
                """CREATE INDEX IF NOT EXISTS quarantine_receipts_plan_idx
                    ON quarantine_receipts(plan_id, created_at)""",
            ):
                connection.execute(statement)
            return
        if version == 6:
            for statement in (
                "ALTER TABLE quarantine_entries ADD COLUMN restore_claim_owner TEXT",
                "ALTER TABLE quarantine_entries ADD COLUMN restore_claim_owner_pid INTEGER",
                "ALTER TABLE quarantine_entries ADD COLUMN restore_claim_owner_create_time REAL",
            ):
                connection.execute(statement)
            return
        if version == 7:
            SQLiteStateStore._add_column_if_missing(
                connection,
                "quarantine_plans",
                "legacy_recovery_reason TEXT",
            )
            SQLiteStateStore._classify_legacy_quarantine_plans(connection)
            return
        if version == 8:
            for statement in (
                """CREATE TABLE IF NOT EXISTS vault_sources (
                    source_id TEXT PRIMARY KEY,
                    source_path TEXT NOT NULL,
                    format TEXT NOT NULL,
                    capabilities_json TEXT NOT NULL,
                    revision TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )""",
                """CREATE TABLE IF NOT EXISTS memory_mutation_plans (
                    plan_id TEXT PRIMARY KEY,
                    source_id TEXT NOT NULL REFERENCES vault_sources(source_id),
                    digest TEXT NOT NULL,
                    source_revision TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    field_names_json TEXT NOT NULL,
                    expected_old_hash TEXT NOT NULL,
                    new_store_hash TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                )""",
                """CREATE INDEX IF NOT EXISTS memory_mutation_plans_status_idx
                    ON memory_mutation_plans(status, expires_at)""",
                """CREATE TABLE IF NOT EXISTS memory_snapshots (
                    snapshot_id TEXT PRIMARY KEY,
                    source_id TEXT NOT NULL REFERENCES vault_sources(source_id),
                    source_path_binding TEXT NOT NULL,
                    source_revision TEXT NOT NULL,
                    digest TEXT NOT NULL,
                    size INTEGER NOT NULL CHECK(size >= 0),
                    backup_path TEXT NOT NULL,
                    status TEXT NOT NULL,
                    retention_until TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )""",
                """CREATE INDEX IF NOT EXISTS memory_snapshots_retention_idx
                    ON memory_snapshots(status, retention_until)""",
                """CREATE TABLE IF NOT EXISTS memory_receipts (
                    receipt_id TEXT PRIMARY KEY,
                    plan_id TEXT REFERENCES memory_mutation_plans(plan_id),
                    snapshot_id TEXT NOT NULL REFERENCES memory_snapshots(snapshot_id),
                    source_id TEXT NOT NULL REFERENCES vault_sources(source_id),
                    operation TEXT NOT NULL,
                    field_names_json TEXT NOT NULL,
                    before_revision TEXT NOT NULL,
                    after_revision TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )""",
                """CREATE INDEX IF NOT EXISTS memory_receipts_source_idx
                    ON memory_receipts(source_id, created_at)""",
            ):
                connection.execute(statement)
            return
        if version == 9:
            for definition in (
                "source_identity_json TEXT",
                "record_hash TEXT",
                "operation_field TEXT",
                "operation_metadata_key TEXT",
                "proposed_value_hash TEXT",
                "proposed_value_type TEXT",
                "diff_json TEXT",
                "old_store_hash TEXT",
                "phase TEXT NOT NULL DEFAULT 'planned'",
                "snapshot_id TEXT",
                "claim_owner TEXT",
                "claim_owner_pid INTEGER",
                "claim_owner_create_time REAL",
                "claimed_at TEXT",
            ):
                SQLiteStateStore._add_column_if_missing(
                    connection, "memory_mutation_plans", definition
                )
            SQLiteStateStore._add_column_if_missing(
                connection, "memory_snapshots", "backup_identity_json TEXT"
            )
            SQLiteStateStore._add_column_if_missing(
                connection, "memory_snapshots", "source_identity_json TEXT"
            )
            return
        if version == 10:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS memory_restore_plans (
                    restore_plan_id TEXT PRIMARY KEY,
                    restore_key TEXT NOT NULL UNIQUE,
                    source_id TEXT NOT NULL REFERENCES vault_sources(source_id),
                    snapshot_id TEXT NOT NULL REFERENCES memory_snapshots(snapshot_id),
                    snapshot_digest TEXT NOT NULL,
                    expected_revision TEXT NOT NULL,
                    source_identity_json TEXT NOT NULL,
                    before_hash TEXT NOT NULL,
                    target_hash TEXT NOT NULL,
                    digest TEXT NOT NULL,
                    status TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    rollback_snapshot_id TEXT REFERENCES memory_snapshots(snapshot_id),
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    claim_owner TEXT,
                    claim_owner_pid INTEGER,
                    claim_owner_create_time REAL,
                    claimed_at TEXT
                )"""
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS memory_restore_status_idx "
                "ON memory_restore_plans(status, expires_at)"
            )
            SQLiteStateStore._add_column_if_missing(
                connection, "memory_receipts", "restore_plan_id TEXT"
            )
            connection.execute(
                "UPDATE memory_mutation_plans SET status = 'failed', "
                "phase = 'legacy_incompatible', claim_owner = NULL, "
                "claim_owner_pid = NULL, claim_owner_create_time = NULL "
                "WHERE (source_identity_json IS NULL OR record_hash IS NULL "
                "OR proposed_value_hash IS NULL OR proposed_value_type IS NULL "
                "OR diff_json IS NULL OR old_store_hash IS NULL) "
                "AND status IN ('planned', 'running', 'interrupted')"
            )
            connection.execute(
                "UPDATE memory_snapshots SET status = 'legacy_unbound' "
                "WHERE source_identity_json IS NULL OR backup_identity_json IS NULL"
            )
            return
        if version == 11:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS memory_sessions (
                    session_nonce TEXT PRIMARY KEY,
                    session_fingerprint TEXT NOT NULL,
                    owner_pid INTEGER NOT NULL,
                    owner_create_time REAL NOT NULL,
                    registered_at TEXT NOT NULL,
                    heartbeat_at TEXT NOT NULL
                )"""
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS memory_sessions_heartbeat_idx "
                "ON memory_sessions(heartbeat_at)"
            )
            return
        if version == 12:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS settings_metadata (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    revision INTEGER NOT NULL CHECK(revision >= 0)
                )"""
            )
            connection.execute(
                "INSERT OR IGNORE INTO settings_metadata(singleton, revision) VALUES (1, 0)"
            )
            return
        if version == 13:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS workflow_plans (
                    kind TEXT NOT NULL, plan_id TEXT NOT NULL, digest TEXT NOT NULL,
                    payload_json TEXT NOT NULL, payload_hash TEXT NOT NULL,
                    authority_hash TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('planned', 'running', 'finished')),
                    created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
                    claim_owner TEXT, claim_owner_pid INTEGER,
                    claim_owner_create_time REAL, claimed_at TEXT,
                    receipt_json TEXT, receipt_hash TEXT, finished_at TEXT,
                    PRIMARY KEY(kind, plan_id)
                )"""
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS workflow_plans_status_idx "
                "ON workflow_plans(kind, status, expires_at)"
            )
            return
        if version != 2:
            raise StoreError(f"unsupported database migration {version}")
        statements = (
            """CREATE TABLE IF NOT EXISTS action_plans (
                plan_id TEXT PRIMARY KEY,
                digest TEXT NOT NULL,
                plan_json TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT
            )""",
            """CREATE INDEX IF NOT EXISTS action_plans_status_idx
                ON action_plans(status, expires_at)""",
            """CREATE TABLE IF NOT EXISTS receipts (
                receipt_id TEXT PRIMARY KEY,
                plan_id TEXT NOT NULL REFERENCES action_plans(plan_id),
                correlation_id TEXT NOT NULL,
                receipt_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )""",
            """CREATE INDEX IF NOT EXISTS receipts_plan_idx
                ON receipts(plan_id, created_at)""",
            """CREATE TABLE IF NOT EXISTS audit_events (
                event_id TEXT PRIMARY KEY,
                correlation_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                details_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS quarantine_entries (
                entry_id TEXT PRIMARY KEY,
                state_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS vault_entries (
                entry_id TEXT PRIMARY KEY,
                state_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS snapshots (
                snapshot_id TEXT PRIMARY KEY,
                state_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )""",
        )
        for statement in statements:
            connection.execute(statement)

    @staticmethod
    def _add_column_if_missing(
        connection: sqlite3.Connection,
        table: str,
        definition: str,
    ) -> None:
        column = definition.partition(" ")[0]
        existing = {
            str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
        }
        if column not in existing:
            connection.execute(f"ALTER TABLE {table} ADD COLUMN {definition}")

    @staticmethod
    def _classify_legacy_quarantine_plans(connection: sqlite3.Connection) -> None:
        """Fail closed without rewriting legacy authority or evidence JSON."""
        rows = connection.execute(
            "SELECT plan_id, plan_json, status FROM quarantine_plans "
            "WHERE legacy_recovery_reason IS NULL"
        ).fetchall()
        for row in rows:
            plan_id = str(row["plan_id"])
            raw_json = str(row["plan_json"])
            try:
                payload = json.loads(raw_json)
            except (TypeError, ValueError):
                payload = None
            if not isinstance(payload, dict):
                connection.execute(
                    "UPDATE quarantine_plans SET status = ?, phase = ?, "
                    "legacy_recovery_reason = ?, claim_owner = NULL, "
                    "claim_owner_pid = NULL, claim_owner_create_time = NULL "
                    "WHERE plan_id = ? AND legacy_recovery_reason IS NULL",
                    (
                        "interrupted",
                        "legacy_incompatible",
                        "corrupt_plan_json",
                        plan_id,
                    ),
                )
                continue
            if {
                "manifest_created_at",
                "manifest_expires_at",
            }.issubset(payload):
                continue
            entry_exists = connection.execute(
                "SELECT 1 FROM quarantine_entries WHERE plan_id = ? LIMIT 1",
                (plan_id,),
            ).fetchone()
            status = str(row["status"])
            if status == "succeeded" and entry_exists is not None:
                next_status = status
                phase = "legacy_restore_only"
                reason = "missing_manifest_authority"
            else:
                next_status = "interrupted"
                phase = "legacy_incompatible"
                reason = (
                    "missing_quarantine_entry"
                    if status == "succeeded"
                    else "missing_manifest_authority"
                )
            connection.execute(
                "UPDATE quarantine_plans SET status = ?, phase = ?, "
                "legacy_recovery_reason = ?, claim_owner = NULL, "
                "claim_owner_pid = NULL, claim_owner_create_time = NULL "
                "WHERE plan_id = ? AND legacy_recovery_reason IS NULL",
                (next_status, phase, reason, plan_id),
            )

    def _reconcile_memory_running(self, connection: sqlite3.Connection) -> None:
        rows = connection.execute(
            "SELECT plan_id, claim_owner, claim_owner_pid, "
            "claim_owner_create_time FROM memory_mutation_plans "
            "WHERE status = 'running'"
        ).fetchall()
        for row in rows:
            if self._memory_claim_owner_alive(
                connection,
                str(row["claim_owner"] or ""),
                row["claim_owner_pid"],
                row["claim_owner_create_time"],
            ):
                continue
            connection.execute(
                "UPDATE memory_mutation_plans SET status = 'interrupted', "
                "phase = 'reconcile_required', claim_owner = NULL, "
                "claim_owner_pid = NULL, claim_owner_create_time = NULL "
                "WHERE plan_id = ? AND status = 'running'",
                (str(row["plan_id"]),),
            )

    def _reconcile_memory_restore_running(self, connection: sqlite3.Connection) -> None:
        rows = connection.execute(
            "SELECT restore_plan_id, claim_owner, claim_owner_pid, "
            "claim_owner_create_time FROM memory_restore_plans WHERE status = 'running'"
        ).fetchall()
        for row in rows:
            if self._memory_claim_owner_alive(
                connection,
                str(row["claim_owner"] or ""),
                row["claim_owner_pid"],
                row["claim_owner_create_time"],
            ):
                continue
            connection.execute(
                "UPDATE memory_restore_plans SET status = 'interrupted', "
                "phase = 'reconcile_required', claim_owner = NULL, "
                "claim_owner_pid = NULL, claim_owner_create_time = NULL "
                "WHERE restore_plan_id = ? AND status = 'running'",
                (str(row["restore_plan_id"]),),
            )

    def connection_pragmas(self) -> dict[str, int | str]:
        with closing(self._connect()) as connection:
            return {
                "foreign_keys": int(connection.execute("PRAGMA foreign_keys").fetchone()[0]),
                "busy_timeout": int(connection.execute("PRAGMA busy_timeout").fetchone()[0]),
                "journal_mode": str(
                    connection.execute("PRAGMA journal_mode").fetchone()[0]
                ).lower(),
            }

    def _serialize_json(self, value: object) -> str:
        try:
            encoded = json.dumps(
                value,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        except (TypeError, ValueError) as error:
            raise ValueError("JSON payload is not finite and serializable") from error
        if len(encoded.encode("utf-8")) > self._max_json_bytes:
            raise ValueError("JSON payload exceeds configured byte limit")
        return encoded

    def _encode_json(self, value: object) -> str:
        if isinstance(value, Mapping):
            return self._serialize_json(redact_mapping(value))
        return self._serialize_json(redact_text(value, max_length=2048))

    def _encode_canonical_model(self, value: DomainModel) -> str:
        return self._serialize_json(value.model_dump(mode="json"))

    @staticmethod
    def _validate_workflow_key(kind: str, plan_id: str, digest: str | None = None) -> None:
        _IDENTIFIER_ADAPTER.validate_python(kind)
        _IDENTIFIER_ADAPTER.validate_python(plan_id)
        if len(kind) > 64:
            raise ValueError("workflow kind exceeds its bounds")
        if digest is not None and (
            len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ValueError("workflow digest must be lowercase SHA-256")

    @staticmethod
    def _workflow_authority_hash(values: Mapping[str, object]) -> str:
        immutable = {
            name: values[name]
            for name in (
                "kind",
                "plan_id",
                "digest",
                "payload_hash",
                "created_at",
                "expires_at",
            )
        }
        return hashlib.sha256(
            json.dumps(
                immutable,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()

    def _workflow_payload(self, row: sqlite3.Row) -> dict[str, object]:
        encoded = str(row["payload_json"])
        if (
            len(encoded.encode()) > self._max_json_bytes
            or not secrets.compare_digest(
                hashlib.sha256(encoded.encode()).hexdigest(),
                str(row["payload_hash"]),
            )
            or not secrets.compare_digest(
                self._workflow_authority_hash(dict(row)),
                str(row["authority_hash"]),
            )
        ):
            raise StoreError("workflow authority integrity failed")
        payload: object = json.loads(encoded)
        if not isinstance(payload, dict) or any(not isinstance(key, str) for key in payload):
            raise StoreError("workflow payload must be a JSON object")
        if ("plan_id" in payload and payload["plan_id"] != row["plan_id"]) or (
            "digest" in payload and payload["digest"] != row["digest"]
        ):
            raise StoreError("workflow payload does not match authoritative columns")
        if "expires_at" in payload and (
            not isinstance(payload["expires_at"], str)
            or _parse_utc(payload["expires_at"]) != _parse_utc(str(row["expires_at"]))
        ):
            raise StoreError("workflow payload expiry does not match authoritative columns")
        return payload

    def save_workflow_plan(
        self,
        kind: str,
        plan_id: str,
        digest: str,
        payload: dict[str, object],
        *,
        expires_at: datetime,
    ) -> None:
        """Retain bounded private executable authority without presentation redaction."""
        self._validate_workflow_key(kind, plan_id, digest)
        encoded = self._serialize_json(payload)
        created_at = _require_utc(self._clock())
        expires_at = _require_utc(expires_at)
        if not created_at < expires_at <= created_at + timedelta(seconds=30):
            raise ValueError("workflow plan expiry must be within thirty seconds")
        values: dict[str, object] = {
            "kind": kind,
            "plan_id": plan_id,
            "digest": digest,
            "payload_hash": hashlib.sha256(encoded.encode()).hexdigest(),
            "created_at": _utc_text(created_at),
            "expires_at": _utc_text(expires_at),
        }
        with closing(self._connect()) as connection:
            try:
                connection.execute(
                    "INSERT INTO workflow_plans(kind, plan_id, digest, payload_json, "
                    "payload_hash, authority_hash, status, created_at, expires_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, 'planned', ?, ?)",
                    (
                        kind,
                        plan_id,
                        digest,
                        encoded,
                        values["payload_hash"],
                        self._workflow_authority_hash(values),
                        values["created_at"],
                        values["expires_at"],
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise StoreError("workflow plan already exists") from error

    def get_workflow_plan(self, kind: str, plan_id: str) -> dict[str, object] | None:
        """Read immutable evidence even after expiry for domain recovery and restore."""
        self._validate_workflow_key(kind, plan_id)
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT * FROM workflow_plans WHERE kind = ? AND plan_id = ?",
                (kind, plan_id),
            ).fetchone()
        return self._workflow_payload(row) if row is not None else None

    def claim_workflow_plan(
        self,
        kind: str,
        plan_id: str,
        *,
        expected_digest: str,
        reconcile: bool = False,
    ) -> dict[str, object]:
        """Claim once; dead-owner outcomes require explicit domain reconciliation.

        ``reconcile`` grants journal ownership, never permission to repeat an
        external effect. The domain must prove its source/destination before
        retrying and enforce expiry at the actual mutation boundary.
        """
        self._validate_workflow_key(kind, plan_id, expected_digest)
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT * FROM workflow_plans WHERE kind = ? AND plan_id = ?",
                    (kind, plan_id),
                ).fetchone()
                if row is None or not secrets.compare_digest(str(row["digest"]), expected_digest):
                    raise PlanClaimError("workflow plan digest did not match")
                payload = self._workflow_payload(row)
                now = _require_utc(self._clock())
                status = str(row["status"])
                if status == "finished":
                    raise PlanClaimError("workflow already has a final receipt")
                if status == "running":
                    if self._claim_owner_alive(
                        str(row["claim_owner"] or ""),
                        row["claim_owner_pid"],
                        row["claim_owner_create_time"],
                    ):
                        raise PlanClaimError("workflow execution owner is still alive")
                    if not reconcile:
                        raise PlanClaimError("workflow outcome requires domain reconciliation")
                    payload = {**payload, "_workflow_reconcile_required": True}
                elif status != "planned":
                    raise PlanClaimError("workflow plan cannot be claimed")
                elif now >= _parse_utc(str(row["expires_at"])):
                    raise ExpiredPlanError("workflow plan has expired")
                connection.execute(
                    "UPDATE workflow_plans SET status = 'running', claim_owner = ?, "
                    "claim_owner_pid = ?, claim_owner_create_time = ?, claimed_at = ? "
                    "WHERE kind = ? AND plan_id = ?",
                    (
                        self._session_fingerprint,
                        self._owner_pid,
                        self._owner_create_time,
                        _utc_text(now),
                        kind,
                        plan_id,
                    ),
                )
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
        return payload

    def finish_workflow_plan(
        self,
        kind: str,
        plan_id: str,
        receipt: dict[str, object],
    ) -> None:
        self._validate_workflow_key(kind, plan_id)
        if receipt.get("plan_id") != plan_id:
            raise StoreError("workflow receipt does not match the reviewed plan")
        encoded = self._serialize_json(receipt)
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT * FROM workflow_plans WHERE kind = ? AND plan_id = ?",
                    (kind, plan_id),
                ).fetchone()
                if row is None:
                    raise StoreError("workflow plan was not found")
                self._workflow_payload(row)
                if (
                    row["status"] != "running"
                    or row["claim_owner"] != self._session_fingerprint
                    or row["claim_owner_pid"] != self._owner_pid
                    or row["claim_owner_create_time"] != self._owner_create_time
                ):
                    raise StoreError("workflow finish does not belong to this claimed session")
                connection.execute(
                    "UPDATE workflow_plans SET status = 'finished', receipt_json = ?, "
                    "receipt_hash = ?, finished_at = ? WHERE kind = ? AND plan_id = ?",
                    (
                        encoded,
                        hashlib.sha256(encoded.encode()).hexdigest(),
                        _utc_text(self._clock()),
                        kind,
                        plan_id,
                    ),
                )
                connection.commit()
            except BaseException:
                connection.rollback()
                raise

    def get_workflow_receipt(self, kind: str, plan_id: str) -> dict[str, object] | None:
        self._validate_workflow_key(kind, plan_id)
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT * FROM workflow_plans WHERE kind = ? AND plan_id = ?",
                (kind, plan_id),
            ).fetchone()
        if row is None:
            return None
        return self._workflow_public_receipt(row)

    def _workflow_public_receipt(self, row: sqlite3.Row) -> dict[str, object] | None:
        self._workflow_payload(row)
        if row["status"] != "finished":
            return None
        encoded = str(row["receipt_json"])
        if len(encoded.encode()) > self._max_json_bytes or not secrets.compare_digest(
            hashlib.sha256(encoded.encode()).hexdigest(),
            str(row["receipt_hash"]),
        ):
            raise StoreError("workflow receipt integrity failed")
        receipt: object = json.loads(encoded)
        if not isinstance(receipt, dict) or receipt.get("plan_id") != row["plan_id"]:
            raise StoreError("workflow receipt binding failed")
        if "kind" not in receipt:
            public_kind = _WORKFLOW_RECEIPT_KINDS.get(str(row["kind"]))
            if public_kind is not None:
                receipt = {**receipt, "kind": public_kind}
        return receipt

    def get_workflow_receipt_by_id(self, receipt_id: str) -> dict[str, object] | None:
        validated_id = _IDENTIFIER_ADAPTER.validate_python(receipt_id)
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT * FROM workflow_plans WHERE status='finished' "
                "AND json_extract(receipt_json, '$.receipt_id')=? LIMIT 2",
                (validated_id,),
            ).fetchall()
        if len(rows) > 1:
            raise StoreError("workflow receipt identifier is ambiguous")
        return self._workflow_public_receipt(rows[0]) if rows else None

    def list_workflow_receipts(
        self,
        *,
        limit: int = 100,
        cursor: str | None = None,
    ) -> tuple[dict[str, object], ...]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
            raise ValueError("workflow receipt limit must be between one and five hundred")
        cursor_clause = ""
        values: tuple[object, ...] = ()
        with closing(self._connect()) as connection:
            if cursor is not None:
                _IDENTIFIER_ADAPTER.validate_python(cursor)
                prior = connection.execute(
                    "SELECT * FROM workflow_plans WHERE status='finished' "
                    "AND json_extract(receipt_json, '$.receipt_id')=? LIMIT 2",
                    (cursor,),
                ).fetchall()
                if len(prior) != 1:
                    raise ValueError("workflow receipt cursor is invalid or unavailable")
                self._workflow_public_receipt(prior[0])
                cursor_clause = (
                    "AND (finished_at < ? OR (finished_at = ? "
                    "AND json_extract(receipt_json, '$.receipt_id') < ?)) "
                )
                values = (prior[0]["finished_at"], prior[0]["finished_at"], cursor)
            rows = connection.execute(
                "SELECT * FROM workflow_plans WHERE status='finished' "
                + cursor_clause
                + (
                    "ORDER BY finished_at DESC, "
                    "json_extract(receipt_json, '$.receipt_id') DESC LIMIT ?"
                ),
                (*values, limit),
            ).fetchall()
        receipts: list[dict[str, object]] = []
        for row in rows:
            receipt = self._workflow_public_receipt(row)
            if receipt is not None:
                receipts.append(receipt)
        return tuple(receipts)

    def list_public_receipts(
        self,
        *,
        limit: int = 100,
        cursor: str | None = None,
    ) -> tuple[ActionReceipt | dict[str, object], ...]:
        """Read one globally ordered, bounded page without exposing private plans."""
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
            raise ValueError("public receipt limit must be between one and five hundred")
        if cursor is not None:
            _IDENTIFIER_ADAPTER.validate_python(cursor)

        def workflow_time(encoded: str, finished_at: str) -> str:
            if len(encoded.encode()) > self._max_json_bytes:
                raise StoreError("workflow receipt exceeds its integrity bound")
            value: object = json.loads(encoded)
            if not isinstance(value, dict):
                raise StoreError("workflow receipt is not an object")
            created_at = value.get("created_at", finished_at)
            if not isinstance(created_at, str):
                raise StoreError("workflow receipt timestamp is invalid")
            return _utc_text(_parse_utc(created_at))

        inventory = (
            "WITH public_receipts AS ("
            "SELECT 'action' AS source, '' AS kind, plan_id, receipt_id, "
            "public_utc_time(created_at) AS sort_at FROM receipts UNION ALL "
            "SELECT 'workflow', kind, plan_id, "
            "json_extract(receipt_json, '$.receipt_id'), "
            "public_workflow_time(receipt_json, finished_at) FROM workflow_plans "
            "WHERE status='finished') "
        )
        with closing(self._connect()) as connection:
            connection.create_function("public_workflow_time", 2, workflow_time, deterministic=True)
            connection.create_function(
                "public_utc_time", 1, lambda value: _utc_text(_parse_utc(value)), deterministic=True
            )
            connection.execute("BEGIN")

            def read_verified(row: sqlite3.Row) -> ActionReceipt | dict[str, object]:
                if row["source"] == "action":
                    stored = connection.execute(
                        "SELECT receipt_json FROM receipts WHERE receipt_id = ?",
                        (row["receipt_id"],),
                    ).fetchone()
                    if stored is None:
                        raise StoreError("public action receipt is unavailable")
                    action = ActionReceipt.model_validate_json(str(stored["receipt_json"]))
                    if (
                        action.receipt_id != row["receipt_id"]
                        or action.plan_id != row["plan_id"]
                        or _utc_text(action.finished_at) != row["sort_at"]
                    ):
                        raise StoreError("public action receipt binding failed")
                    return action
                stored = connection.execute(
                    "SELECT * FROM workflow_plans WHERE kind=? AND plan_id=?",
                    (row["kind"], row["plan_id"]),
                ).fetchone()
                if stored is None:
                    raise StoreError("public workflow receipt is unavailable")
                receipt = self._workflow_public_receipt(stored)
                if (
                    receipt is None
                    or receipt.get("receipt_id") != row["receipt_id"]
                    or workflow_time(str(stored["receipt_json"]), str(stored["finished_at"]))
                    != row["sort_at"]
                ):
                    raise StoreError("public workflow receipt binding failed")
                _IDENTIFIER_ADAPTER.validate_python(receipt["receipt_id"])
                return receipt

            try:
                clause = ""
                values: tuple[object, ...] = ()
                if cursor is not None:
                    prior = connection.execute(
                        inventory + "SELECT * FROM public_receipts WHERE receipt_id=? LIMIT 2",
                        (cursor,),
                    ).fetchall()
                    if len(prior) != 1:
                        raise ValueError("public receipt cursor is invalid or unavailable")
                    read_verified(prior[0])
                    clause = "WHERE (sort_at < ? OR (sort_at = ? AND receipt_id < ?)) "
                    values = (prior[0]["sort_at"], prior[0]["sort_at"], cursor)
                rows = connection.execute(
                    inventory
                    + "SELECT * FROM public_receipts "
                    + clause
                    + "ORDER BY sort_at DESC, receipt_id DESC LIMIT ?",
                    (*values, limit),
                ).fetchall()
                return tuple(read_verified(row) for row in rows)
            except sqlite3.Error as error:
                raise StoreError("public receipt inventory integrity failed") from error

    def save_plan(self, plan: ActionPlan) -> None:
        if plan.status is not PlanStatus.PLANNED or not plan.verify_digest():
            raise ValueError("only valid PLANNED action plans can be saved")
        encoded = self._encode_canonical_model(plan)
        if ActionPlan.model_validate_json(encoded) != plan:
            raise ValueError("canonical action plan serialization did not round trip")
        with closing(self._connect()) as connection:
            try:
                connection.execute(
                    "INSERT INTO action_plans("
                    "plan_id, digest, plan_json, status, created_at, expires_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        plan.plan_id,
                        plan.digest,
                        encoded,
                        plan.status.value,
                        _utc_text(plan.created_at),
                        _utc_text(plan.expires_at),
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise StoreError("action plan already exists") from error

    def get_plan(self, plan_id: str) -> ActionPlan | None:
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._reconcile_running(
                    connection,
                    now=_require_utc(self._clock()),
                    check_owner=False,
                )
                row = connection.execute(
                    "SELECT plan_json, status FROM action_plans WHERE plan_id = ?",
                    (plan_id,),
                ).fetchone()
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
        if row is None:
            return None
        stored = ActionPlan.model_validate_json(str(row["plan_json"]))
        return stored.model_copy(update={"status": PlanStatus(str(row["status"]))})

    def claim_plan(
        self,
        plan_id: str,
        *,
        expected_digest: str,
    ) -> ActionPlan:
        failure: PlanClaimError | None = None
        claimed_plan: ActionPlan | None = None
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                claimed_at = _require_utc(self._clock())
                self._reconcile_running(
                    connection,
                    now=claimed_at,
                    check_owner=False,
                )
                row = connection.execute(
                    "SELECT digest, plan_json, status, created_at, expires_at "
                    "FROM action_plans WHERE plan_id = ?",
                    (plan_id,),
                ).fetchone()
                if row is None:
                    failure = PlanClaimError("action plan was not found")
                elif str(row["digest"]) != expected_digest:
                    failure = PlanClaimError("action plan digest does not match")
                elif str(row["status"]) != PlanStatus.PLANNED.value:
                    failure = PlanClaimError("action plan status is not PLANNED")
                else:
                    try:
                        candidate = ActionPlan.model_validate_json(str(row["plan_json"]))
                    except ValueError:
                        failure = PlanClaimError("stored plan failed canonical validation")
                        candidate = None
                    if candidate is not None and (
                        candidate.plan_id != plan_id
                        or candidate.digest != expected_digest
                        or candidate.status is not PlanStatus.PLANNED
                        or _utc_text(candidate.created_at) != str(row["created_at"])
                        or _utc_text(candidate.expires_at) != str(row["expires_at"])
                    ):
                        failure = PlanClaimError("stored plan does not match authoritative columns")
                        candidate = None
                    if candidate is None:
                        pass
                    elif claimed_at >= candidate.expires_at:
                        connection.execute(
                            "UPDATE action_plans SET status = ?, finished_at = ? "
                            "WHERE plan_id = ? AND status = ?",
                            (
                                PlanStatus.EXPIRED.value,
                                _utc_text(claimed_at),
                                plan_id,
                                PlanStatus.PLANNED.value,
                            ),
                        )
                        failure = ExpiredPlanError("action plan has expired")
                    else:
                        changed = connection.execute(
                            "UPDATE action_plans SET status = ?, started_at = ?, "
                            "claim_owner = ?, claimed_at = ?, phase = ?, "
                            "claim_owner_pid = ?, claim_owner_create_time = ? "
                            "WHERE plan_id = ? AND status = ? AND digest = ?",
                            (
                                PlanStatus.RUNNING.value,
                                _utc_text(claimed_at),
                                self._session_fingerprint,
                                _utc_text(claimed_at),
                                "claimed",
                                self._owner_pid,
                                self._owner_create_time,
                                plan_id,
                                PlanStatus.PLANNED.value,
                                expected_digest,
                            ),
                        ).rowcount
                        if changed != 1:
                            failure = PlanClaimError("action plan could not be claimed")
                        else:
                            claimed_plan = candidate
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
        if failure is not None:
            raise failure
        assert claimed_plan is not None
        return claimed_plan.model_copy(update={"status": PlanStatus.RUNNING})

    @staticmethod
    def _status_for_receipt(receipt: ActionReceipt) -> PlanStatus:
        if receipt.result is ActionResult.INTERRUPTED or receipt.action_issued is None:
            return PlanStatus.INTERRUPTED
        if receipt.result in {
            ActionResult.ACCESS_DENIED,
            ActionResult.IDENTITY_MISMATCH,
            ActionResult.FAILED,
        }:
            return PlanStatus.PARTIAL if receipt.action_issued is True else PlanStatus.FAILED
        if receipt.result in {
            ActionResult.REQUESTED,
            ActionResult.PENDING,
        }:
            return PlanStatus.PARTIAL
        if receipt.result in {ActionResult.COMPLETED, ActionResult.DISAPPEARED}:
            return PlanStatus.PARTIAL if receipt.partial_failures else PlanStatus.SUCCEEDED
        return PlanStatus.FAILED

    @staticmethod
    def _validate_receipt_outcome(
        receipt: ActionReceipt,
        *,
        phase: str,
        claimed_plan: ActionPlan,
    ) -> None:
        expected_effects: dict[str, set[bool | None]] = {
            "claimed": {False},
            "validated": {False},
            "action_issuing": {False, True, None},
            "action_issued": {True},
            "verifying": {True},
        }
        if phase not in expected_effects:
            raise StoreError("action receipt references an unknown claim phase")
        if receipt.result is ActionResult.INTERRUPTED or receipt.action_issued is None:
            if receipt.result is ActionResult.INTERRUPTED and receipt.action_issued is None:
                return
            raise StoreError("action receipt effect and uncertainty fields conflict")
        successful_action = receipt.result in {
            ActionResult.COMPLETED,
            ActionResult.REQUESTED,
            ActionResult.PENDING,
        }
        if (
            receipt.action_issued not in expected_effects[phase]
            or (successful_action and phase != "verifying")
            or (
                receipt.result is ActionResult.REQUESTED
                and claimed_plan.mode.value != "request_stop"
            )
        ):
            raise StoreError("action receipt outcome conflicts with claim phase")

    def update_plan_phase(self, plan_id: str, phase: str) -> None:
        prior_phase = {
            "validated": "claimed",
            "action_issuing": "validated",
            "action_issued": "action_issuing",
            "verifying": "action_issued",
        }.get(phase)
        if prior_phase is None:
            raise ValueError("unsupported action execution phase")
        with closing(self._connect()) as connection:
            changed = connection.execute(
                "UPDATE action_plans SET phase = ? WHERE plan_id = ? "
                "AND status = ? AND claim_owner = ? AND phase = ?",
                (
                    phase,
                    plan_id,
                    PlanStatus.RUNNING.value,
                    self._session_fingerprint,
                    prior_phase,
                ),
            ).rowcount
        if changed != 1:
            raise StoreError("action plan phase could not be updated")

    def finish_plan(self, receipt: ActionReceipt) -> None:
        receipt = ActionReceipt.model_validate(receipt.model_dump(mode="python"))
        status = self._status_for_receipt(receipt)
        receipt_json = self._encode_canonical_model(receipt)
        audit_json = self._serialize_json({"receipt": receipt.model_dump(mode="json")})
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                current = connection.execute(
                    "SELECT status, plan_json, claim_owner, claimed_at, phase "
                    "FROM action_plans WHERE plan_id = ?",
                    (receipt.plan_id,),
                ).fetchone()
                if current is None or current[0] != PlanStatus.RUNNING.value:
                    raise StoreError("only a RUNNING action plan can be finished")
                claimed_plan = ActionPlan.model_validate_json(str(current["plan_json"]))
                claimed_at_text = current["claimed_at"]
                phase = str(current["phase"] or "")
                if (
                    receipt.correlation_id != claimed_plan.correlation_id
                    or receipt.action is not claimed_plan.mode
                    or receipt.target != claimed_plan.identity
                    or receipt.plan_id != claimed_plan.plan_id
                    or str(current["claim_owner"]) != receipt.session_id
                    or claimed_at_text is None
                    or receipt.started_at < _parse_utc(str(claimed_at_text))
                    or receipt.finished_at < _parse_utc(str(claimed_at_text))
                ):
                    raise StoreError("action receipt does not match the claimed plan")
                self._validate_receipt_outcome(
                    receipt,
                    phase=phase,
                    claimed_plan=claimed_plan,
                )
                connection.execute(
                    "INSERT INTO receipts("
                    "receipt_id, plan_id, correlation_id, receipt_json, created_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        receipt.receipt_id,
                        receipt.plan_id,
                        receipt.correlation_id,
                        receipt_json,
                        _utc_text(receipt.finished_at),
                    ),
                )
                connection.execute(
                    "INSERT INTO audit_events("
                    "event_id, correlation_id, event_type, details_json, created_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        receipt.receipt_id,
                        receipt.correlation_id,
                        "action_receipt",
                        audit_json,
                        _utc_text(receipt.finished_at),
                    ),
                )
                changed = connection.execute(
                    "UPDATE action_plans SET status = ?, finished_at = ? "
                    "WHERE plan_id = ? AND status = ?",
                    (
                        status.value,
                        _utc_text(receipt.finished_at),
                        receipt.plan_id,
                        PlanStatus.RUNNING.value,
                    ),
                ).rowcount
                if changed != 1:
                    raise StoreError("action plan terminal transition failed")
                connection.commit()
            except BaseException:
                connection.rollback()
                raise

    def _reconcile_running(
        self,
        connection: sqlite3.Connection,
        *,
        now: datetime,
        check_owner: bool,
    ) -> None:
        rows = connection.execute(
            "SELECT plan_id, plan_json, claim_owner, claimed_at, phase, expires_at, "
            "claim_owner_pid, claim_owner_create_time "
            "FROM action_plans WHERE status = ?",
            (PlanStatus.RUNNING.value,),
        ).fetchall()
        for row in rows:
            owner = str(row["claim_owner"] or "")
            expired = now >= _parse_utc(str(row["expires_at"]))
            owner_dead = check_owner and not self._claim_owner_alive(
                owner,
                row["claim_owner_pid"],
                row["claim_owner_create_time"],
            )
            if not expired and not owner_dead:
                continue
            plan = ActionPlan.model_validate_json(str(row["plan_json"])).model_copy(
                update={"status": PlanStatus.RUNNING}
            )
            claimed_at = (
                _parse_utc(str(row["claimed_at"]))
                if row["claimed_at"] is not None
                else plan.created_at
            )
            finished_at = max(now, claimed_at)
            receipt = ActionReceipt.create(
                plan=plan,
                actor="zombie-killer-engine",
                session_id=owner or self.session_id,
                result=ActionResult.INTERRUPTED,
                action_issued=None,
                before=str(row["phase"] or "running"),
                after="execution_outcome_uncertain",
                started_at=claimed_at,
                finished_at=finished_at,
                partial_failures=(
                    "A claimed action lost its owner or exceeded its recovery window; "
                    "the execution outcome is uncertain.",
                ),
            )
            self._validate_receipt_outcome(
                receipt,
                phase=str(row["phase"] or "claimed"),
                claimed_plan=plan,
            )
            if self._status_for_receipt(receipt) is not PlanStatus.INTERRUPTED:
                raise StoreError("reconciled receipt did not derive interrupted status")
            receipt_json = self._encode_canonical_model(receipt)
            audit_json = self._serialize_json({"receipt": receipt.model_dump(mode="json")})
            connection.execute(
                "INSERT INTO receipts(receipt_id, plan_id, correlation_id, "
                "receipt_json, created_at) VALUES (?, ?, ?, ?, ?)",
                (
                    receipt.receipt_id,
                    receipt.plan_id,
                    receipt.correlation_id,
                    receipt_json,
                    _utc_text(receipt.finished_at),
                ),
            )

            connection.execute(
                "INSERT INTO audit_events(event_id, correlation_id, event_type, "
                "details_json, created_at) VALUES (?, ?, ?, ?, ?)",
                (
                    receipt.receipt_id,
                    receipt.correlation_id,
                    "action_receipt",
                    audit_json,
                    _utc_text(receipt.finished_at),
                ),
            )
            connection.execute(
                "UPDATE action_plans SET status = ?, finished_at = ?, phase = ? "
                "WHERE plan_id = ? AND status = ?",
                (
                    PlanStatus.INTERRUPTED.value,
                    _utc_text(receipt.finished_at),
                    "interrupted",
                    receipt.plan_id,
                    PlanStatus.RUNNING.value,
                ),
            )

    def _claim_owner_alive(
        self,
        owner: str,
        owner_pid: int | str | None,
        owner_create_time: float | str | None,
    ) -> bool:
        if not owner:
            return False
        if owner_pid is None or owner_create_time is None:
            return False
        try:
            parsed_pid = int(owner_pid)
            parsed_create_time = float(owner_create_time)
        except (TypeError, ValueError):
            return False
        if self._is_session_alive is not None and not self._is_session_alive(owner):
            return False
        try:
            process = psutil.Process(parsed_pid)
            observed_create_time = float(process.create_time())
        except psutil.AccessDenied:
            return True
        except (psutil.NoSuchProcess, ValueError, TypeError):
            return False
        return abs(observed_create_time - parsed_create_time) <= 0.001

    def _register_memory_session(self, connection: sqlite3.Connection, now: datetime) -> None:
        timestamp = _utc_text(now)
        connection.execute(
            "INSERT INTO memory_sessions(session_nonce, session_fingerprint, owner_pid, "
            "owner_create_time, registered_at, heartbeat_at) VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(session_nonce) DO UPDATE SET heartbeat_at=excluded.heartbeat_at",
            (
                self._memory_session_nonce,
                self._session_fingerprint,
                self._owner_pid,
                self._owner_create_time,
                timestamp,
                timestamp,
            ),
        )

    def _heartbeat_memory_session(
        self, connection: sqlite3.Connection, now: datetime | None = None
    ) -> None:
        updated = connection.execute(
            "UPDATE memory_sessions SET heartbeat_at=? WHERE session_nonce=? "
            "AND owner_pid=? AND owner_create_time=?",
            (
                _utc_text(now or self._clock()),
                self._memory_session_nonce,
                self._owner_pid,
                self._owner_create_time,
            ),
        )
        if updated.rowcount != 1:
            raise StoreError("memory session registration is unavailable")

    def abandon_memory_session(self) -> None:
        """Make an unrecoverable local journal owner immediately reclaimable."""
        self._memory_session_finalizer()

    def _memory_claim_owner_alive(
        self,
        connection: sqlite3.Connection,
        owner: str,
        owner_pid: int | str | None,
        owner_create_time: float | str | None,
    ) -> bool:
        if not self._claim_owner_alive(owner, owner_pid, owner_create_time):
            return False
        row = connection.execute(
            "SELECT owner_pid, owner_create_time, heartbeat_at FROM memory_sessions "
            "WHERE session_nonce=?",
            (owner,),
        ).fetchone()
        if row is None:
            return False
        try:
            parsed_pid = int(owner_pid) if owner_pid is not None else -1
            parsed_create_time = float(owner_create_time) if owner_create_time is not None else -1.0
            registered_pid = int(row["owner_pid"])
            registered_create_time = float(row["owner_create_time"])
            heartbeat = _parse_utc(str(row["heartbeat_at"]))
        except (TypeError, ValueError):
            return False
        if registered_pid != parsed_pid or abs(registered_create_time - parsed_create_time) > 0.001:
            return False
        if parsed_pid == self._owner_pid:
            with _PROCESS_MEMORY_SESSION_LOCK:
                return owner in _PROCESS_MEMORY_SESSIONS
        return self._clock() - heartbeat <= _MEMORY_HEARTBEAT_LIFETIME

    def _memory_journal_write(self, operation: Callable[[sqlite3.Connection], None]) -> None:
        for attempt in range(3):
            try:
                with closing(self._connect()) as connection:
                    connection.execute("PRAGMA busy_timeout=25")
                    operation(connection)
                return
            except Exception as error:
                if not _is_memory_journal_unavailable(error):
                    raise
                if attempt == 2:
                    self.abandon_memory_session()
                    from zombie_killer_engine.memory.base import MemoryJournalError

                    raise MemoryJournalError(
                        "memory journal is unavailable; reconciliation is required"
                    ) from None
                time.sleep(0.01 * (attempt + 1))

    def list_receipts(self, plan_id: str) -> tuple[ActionReceipt, ...]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT receipt_json FROM receipts WHERE plan_id = ? "
                "ORDER BY created_at, receipt_id",
                (plan_id,),
            ).fetchall()
        return tuple(ActionReceipt.model_validate_json(row[0]) for row in rows)

    def get_action_receipt(self, receipt_id: str) -> ActionReceipt | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT receipt_json FROM receipts WHERE receipt_id = ?",
                (receipt_id,),
            ).fetchone()
        return None if row is None else ActionReceipt.model_validate_json(row[0])

    def list_action_receipts(
        self, *, limit: int = 100, cursor: str | None = None
    ) -> tuple[ActionReceipt, ...]:
        if not 1 <= limit <= 500:
            raise ValueError("receipt limit is outside the supported bound")
        with closing(self._connect()) as connection:
            cursor_clause = ""
            cursor_values: tuple[object, ...] = ()
            if cursor is not None:
                cursor_row = connection.execute(
                    "SELECT created_at, receipt_id FROM receipts WHERE receipt_id = ?",
                    (cursor,),
                ).fetchone()
                if cursor_row is None:
                    raise ValueError("activity cursor is invalid or no longer available")
                cursor_clause = "WHERE (created_at < ? OR (created_at = ? AND receipt_id < ?)) "
                cursor_values = (
                    str(cursor_row["created_at"]),
                    str(cursor_row["created_at"]),
                    str(cursor_row["receipt_id"]),
                )
            rows = connection.execute(
                "SELECT receipt_json FROM receipts "
                + cursor_clause
                + "ORDER BY created_at DESC, receipt_id DESC LIMIT ?",
                (*cursor_values, limit),
            ).fetchall()
        return tuple(ActionReceipt.model_validate_json(row[0]) for row in rows)

    def save_quarantine_plan(self, plan: QuarantinePlan) -> None:
        """Persist one valid cleanup plan in the restricted state database."""
        from zombie_killer_engine.quarantine import QuarantinePlan, QuarantineState

        validated = QuarantinePlan.model_validate(plan.model_dump(mode="python"))
        if validated.state is not QuarantineState.PLANNED or not validated.verify_digest():
            raise ValueError("only valid planned quarantine plans can be saved")
        encoded = self._encode_canonical_model(validated)
        with closing(self._connect()) as connection:
            try:
                connection.execute(
                    "INSERT INTO quarantine_plans("
                    "plan_id, digest, plan_json, status, phase, created_at, expires_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        validated.plan_id,
                        validated.digest,
                        encoded,
                        validated.state.value,
                        "planned",
                        _utc_text(validated.created_at),
                        _utc_text(validated.expires_at),
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise StoreError("quarantine plan already exists") from error

    def get_quarantine_plan(self, plan_id: str) -> QuarantinePlan | None:
        from zombie_killer_engine.quarantine import QuarantinePlan, QuarantineState

        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT plan_json, status FROM quarantine_plans WHERE plan_id = ?",
                (plan_id,),
            ).fetchone()
        if row is None:
            return None
        stored = QuarantinePlan.model_validate_json(str(row["plan_json"]))
        return stored.model_copy(update={"state": QuarantineState(str(row["status"]))})

    def get_legacy_quarantine_reason(self, plan_id: str) -> LegacyRecoveryReason | None:
        from zombie_killer_engine.quarantine import LegacyRecoveryReason

        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT legacy_recovery_reason FROM quarantine_plans WHERE plan_id = ?",
                (plan_id,),
            ).fetchone()
        if row is None or row["legacy_recovery_reason"] is None:
            return None
        return LegacyRecoveryReason(str(row["legacy_recovery_reason"]))

    def get_legacy_restore_plan(
        self,
        entry_id: str,
        *,
        expected_entry_digest: str,
    ) -> tuple[LegacyRestorePlan, QuarantineEntry]:
        from zombie_killer_engine.quarantine import (
            LegacyRecoveryReason,
            LegacyRestorePlan,
            QuarantineEntry,
            QuarantineState,
        )

        with closing(self._connect()) as connection:
            entry_row = connection.execute(
                "SELECT state_json, status, plan_id FROM quarantine_entries WHERE entry_id = ?",
                (entry_id,),
            ).fetchone()
            if entry_row is None:
                raise StoreError("legacy quarantine entry was not found")
            plan_row = connection.execute(
                "SELECT plan_json, digest, status, phase, legacy_recovery_reason "
                "FROM quarantine_plans WHERE plan_id = ?",
                (str(entry_row["plan_id"]),),
            ).fetchone()
        if plan_row is None:
            raise StoreError("legacy quarantine plan was not found")
        entry = QuarantineEntry.model_validate_json(str(entry_row["state_json"]))
        entry = entry.model_copy(update={"state": QuarantineState(str(entry_row["status"]))})
        if not entry.verify_digest() or not secrets.compare_digest(
            entry.digest, expected_entry_digest
        ):
            raise StoreError("legacy quarantine entry digest does not match")
        if (
            str(plan_row["status"]) != QuarantineState.SUCCEEDED.value
            or str(plan_row["phase"]) != "legacy_restore_only"
            or str(plan_row["legacy_recovery_reason"])
            != LegacyRecoveryReason.MISSING_MANIFEST_AUTHORITY.value
            or entry.state
            not in {
                QuarantineState.SUCCEEDED,
                QuarantineState.INTERRUPTED,
                QuarantineState.RESTORED,
            }
        ):
            raise StoreError("legacy quarantine entry is not restore-only")
        plan = LegacyRestorePlan.model_validate_json(str(plan_row["plan_json"]))
        if not secrets.compare_digest(plan.digest, str(plan_row["digest"])):
            raise StoreError("legacy quarantine plan evidence digest changed")
        if (
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
        ) != (
            plan.plan_id,
            plan.correlation_id,
            plan.agent_id,
            plan.creating_identity,
            plan.resource_type,
            plan.approved_root,
            plan.target,
            plan.relative_path,
            plan.root_hash,
            plan.target_hash,
            plan.fingerprint,
        ):
            raise StoreError("legacy entry does not match preserved plan evidence")
        return plan, entry

    def get_quarantine_recovery(
        self,
        plan_id: str,
        *,
        expected_digest: str,
    ) -> tuple[QuarantinePlan, str] | None:
        """Return a dead-owner running claim for path-aware executor recovery."""
        from zombie_killer_engine.quarantine import QuarantinePlan, QuarantineState

        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT digest, plan_json, status, phase, claim_owner, "
                    "claim_owner_pid, claim_owner_create_time FROM quarantine_plans "
                    "WHERE plan_id = ?",
                    (plan_id,),
                ).fetchone()
                if row is None or str(row["status"]) != QuarantineState.RUNNING.value:
                    connection.commit()
                    return None
                if not secrets.compare_digest(str(row["digest"]), expected_digest):
                    raise PlanClaimError("quarantine plan digest does not match")
                owner = str(row["claim_owner"] or "")
                if self._claim_owner_alive(
                    owner,
                    row["claim_owner_pid"],
                    row["claim_owner_create_time"],
                ):
                    raise PlanClaimError("quarantine running owner is alive")
                changed = connection.execute(
                    "UPDATE quarantine_plans SET claim_owner = ?, claim_owner_pid = ?, "
                    "claim_owner_create_time = ? WHERE plan_id = ? AND status = ? "
                    "AND claim_owner = ? AND digest = ?",
                    (
                        self._session_fingerprint,
                        self._owner_pid,
                        self._owner_create_time,
                        plan_id,
                        QuarantineState.RUNNING.value,
                        owner,
                        expected_digest,
                    ),
                ).rowcount
                if changed != 1:
                    raise PlanClaimError("dead-owner recovery claim changed")
                plan = QuarantinePlan.model_validate_json(str(row["plan_json"])).model_copy(
                    update={"state": QuarantineState.RUNNING}
                )
                phase = str(row["phase"] or "running")
                connection.commit()
                return plan, phase
            except BaseException:
                connection.rollback()
                raise

    def reset_quarantine_plan_for_retry(
        self,
        plan_id: str,
        *,
        entry: QuarantineEntry | None,
    ) -> None:
        """Recover only the unambiguous source-intact/destination-absent state."""
        from zombie_killer_engine.quarantine import QuarantineEntry, QuarantineState

        validated_entry = (
            QuarantineEntry.model_validate(entry.model_dump(mode="python"))
            if entry is not None
            else None
        )
        encoded_entry = (
            self._encode_canonical_model(validated_entry) if validated_entry is not None else None
        )
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                changed = connection.execute(
                    "UPDATE quarantine_plans SET status = ?, phase = ?, started_at = NULL, "
                    "claim_owner = NULL, claim_owner_pid = NULL, "
                    "claim_owner_create_time = NULL WHERE plan_id = ? AND status = ? "
                    "AND claim_owner = ?",
                    (
                        QuarantineState.PLANNED.value,
                        "recovered_retryable",
                        plan_id,
                        QuarantineState.RUNNING.value,
                        self._session_fingerprint,
                    ),
                ).rowcount
                if changed != 1:
                    raise StoreError("running quarantine plan could not be recovered")
                if validated_entry is not None and encoded_entry is not None:
                    self._write_quarantine_entry(connection, validated_entry, encoded_entry)
                connection.commit()
            except BaseException:
                connection.rollback()
                raise

    def claim_quarantine_plan(
        self,
        plan_id: str,
        *,
        expected_digest: str,
    ) -> QuarantinePlan:
        """Atomically make a short-lived cleanup plan one-shot."""
        from zombie_killer_engine.quarantine import QuarantinePlan, QuarantineState

        failure: PlanClaimError | None = None
        claimed: QuarantinePlan | None = None
        claimed_at = _require_utc(self._clock())
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT digest, plan_json, status, created_at, expires_at "
                    "FROM quarantine_plans WHERE plan_id = ?",
                    (plan_id,),
                ).fetchone()
                if row is None:
                    failure = PlanClaimError("quarantine plan was not found")
                elif not secrets.compare_digest(str(row["digest"]), expected_digest):
                    failure = PlanClaimError("quarantine plan digest does not match")
                elif str(row["status"]) != QuarantineState.PLANNED.value:
                    failure = PlanClaimError("quarantine plan is no longer planned")
                else:
                    try:
                        candidate = QuarantinePlan.model_validate_json(str(row["plan_json"]))
                    except ValueError:
                        candidate = None
                        failure = PlanClaimError("stored quarantine plan is invalid")
                    if candidate is not None and (
                        candidate.plan_id != plan_id
                        or not secrets.compare_digest(candidate.digest, expected_digest)
                        or _utc_text(candidate.created_at) != str(row["created_at"])
                        or _utc_text(candidate.expires_at) != str(row["expires_at"])
                    ):
                        candidate = None
                        failure = PlanClaimError(
                            "stored quarantine plan does not match authoritative columns"
                        )
                    if candidate is None:
                        pass
                    elif claimed_at >= candidate.expires_at:
                        connection.execute(
                            "UPDATE quarantine_plans SET status = ?, phase = ?, "
                            "finished_at = ? WHERE plan_id = ? AND status = ?",
                            (
                                QuarantineState.FAILED.value,
                                "expired",
                                _utc_text(claimed_at),
                                plan_id,
                                QuarantineState.PLANNED.value,
                            ),
                        )
                        failure = ExpiredPlanError("quarantine plan has expired")
                    else:
                        changed = connection.execute(
                            "UPDATE quarantine_plans SET status = ?, phase = ?, "
                            "started_at = ?, claim_owner = ?, claim_owner_pid = ?, "
                            "claim_owner_create_time = ? WHERE plan_id = ? "
                            "AND status = ? AND digest = ?",
                            (
                                QuarantineState.RUNNING.value,
                                "claimed",
                                _utc_text(claimed_at),
                                self._session_fingerprint,
                                self._owner_pid,
                                self._owner_create_time,
                                plan_id,
                                QuarantineState.PLANNED.value,
                                expected_digest,
                            ),
                        ).rowcount
                        if changed != 1:
                            failure = PlanClaimError(
                                "quarantine plan could not be claimed atomically"
                            )
                        else:
                            claimed = candidate.model_copy(
                                update={"state": QuarantineState.RUNNING}
                            )
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
        if failure is not None:
            raise failure
        if claimed is None:
            raise StoreError("quarantine plan claim produced no result")
        return claimed

    def update_quarantine_plan_phase(self, plan_id: str, phase: str) -> None:
        cleaned = redact_text(phase, max_length=64).strip()
        if not cleaned or cleaned != phase:
            raise ValueError("quarantine phase must be bounded and display-safe")
        from zombie_killer_engine.quarantine import QuarantineState

        prior_phase = {
            "validating": "claimed",
            "journaled": "validating",
            "graveyard_prepared": "journaled",
            "running": "graveyard_prepared",
            "rename_issuing": "running",
            "renamed": "rename_issuing",
        }.get(cleaned)
        if prior_phase is None:
            raise StoreError("unsupported quarantine phase transition")

        with closing(self._connect()) as connection:
            changed = connection.execute(
                "UPDATE quarantine_plans SET phase = ? WHERE plan_id = ? AND status = ? "
                "AND claim_owner = ? AND phase = ?",
                (
                    cleaned,
                    plan_id,
                    QuarantineState.RUNNING.value,
                    self._session_fingerprint,
                    prior_phase,
                ),
            ).rowcount
        if changed != 1:
            raise StoreError("quarantine phase or claim owner does not match")

    def save_quarantine_entry(self, entry: QuarantineEntry) -> None:
        """Journal restricted raw restore metadata outside generic audit storage."""
        from zombie_killer_engine.quarantine import (
            QuarantineEntry,
            QuarantinePlan,
            QuarantineState,
        )

        validated = QuarantineEntry.model_validate(entry.model_dump(mode="python"))
        encoded = self._encode_canonical_model(validated)
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT plan_json, status, claim_owner FROM quarantine_plans WHERE plan_id = ?",
                    (validated.plan_id,),
                ).fetchone()
                if row is None:
                    raise StoreError("quarantine entry plan was not found")
                plan = QuarantinePlan.model_validate_json(str(row["plan_json"]))
                if (
                    str(row["status"]) != QuarantineState.RUNNING.value
                    or str(row["claim_owner"] or "") != self._session_fingerprint
                    or validated.correlation_id != plan.correlation_id
                    or validated.agent_id != plan.agent_id
                    or validated.resource_type is not plan.resource_type
                    or validated.approved_root != plan.approved_root
                    or validated.original_path != plan.target
                    or validated.original_path_hash != plan.target_hash
                    or validated.root_hash != plan.root_hash
                ):
                    raise StoreError("quarantine entry does not match the claimed plan")
                self._write_quarantine_entry(connection, validated, encoded)
                connection.commit()
            except BaseException:
                connection.rollback()
                raise

    def get_quarantine_entry(self, entry_id: str) -> QuarantineEntry | None:
        from zombie_killer_engine.quarantine import QuarantineEntry, QuarantineState

        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT state_json, status FROM quarantine_entries WHERE entry_id = ?",
                (entry_id,),
            ).fetchone()
        if row is None:
            return None
        stored = QuarantineEntry.model_validate_json(str(row["state_json"]))
        if stored.state.value != str(row["status"]):
            stored = stored.model_copy(update={"state": QuarantineState(str(row["status"]))})
        return stored

    def list_quarantine_entries(
        self, *, limit: int = 500, cursor: str | None = None
    ) -> tuple[QuarantineEntryListing, ...]:
        from zombie_killer_engine.quarantine import QuarantineEntry, QuarantineState

        if not 1 <= limit <= 500:
            raise ValueError("quarantine entry limit is outside the supported bound")
        with closing(self._connect()) as connection:
            cursor_clause = ""
            cursor_values: tuple[object, ...] = ()
            if cursor is not None:
                cursor_row = connection.execute(
                    "SELECT created_at, entry_id FROM quarantine_entries "
                    "WHERE entry_id = ? AND status IN (?, ?, ?, ?)",
                    (
                        cursor,
                        QuarantineState.SUCCEEDED.value,
                        QuarantineState.PARTIAL.value,
                        QuarantineState.INTERRUPTED.value,
                        QuarantineState.RESTORED.value,
                    ),
                ).fetchone()
                if cursor_row is None:
                    raise ValueError("quarantine cursor is invalid or no longer available")
                cursor_clause = "AND (created_at < ? OR (created_at = ? AND entry_id < ?)) "
                cursor_values = (
                    str(cursor_row["created_at"]),
                    str(cursor_row["created_at"]),
                    str(cursor_row["entry_id"]),
                )
            rows = connection.execute(
                "SELECT state_json, status, restore_claim_owner, "
                "restore_claim_owner_pid, restore_claim_owner_create_time "
                "FROM quarantine_entries "
                "WHERE status IN (?, ?, ?, ?) "
                + cursor_clause
                + "ORDER BY created_at DESC, entry_id DESC LIMIT ?",
                (
                    QuarantineState.SUCCEEDED.value,
                    QuarantineState.PARTIAL.value,
                    QuarantineState.INTERRUPTED.value,
                    QuarantineState.RESTORED.value,
                    *cursor_values,
                    limit,
                ),
            ).fetchall()
        entries = []
        for row in rows:
            stored = QuarantineEntry.model_validate_json(str(row["state_json"]))
            if stored.state.value != str(row["status"]):
                stored = stored.model_copy(update={"state": QuarantineState(str(row["status"]))})
            owner = str(row["restore_claim_owner"] or "")
            entries.append(
                QuarantineEntryListing(
                    entry=stored,
                    restoring=self._claim_owner_alive(
                        owner,
                        row["restore_claim_owner_pid"],
                        row["restore_claim_owner_create_time"],
                    ),
                )
            )
        return tuple(entries)

    def claim_quarantine_restore(self, entry_id: str) -> QuarantineEntry:
        """Claim one restore attempt by exact owner process identity."""
        from zombie_killer_engine.quarantine import QuarantineEntry, QuarantineState

        allowed = {QuarantineState.SUCCEEDED}
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT state_json, status, restore_claim_owner, "
                    "restore_claim_owner_pid, restore_claim_owner_create_time "
                    "FROM quarantine_entries WHERE entry_id = ?",
                    (entry_id,),
                ).fetchone()
                if row is None:
                    raise StoreError("quarantine entry was not found")
                entry = QuarantineEntry.model_validate_json(str(row["state_json"]))
                entry = entry.model_copy(update={"state": QuarantineState(str(row["status"]))})
                if entry.state not in allowed:
                    raise PlanClaimError("quarantine entry is not restoreable")
                owner_value = row["restore_claim_owner"]
                owner = "" if owner_value is None else str(owner_value)
                if owner and self._claim_owner_alive(
                    owner,
                    row["restore_claim_owner_pid"],
                    row["restore_claim_owner_create_time"],
                ):
                    raise PlanClaimError("quarantine restore owner is alive")
                changed = connection.execute(
                    "UPDATE quarantine_entries SET restore_claim_owner = ?, "
                    "restore_claim_owner_pid = ?, restore_claim_owner_create_time = ? "
                    "WHERE entry_id = ? AND restore_claim_owner IS ?",
                    (
                        self._session_fingerprint,
                        self._owner_pid,
                        self._owner_create_time,
                        entry_id,
                        owner_value,
                    ),
                ).rowcount
                if changed != 1:
                    raise PlanClaimError("quarantine restore claim changed")
                connection.commit()
                return entry
            except BaseException:
                connection.rollback()
                raise

    def preflight_quarantine_restore(self, entry_id: str) -> None:
        """Prove the claimed restore journal can be read and written before rename."""
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                if self._current_version(connection) != self.schema_version:
                    raise StoreError("restore journal schema version is not current")
                row = connection.execute(
                    "SELECT e.plan_id, e.state_json, e.status, "
                    "e.restore_claim_owner, e.restore_claim_owner_pid, "
                    "e.restore_claim_owner_create_time, p.digest, p.plan_json, "
                    "p.status, p.phase, p.legacy_recovery_reason "
                    "FROM quarantine_entries AS e "
                    "JOIN quarantine_plans AS p ON p.plan_id = e.plan_id "
                    "WHERE e.entry_id = ?",
                    (entry_id,),
                ).fetchone()
                if row is None:
                    raise StoreError("restore journal entry or plan was not found")
                if str(row["restore_claim_owner"] or "") != self._session_fingerprint:
                    raise StoreError("restore journal claim owner changed")
                connection.execute(
                    "SELECT receipt_id, plan_id, entry_id, operation, result, "
                    "receipt_json, created_at FROM quarantine_receipts LIMIT 0"
                ).fetchall()
                connection.execute("SAVEPOINT restore_audit_preflight")
                connection.execute(
                    "INSERT INTO audit_events(event_id, correlation_id, event_type, "
                    "details_json, created_at) VALUES (?, ?, ?, ?, ?)",
                    (
                        secrets.token_urlsafe(24),
                        hashlib.sha256(f"restore-preflight\0{entry_id}".encode()).hexdigest(),
                        "restore_preflight",
                        self._serialize_json({"preflight": True}),
                        _utc_text(_require_utc(self._clock())),
                    ),
                )
                connection.execute("ROLLBACK TO restore_audit_preflight")
                connection.execute("RELEASE restore_audit_preflight")
                writable = connection.execute(
                    "UPDATE quarantine_entries SET updated_at = updated_at "
                    "WHERE entry_id = ? AND restore_claim_owner = ?",
                    (entry_id, self._session_fingerprint),
                ).rowcount
                if writable != 1:
                    raise StoreError("restore journal preflight write failed")
                connection.commit()
            except BaseException:
                connection.rollback()
                raise

    def release_quarantine_restore(self, entry_id: str) -> None:
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT restore_claim_owner FROM quarantine_entries WHERE entry_id = ?",
                    (entry_id,),
                ).fetchone()
                if row is None:
                    raise StoreError("quarantine entry was not found")
                owner = row["restore_claim_owner"]
                if owner is None:
                    connection.commit()
                    return
                if str(owner) != self._session_fingerprint:
                    raise StoreError("quarantine restore claim owner does not match")
                changed = connection.execute(
                    "UPDATE quarantine_entries SET restore_claim_owner = NULL, "
                    "restore_claim_owner_pid = NULL, "
                    "restore_claim_owner_create_time = NULL "
                    "WHERE entry_id = ? AND restore_claim_owner = ?",
                    (entry_id, self._session_fingerprint),
                ).rowcount
                if changed != 1:
                    raise StoreError("quarantine restore claim changed")
                connection.commit()
            except BaseException:
                connection.rollback()
                raise

    def get_quarantine_entry_for_plan(self, plan_id: str) -> QuarantineEntry | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT entry_id FROM quarantine_entries WHERE plan_id = ?",
                (plan_id,),
            ).fetchone()
        return None if row is None else self.get_quarantine_entry(str(row[0]))

    def get_quarantine_receipt_for_plan(
        self, plan_id: str, *, expected_digest: str
    ) -> QuarantineReceipt | None:
        from zombie_killer_engine.quarantine import QuarantineReceipt

        with closing(self._connect()) as connection:
            plan_row = connection.execute(
                "SELECT digest FROM quarantine_plans WHERE plan_id = ?",
                (plan_id,),
            ).fetchone()
            if plan_row is None:
                raise PlanClaimError("quarantine plan was not found")
            if not secrets.compare_digest(str(plan_row["digest"]), expected_digest):
                raise PlanClaimError("quarantine plan digest does not match")
            row = connection.execute(
                "SELECT receipt_json FROM quarantine_receipts "
                "WHERE plan_id = ? AND operation = 'quarantine' "
                "ORDER BY created_at, receipt_id LIMIT 1",
                (plan_id,),
            ).fetchone()
        return (
            None if row is None else QuarantineReceipt.model_validate_json(str(row["receipt_json"]))
        )

    @staticmethod
    def _write_quarantine_entry(
        connection: sqlite3.Connection,
        entry: QuarantineEntry,
        encoded: str,
    ) -> None:
        from zombie_killer_engine.quarantine import QuarantineEntry

        existing_row = connection.execute(
            "SELECT state_json FROM quarantine_entries WHERE entry_id = ?",
            (entry.entry_id,),
        ).fetchone()
        if existing_row is not None:
            existing = QuarantineEntry.model_validate_json(str(existing_row["state_json"]))
            if (
                not secrets.compare_digest(existing.digest, entry.digest)
                or existing.immutable_fields() != entry.immutable_fields()
            ):
                raise StoreError("quarantine journal immutable binding cannot be overwritten")
        connection.execute(
            "INSERT INTO quarantine_entries("
            "entry_id, state_json, created_at, plan_id, status, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(entry_id) DO UPDATE SET "
            "state_json = excluded.state_json, status = excluded.status, "
            "updated_at = excluded.updated_at",
            (
                entry.entry_id,
                encoded,
                _utc_text(entry.created_at),
                entry.plan_id,
                entry.state.value,
                _utc_text(entry.updated_at),
            ),
        )

    def _write_quarantine_receipt(
        self,
        connection: sqlite3.Connection,
        receipt: QuarantineReceipt,
    ) -> None:
        receipt_json = self._encode_canonical_model(receipt)
        audit_json = self._serialize_json({"receipt": receipt.model_dump(mode="json")})
        connection.execute(
            "INSERT INTO quarantine_receipts("
            "receipt_id, plan_id, entry_id, operation, result, receipt_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                receipt.receipt_id,
                receipt.plan_id,
                receipt.entry_id,
                receipt.operation,
                receipt.result.value,
                receipt_json,
                _utc_text(receipt.finished_at),
            ),
        )
        connection.execute(
            "INSERT INTO audit_events(event_id, correlation_id, event_type, "
            "details_json, created_at) VALUES (?, ?, ?, ?, ?)",
            (
                receipt.audit_event_id,
                hashlib.sha256(f"correlation\0{receipt.correlation_id}".encode()).hexdigest(),
                "quarantine_receipt",
                audit_json,
                _utc_text(receipt.finished_at),
            ),
        )

    def get_quarantine_receipt_for_entry(
        self,
        entry_id: str,
        *,
        operation: str,
        result: QuarantineResult,
    ) -> QuarantineReceipt | None:
        from zombie_killer_engine.quarantine import QuarantineReceipt

        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT receipt_json FROM quarantine_receipts WHERE entry_id = ? "
                "AND operation = ? AND result = ? ORDER BY created_at, receipt_id "
                "LIMIT 1",
                (entry_id, operation, result.value),
            ).fetchone()
        return (
            None if row is None else QuarantineReceipt.model_validate_json(str(row["receipt_json"]))
        )

    def finish_quarantine_plan(
        self,
        plan_id: str,
        *,
        state: QuarantineState,
        receipt: QuarantineReceipt,
        entry: QuarantineEntry | None,
    ) -> None:
        from zombie_killer_engine.quarantine import (
            QuarantineEntry,
            QuarantinePlan,
            QuarantineReceipt,
            QuarantineResult,
            QuarantineState,
        )

        if state not in {
            QuarantineState.SUCCEEDED,
            QuarantineState.PARTIAL,
            QuarantineState.FAILED,
            QuarantineState.INTERRUPTED,
        }:
            raise ValueError("quarantine plan must finish in a terminal state")
        validated_receipt = QuarantineReceipt.model_validate(receipt.model_dump(mode="python"))
        validated_entry = (
            QuarantineEntry.model_validate(entry.model_dump(mode="python"))
            if entry is not None
            else None
        )
        encoded_entry = (
            self._encode_canonical_model(validated_entry) if validated_entry is not None else None
        )
        expected_results = {
            QuarantineState.SUCCEEDED: QuarantineResult.QUARANTINED,
            QuarantineState.PARTIAL: QuarantineResult.PARTIAL,
            QuarantineState.FAILED: QuarantineResult.FAILED,
            QuarantineState.INTERRUPTED: QuarantineResult.INTERRUPTED,
        }
        if (
            validated_receipt.plan_id != plan_id
            or validated_receipt.operation != "quarantine"
            or validated_receipt.result is not expected_results[state]
        ):
            raise StoreError("quarantine receipt does not match terminal plan state")
        allowed_phases = {
            QuarantineState.SUCCEEDED: {"rename_issuing", "renamed"},
            QuarantineState.PARTIAL: {"rename_issuing", "renamed"},
            QuarantineState.FAILED: {
                "claimed",
                "validating",
                "journaled",
                "graveyard_prepared",
                "running",
                "rename_issuing",
            },
            QuarantineState.INTERRUPTED: {
                "claimed",
                "validating",
                "journaled",
                "graveyard_prepared",
                "running",
                "rename_issuing",
                "renamed",
            },
        }
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT plan_json, digest, phase FROM quarantine_plans "
                    "WHERE plan_id = ? AND status = ? AND claim_owner = ?",
                    (
                        plan_id,
                        QuarantineState.RUNNING.value,
                        self._session_fingerprint,
                    ),
                ).fetchone()
                if row is None:
                    raise StoreError("quarantine plan claim owner does not match")
                plan = QuarantinePlan.model_validate_json(str(row["plan_json"]))
                expected_content_hash = plan.fingerprint.sha256 or plan.fingerprint.inventory_digest
                if (
                    not secrets.compare_digest(plan.digest, str(row["digest"]))
                    or validated_receipt.correlation_id != plan.correlation_id
                    or validated_receipt.root_hash != plan.root_hash
                    or validated_receipt.target_hash != plan.target_hash
                    or validated_receipt.content_hash != expected_content_hash
                    or validated_receipt.size != plan.fingerprint.total_bytes
                    or validated_receipt.entry_count != plan.fingerprint.entry_count
                    or validated_receipt.agent_hash
                    != hashlib.sha256(f"agent\0{plan.agent_id}".encode()).hexdigest()
                    or validated_receipt.session_hash
                    != hashlib.sha256(f"session\0{self.session_id}".encode()).hexdigest()
                    or str(row["phase"]) not in allowed_phases[state]
                ):
                    raise StoreError("quarantine receipt or phase does not match plan")
                if (validated_entry is None) != (validated_receipt.entry_id is None) or (
                    state in {QuarantineState.SUCCEEDED, QuarantineState.PARTIAL}
                    and validated_entry is None
                ):
                    raise StoreError("quarantine receipt entry relationship is invalid")
                if validated_entry is not None and (
                    validated_entry.plan_id != plan.plan_id
                    or validated_entry.correlation_id != plan.correlation_id
                    or validated_entry.resource_type is not plan.resource_type
                    or validated_entry.agent_id != plan.agent_id
                    or validated_entry.entry_id != validated_receipt.entry_id
                    or validated_entry.state is not state
                ):
                    raise StoreError("quarantine entry does not match plan or receipt")
                changed = connection.execute(
                    "UPDATE quarantine_plans SET status = ?, phase = ?, finished_at = ? "
                    "WHERE plan_id = ? AND status = ? AND claim_owner = ?",
                    (
                        state.value,
                        state.value,
                        _utc_text(validated_receipt.finished_at),
                        plan_id,
                        QuarantineState.RUNNING.value,
                        self._session_fingerprint,
                    ),
                ).rowcount
                if changed != 1:
                    raise StoreError("quarantine plan is not running")
                if validated_entry is not None and encoded_entry is not None:
                    self._write_quarantine_entry(connection, validated_entry, encoded_entry)
                self._write_quarantine_receipt(connection, validated_receipt)
                connection.commit()
            except BaseException:
                connection.rollback()
                raise

    def save_quarantine_receipt(
        self,
        receipt: QuarantineReceipt,
        *,
        entry: QuarantineEntry | None,
    ) -> None:
        from zombie_killer_engine.quarantine import (
            LegacyRecoveryReason,
            LegacyRestorePlan,
            QuarantineEntry,
            QuarantinePlan,
            QuarantineReceipt,
            QuarantineResult,
            QuarantineState,
        )

        validated_receipt = QuarantineReceipt.model_validate(receipt.model_dump(mode="python"))
        validated_entry = (
            QuarantineEntry.model_validate(entry.model_dump(mode="python"))
            if entry is not None
            else None
        )
        encoded_entry = (
            self._encode_canonical_model(validated_entry) if validated_entry is not None else None
        )
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                if (
                    validated_receipt.operation != "restore"
                    or validated_receipt.entry_id is None
                    or validated_receipt.result
                    not in {
                        QuarantineResult.RESTORED,
                        QuarantineResult.ALREADY_RESTORED,
                        QuarantineResult.FAILED,
                        QuarantineResult.INTERRUPTED,
                    }
                ):
                    raise StoreError("unsupported quarantine receipt transition")
                plan_row = connection.execute(
                    "SELECT plan_json, digest, status, phase, "
                    "legacy_recovery_reason FROM quarantine_plans WHERE plan_id = ?",
                    (validated_receipt.plan_id,),
                ).fetchone()
                entry_row = connection.execute(
                    "SELECT state_json, status, restore_claim_owner FROM quarantine_entries "
                    "WHERE entry_id = ?",
                    (validated_receipt.entry_id,),
                ).fetchone()
                if plan_row is None or entry_row is None:
                    raise StoreError("restore receipt plan or entry was not found")
                legacy_reason = plan_row["legacy_recovery_reason"]
                plan: QuarantinePlan | LegacyRestorePlan
                if legacy_reason is None:
                    plan = QuarantinePlan.model_validate_json(str(plan_row["plan_json"]))
                elif (
                    str(legacy_reason) == LegacyRecoveryReason.MISSING_MANIFEST_AUTHORITY.value
                    and str(plan_row["phase"]) == "legacy_restore_only"
                ):
                    plan = LegacyRestorePlan.model_validate_json(str(plan_row["plan_json"]))
                else:
                    raise StoreError("legacy quarantine plan is not restore-only")
                if not secrets.compare_digest(plan.digest, str(plan_row["digest"])):
                    raise StoreError("restore plan evidence digest changed")
                stored_entry = QuarantineEntry.model_validate_json(str(entry_row["state_json"]))
                if stored_entry.state.value != str(entry_row["status"]):
                    stored_entry = stored_entry.model_copy(
                        update={"state": QuarantineState(str(entry_row["status"]))}
                    )
                expected_content_hash = plan.fingerprint.sha256 or plan.fingerprint.inventory_digest
                restore_claim_owner = str(entry_row["restore_claim_owner"] or "")
                post_restore_observation = (
                    stored_entry.state is QuarantineState.RESTORED
                    and validated_entry is None
                    and validated_receipt.result
                    in {
                        QuarantineResult.ALREADY_RESTORED,
                        QuarantineResult.FAILED,
                    }
                    and not restore_claim_owner
                )
                owns_restore_claim = restore_claim_owner == self._session_fingerprint
                if (
                    str(plan_row["status"])
                    not in {
                        QuarantineState.SUCCEEDED.value,
                        QuarantineState.PARTIAL.value,
                        QuarantineState.INTERRUPTED.value,
                    }
                    or validated_receipt.correlation_id != plan.correlation_id
                    or validated_receipt.root_hash != plan.root_hash
                    or validated_receipt.target_hash != plan.target_hash
                    or validated_receipt.content_hash != expected_content_hash
                    or validated_receipt.size != plan.fingerprint.total_bytes
                    or validated_receipt.entry_count != plan.fingerprint.entry_count
                    or validated_receipt.agent_hash
                    != hashlib.sha256(f"agent\0{plan.agent_id}".encode()).hexdigest()
                    or validated_receipt.session_hash
                    != hashlib.sha256(f"session\0{self.session_id}".encode()).hexdigest()
                    or stored_entry.plan_id != plan.plan_id
                    or stored_entry.correlation_id != plan.correlation_id
                    or stored_entry.agent_id != plan.agent_id
                    or stored_entry.resource_type is not plan.resource_type
                    or stored_entry.entry_id != validated_receipt.entry_id
                    or not (owns_restore_claim or post_restore_observation)
                ):
                    raise StoreError("restore receipt does not match plan and entry")
                expected_entry_state = {
                    QuarantineResult.RESTORED: QuarantineState.RESTORED,
                    QuarantineResult.INTERRUPTED: QuarantineState.INTERRUPTED,
                }.get(validated_receipt.result)
                if validated_entry is not None and (
                    expected_entry_state is None
                    or validated_entry.entry_id != stored_entry.entry_id
                    or validated_entry.plan_id != plan.plan_id
                    or validated_entry.correlation_id != plan.correlation_id
                    or validated_entry.resource_type is not plan.resource_type
                    or validated_entry.agent_id != plan.agent_id
                    or validated_entry.state is not expected_entry_state
                    or not validated_entry.verify_digest()
                ):
                    raise StoreError("restored entry does not match its receipt")
                if validated_entry is None and validated_receipt.result in {
                    QuarantineResult.RESTORED,
                    QuarantineResult.INTERRUPTED,
                }:
                    raise StoreError("restore outcome requires updated recovery metadata")
                if validated_entry is not None and encoded_entry is not None:
                    self._write_quarantine_entry(connection, validated_entry, encoded_entry)
                self._write_quarantine_receipt(connection, validated_receipt)
                if owns_restore_claim:
                    released = connection.execute(
                        "UPDATE quarantine_entries SET restore_claim_owner = NULL, "
                        "restore_claim_owner_pid = NULL, "
                        "restore_claim_owner_create_time = NULL "
                        "WHERE entry_id = ? AND restore_claim_owner = ?",
                        (validated_receipt.entry_id, self._session_fingerprint),
                    ).rowcount
                    if released != 1:
                        raise StoreError("quarantine restore claim changed")
                connection.commit()
            except BaseException:
                connection.rollback()
                raise

    def register_vault_source(self, source: VaultSource) -> None:
        """Register bounded vault metadata; source content is never persisted."""
        from zombie_killer_engine.memory import VaultSource

        if not isinstance(source, VaultSource):
            raise TypeError("source must be a VaultSource")
        timestamp = _utc_text(self._clock())
        capabilities = self._serialize_json(source.capabilities.model_dump(mode="json"))
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    "INSERT INTO vault_sources("
                    "source_id, source_path, format, capabilities_json, revision, "
                    "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(source_id) DO UPDATE SET "
                    "source_path = excluded.source_path, format = excluded.format, "
                    "capabilities_json = excluded.capabilities_json, "
                    "revision = excluded.revision, updated_at = excluded.updated_at",
                    (
                        source.source_id,
                        source.path,
                        source.format.value,
                        capabilities,
                        source.revision,
                        timestamp,
                        timestamp,
                    ),
                )
                connection.commit()
            except BaseException:
                connection.rollback()
                raise

    def list_vault_sources(self, *, limit: int = 500, offset: int = 0) -> tuple[VaultSource, ...]:
        from zombie_killer_engine.memory import VaultCapabilities, VaultFormat, VaultSource

        if not 1 <= limit <= 500:
            raise ValueError("vault source limit is outside the supported bound")
        if offset < 0 or offset > 10_000_000:
            raise ValueError("vault source offset is outside the supported bound")
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT source_id, source_path, format, capabilities_json, revision "
                "FROM vault_sources ORDER BY updated_at DESC, source_id LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return tuple(
            VaultSource(
                source_id=str(row[0]),
                path=str(row[1]),
                format=VaultFormat(str(row[2])),
                capabilities=VaultCapabilities.model_validate_json(row[3]),
                revision=str(row[4]),
            )
            for row in rows
        )

    def vault_sources_revision(self) -> str:
        """Return a stable digest that invalidates offset cursors after any registry change."""
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT source_id, source_path, format, capabilities_json, revision, "
                "updated_at FROM vault_sources ORDER BY source_id"
            ).fetchall()
        canonical = json.dumps(
            [[str(value) for value in row] for row in rows],
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def get_vault_source(self, source_id: str) -> VaultSource | None:
        from zombie_killer_engine.memory import VaultCapabilities, VaultFormat, VaultSource

        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT source_id, source_path, format, capabilities_json, revision "
                "FROM vault_sources WHERE source_id = ?",
                (source_id,),
            ).fetchone()
        if row is None:
            return None
        return VaultSource(
            source_id=str(row[0]),
            path=str(row[1]),
            format=VaultFormat(str(row[2])),
            capabilities=VaultCapabilities.model_validate_json(row[3]),
            revision=str(row[4]),
        )

    def save_memory_plan(self, plan: MutationPlan) -> None:
        """Journal authority hashes and field names, never proposed values."""
        from zombie_killer_engine.memory import MutationPlan

        if not isinstance(plan, MutationPlan):
            raise TypeError("plan must be a MutationPlan")
        field_names = self._serialize_json([item.field_name for item in plan.diff])
        source_identity = self._serialize_json(plan.source_identity.model_dump(mode="json"))
        diff = self._serialize_json([item.model_dump(mode="json") for item in plan.diff])
        with closing(self._connect()) as connection:
            connection.execute(
                "INSERT INTO memory_mutation_plans("
                "plan_id, source_id, digest, source_revision, operation, record_id, "
                "field_names_json, expected_old_hash, new_store_hash, status, "
                "created_at, expires_at, source_identity_json, record_hash, "
                "operation_field, operation_metadata_key, proposed_value_hash, "
                "proposed_value_type, diff_json, old_store_hash, phase) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    plan.plan_id,
                    plan.source_id,
                    plan.digest,
                    plan.source_revision,
                    plan.operation_kind.value,
                    plan.record_id,
                    field_names,
                    plan.expected_old_hash,
                    plan.new_store_hash,
                    "planned",
                    _utc_text(plan.created_at),
                    _utc_text(plan.expires_at),
                    source_identity,
                    plan.record_hash,
                    plan.operation_field,
                    plan.operation_metadata_key,
                    plan.proposed_value_hash,
                    plan.proposed_value_type,
                    diff,
                    plan.old_store_hash,
                    "planned",
                ),
            )

    @staticmethod
    def _memory_authority_from_row(row: sqlite3.Row) -> MemoryPlanAuthority:
        from zombie_killer_engine.memory import (
            FieldDiff,
            FileIdentity,
            MemoryPlanAuthority,
            MutationKind,
        )

        try:
            identity = FileIdentity.model_validate(json.loads(str(row["source_identity_json"])))
            field_names_value = json.loads(str(row["field_names_json"]))
            diff_value = json.loads(str(row["diff_json"]))
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise StoreError("memory plan authority is corrupt") from error
        return MemoryPlanAuthority(
            plan_id=str(row["plan_id"]),
            source_id=str(row["source_id"]),
            digest=str(row["digest"]),
            source_revision=str(row["source_revision"]),
            source_identity=identity,
            operation_kind=MutationKind(str(row["operation"])),
            record_id=str(row["record_id"]),
            record_hash=str(row["record_hash"]),
            operation_field=(
                str(row["operation_field"]) if row["operation_field"] is not None else None
            ),
            operation_metadata_key=(
                str(row["operation_metadata_key"])
                if row["operation_metadata_key"] is not None
                else None
            ),
            proposed_value_hash=str(row["proposed_value_hash"]),
            proposed_value_type=str(row["proposed_value_type"]),
            field_names=tuple(str(item) for item in field_names_value),
            diff=tuple(FieldDiff.model_validate(item) for item in diff_value),
            expected_old_hash=str(row["expected_old_hash"]),
            old_store_hash=str(row["old_store_hash"]),
            new_store_hash=str(row["new_store_hash"]),
            status=str(row["status"]),
            phase=str(row["phase"]),
            snapshot_id=(str(row["snapshot_id"]) if row["snapshot_id"] is not None else None),
            created_at=_parse_utc(str(row["created_at"])),
            expires_at=_parse_utc(str(row["expires_at"])),
        )

    def claim_memory_plan(self, plan_id: str, *, expected_digest: str) -> MemoryPlanAuthority:
        validated_id = _IDENTIFIER_ADAPTER.validate_python(plan_id)
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                now = self._clock()
                row = connection.execute(
                    "SELECT * FROM memory_mutation_plans WHERE plan_id = ?",
                    (validated_id,),
                ).fetchone()
                if row is None or not secrets.compare_digest(str(row["digest"]), expected_digest):
                    raise PlanClaimError("memory plan claim authority did not match")
                from zombie_killer_engine.memory.base import authority_plan_digest

                authority = self._memory_authority_from_row(row)
                if not secrets.compare_digest(authority.digest, authority_plan_digest(authority)):
                    raise PlanClaimError("memory plan persisted digest is invalid")
                if now >= _parse_utc(str(row["expires_at"])):
                    connection.execute(
                        "UPDATE memory_mutation_plans SET status = 'expired', "
                        "phase = 'expired' WHERE plan_id = ?",
                        (validated_id,),
                    )
                    connection.commit()
                    raise ExpiredPlanError("memory plan expired before claim")
                if str(row["status"]) != "planned":
                    raise PlanClaimError("memory plan is already claimed or replayed")
                self._heartbeat_memory_session(connection, now)
                updated = connection.execute(
                    "UPDATE memory_mutation_plans SET status = 'running', "
                    "phase = 'claimed', claim_owner = ?, claim_owner_pid = ?, "
                    "claim_owner_create_time = ?, claimed_at = ? "
                    "WHERE plan_id = ? AND digest = ? AND status = 'planned'",
                    (
                        self._memory_session_nonce,
                        self._owner_pid,
                        self._owner_create_time,
                        _utc_text(now),
                        validated_id,
                        expected_digest,
                    ),
                )
                if updated.rowcount != 1:
                    raise PlanClaimError("memory plan claim lost an atomic race")
                claimed = connection.execute(
                    "SELECT * FROM memory_mutation_plans WHERE plan_id = ?",
                    (validated_id,),
                ).fetchone()
                if claimed is None:
                    raise PlanClaimError("memory plan claim could not be loaded")
                claimed_authority = self._memory_authority_from_row(claimed)
                connection.commit()
            except BaseException:
                if connection.in_transaction:
                    connection.rollback()
                raise
        return claimed_authority

    def update_memory_plan_phase(
        self,
        plan_id: str,
        phase: str,
        *,
        snapshot_id: str | None = None,
    ) -> None:
        allowed = {
            "snapshot_verified",
            "write_issuing",
            "committed",
            "post_verifying",
            "restore_issuing",
        }
        if phase not in allowed:
            raise ValueError("memory plan phase is not recognized")
        validated_id = _IDENTIFIER_ADAPTER.validate_python(plan_id)

        def write_phase(connection: sqlite3.Connection) -> None:
            self._heartbeat_memory_session(connection)
            updated = connection.execute(
                "UPDATE memory_mutation_plans SET phase = ?, "
                "snapshot_id = COALESCE(?, snapshot_id) "
                "WHERE plan_id = ? AND status = 'running' AND claim_owner = ?",
                (phase, snapshot_id, validated_id, self._memory_session_nonce),
            )
            if updated.rowcount != 1:
                raise PlanClaimError("memory plan phase owner or state did not match")

        self._memory_journal_write(write_phase)

    def fail_memory_plan(self, plan_id: str, *, interrupted: bool) -> None:
        validated_id = _IDENTIFIER_ADAPTER.validate_python(plan_id)
        status = "interrupted" if interrupted else "failed"
        phase = "reconcile_required" if interrupted else "failed"

        def write_failure(connection: sqlite3.Connection) -> None:
            self._heartbeat_memory_session(connection)
            updated = connection.execute(
                "UPDATE memory_mutation_plans SET status = ?, phase = ?, "
                "claim_owner = NULL, claim_owner_pid = NULL, "
                "claim_owner_create_time = NULL WHERE plan_id = ? "
                "AND status = 'running' AND claim_owner = ?",
                (status, phase, validated_id, self._memory_session_nonce),
            )
            if updated.rowcount != 1:
                raise PlanClaimError("memory plan failure owner or state did not match")

        self._memory_journal_write(write_failure)

    def list_memory_reconciliation(self, source_id: str) -> tuple[MemoryPlanAuthority, ...]:
        validated_id = _IDENTIFIER_ADAPTER.validate_python(source_id)
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT * FROM memory_mutation_plans WHERE source_id = ? "
                "AND status = 'interrupted' AND phase = 'reconcile_required' "
                "ORDER BY created_at",
                (validated_id,),
            ).fetchall()
        return tuple(self._memory_authority_from_row(row) for row in rows)

    def finish_memory_reconciliation(self, receipt: MemoryReceipt, *, succeeded: bool) -> None:
        if receipt.plan_id is None:
            raise ValueError("a reconciliation receipt must reference its plan")
        status = "succeeded" if succeeded else "failed"
        phase = "recovered_completed" if succeeded else "recovered_rolled_back"
        field_names = self._serialize_json(list(receipt.field_names))

        def write_reconciliation(connection: sqlite3.Connection) -> None:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._heartbeat_memory_session(connection)
                updated = connection.execute(
                    "UPDATE memory_mutation_plans SET status = ?, phase = ? "
                    "WHERE plan_id = ? AND status = 'interrupted' "
                    "AND phase = 'reconcile_required' AND snapshot_id = ?",
                    (status, phase, receipt.plan_id, receipt.snapshot_id),
                )
                if updated.rowcount != 1:
                    raise PlanClaimError("memory reconciliation state did not match")
                connection.execute(
                    "INSERT INTO memory_receipts("
                    "receipt_id, plan_id, snapshot_id, source_id, operation, "
                    "field_names_json, before_revision, after_revision, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        receipt.receipt_id,
                        receipt.plan_id,
                        receipt.snapshot_id,
                        receipt.source_id,
                        receipt.operation,
                        field_names,
                        receipt.before_revision,
                        receipt.after_revision,
                        _utc_text(receipt.created_at),
                    ),
                )
                connection.commit()
            except BaseException:
                connection.rollback()
                raise

        self._memory_journal_write(write_reconciliation)

    @staticmethod
    def _memory_restore_from_row(row: sqlite3.Row) -> RestoreAuthority:
        from zombie_killer_engine.memory import FileIdentity, RestoreAuthority

        try:
            identity = FileIdentity.model_validate_json(str(row["source_identity_json"]))
            return RestoreAuthority(
                restore_plan_id=str(row["restore_plan_id"]),
                restore_key=str(row["restore_key"]),
                source_id=str(row["source_id"]),
                snapshot_id=str(row["snapshot_id"]),
                snapshot_digest=str(row["snapshot_digest"]),
                expected_revision=str(row["expected_revision"]),
                source_identity=identity,
                before_hash=str(row["before_hash"]),
                target_hash=str(row["target_hash"]),
                digest=str(row["digest"]),
                status=str(row["status"]),
                phase=str(row["phase"]),
                rollback_snapshot_id=(
                    str(row["rollback_snapshot_id"])
                    if row["rollback_snapshot_id"] is not None
                    else None
                ),
                created_at=_parse_utc(str(row["created_at"])),
                expires_at=_parse_utc(str(row["expires_at"])),
            )
        except (TypeError, ValueError) as error:
            raise StoreError("memory restore authority is corrupt") from error

    def save_memory_restore_plan(self, plan: RestorePlan) -> RestoreAuthority:
        from zombie_killer_engine.memory import RestorePlan

        if not isinstance(plan, RestorePlan):
            raise TypeError("restore plan must be typed")
        identity = self._serialize_json(plan.source_identity.model_dump(mode="json"))
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT * FROM memory_restore_plans WHERE restore_key = ?",
                    (plan.restore_key,),
                ).fetchone()
                if row is not None and str(row["status"]) in {"failed", "expired"}:
                    retired_key = hashlib.sha256(
                        f"retired\0{row['restore_plan_id']}".encode()
                    ).hexdigest()
                    connection.execute(
                        "UPDATE memory_restore_plans SET restore_key=? "
                        "WHERE restore_plan_id=? AND status IN ('failed','expired')",
                        (retired_key, str(row["restore_plan_id"])),
                    )
                    row = None
                if row is None:
                    connection.execute(
                        "INSERT INTO memory_restore_plans("
                        "restore_plan_id, restore_key, source_id, snapshot_id, "
                        "snapshot_digest, expected_revision, source_identity_json, "
                        "before_hash, target_hash, digest, status, phase, created_at, "
                        "expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'planned', "
                        "'planned', ?, ?)",
                        (
                            plan.restore_plan_id,
                            plan.restore_key,
                            plan.source_id,
                            plan.snapshot_id,
                            plan.snapshot_digest,
                            plan.expected_revision,
                            identity,
                            plan.before_hash,
                            plan.target_hash,
                            plan.digest,
                            _utc_text(plan.created_at),
                            _utc_text(plan.expires_at),
                        ),
                    )
                    row = connection.execute(
                        "SELECT * FROM memory_restore_plans WHERE restore_plan_id=?",
                        (plan.restore_plan_id,),
                    ).fetchone()
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
        if row is None:
            raise StoreError("memory restore plan could not be saved")
        return self._memory_restore_from_row(row)

    def claim_memory_restore(
        self, restore_plan_id: str, *, expected_digest: str
    ) -> RestoreAuthority:
        from zombie_killer_engine.memory.base import restore_plan_digest

        validated = _IDENTIFIER_ADAPTER.validate_python(restore_plan_id)
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                now = self._clock()
                row = connection.execute(
                    "SELECT * FROM memory_restore_plans WHERE restore_plan_id = ?",
                    (validated,),
                ).fetchone()
                if row is None:
                    raise PlanClaimError("memory restore plan was not found")
                authority = self._memory_restore_from_row(row)
                plan_payload = authority.model_dump(
                    mode="python",
                    exclude={"status", "phase", "rollback_snapshot_id"},
                )
                from zombie_killer_engine.memory import RestorePlan

                typed = RestorePlan.model_validate(plan_payload)
                caller_digest_matches = secrets.compare_digest(expected_digest, authority.digest)
                persisted_digest_matches = secrets.compare_digest(
                    authority.digest, restore_plan_digest(typed)
                )
                if not caller_digest_matches or not persisted_digest_matches:
                    raise PlanClaimError("memory restore plan authority is invalid")
                if authority.status == "succeeded":
                    connection.commit()
                    return authority
                if now >= authority.expires_at:
                    connection.execute(
                        "UPDATE memory_restore_plans SET status='expired', phase='expired' "
                        "WHERE restore_plan_id = ?",
                        (validated,),
                    )
                    connection.commit()
                    raise ExpiredPlanError("memory restore plan expired")
                if authority.status != "planned":
                    raise PlanClaimError("memory restore is already claimed or interrupted")
                self._heartbeat_memory_session(connection, now)
                updated = connection.execute(
                    "UPDATE memory_restore_plans SET status='running', phase='claimed', "
                    "claim_owner=?, claim_owner_pid=?, claim_owner_create_time=?, claimed_at=? "
                    "WHERE restore_plan_id=? AND status='planned' AND digest=?",
                    (
                        self._memory_session_nonce,
                        self._owner_pid,
                        self._owner_create_time,
                        _utc_text(now),
                        validated,
                        expected_digest,
                    ),
                )
                if updated.rowcount != 1:
                    raise PlanClaimError("memory restore claim lost an atomic race")
                claimed = connection.execute(
                    "SELECT * FROM memory_restore_plans WHERE restore_plan_id=?",
                    (validated,),
                ).fetchone()
                if claimed is None:
                    raise PlanClaimError("memory restore claim could not be loaded")
                result = self._memory_restore_from_row(claimed)
                connection.commit()
            except BaseException:
                if connection.in_transaction:
                    connection.rollback()
                raise
        return result

    def update_memory_restore_phase(
        self,
        restore_plan_id: str,
        phase: str,
        *,
        rollback_snapshot_id: str | None = None,
    ) -> None:
        if phase not in {"rollback_verified", "restore_issuing", "committed"}:
            raise ValueError("memory restore phase is invalid")

        def write_phase(connection: sqlite3.Connection) -> None:
            self._heartbeat_memory_session(connection)
            updated = connection.execute(
                "UPDATE memory_restore_plans SET phase=?, "
                "rollback_snapshot_id=COALESCE(?, rollback_snapshot_id) "
                "WHERE restore_plan_id=? AND status='running' AND claim_owner=?",
                (
                    phase,
                    rollback_snapshot_id,
                    restore_plan_id,
                    self._memory_session_nonce,
                ),
            )
            if updated.rowcount != 1:
                raise PlanClaimError("memory restore phase owner did not match")

        self._memory_journal_write(write_phase)

    def fail_memory_restore(self, restore_plan_id: str, *, interrupted: bool) -> None:
        def write_failure(connection: sqlite3.Connection) -> None:
            self._heartbeat_memory_session(connection)
            updated = connection.execute(
                "UPDATE memory_restore_plans SET status=?, phase=?, claim_owner=NULL, "
                "claim_owner_pid=NULL, claim_owner_create_time=NULL "
                "WHERE restore_plan_id=? AND status='running' AND claim_owner=?",
                (
                    "interrupted" if interrupted else "failed",
                    "reconcile_required" if interrupted else "failed",
                    restore_plan_id,
                    self._memory_session_nonce,
                ),
            )
            if updated.rowcount != 1:
                raise PlanClaimError("memory restore failure owner did not match")

        self._memory_journal_write(write_failure)

    def finish_memory_restore(self, receipt: MemoryReceipt) -> None:
        if receipt.restore_plan_id is None:
            raise ValueError("restore receipt must reference its plan")

        def write_receipt(connection: sqlite3.Connection) -> None:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._heartbeat_memory_session(connection)
                rolled_back = receipt.operation == "reconciled_restore_rollback"
                updated = connection.execute(
                    "UPDATE memory_restore_plans SET status=?, phase=?, "
                    "claim_owner=NULL, claim_owner_pid=NULL, claim_owner_create_time=NULL "
                    "WHERE restore_plan_id=? AND status IN ('running','interrupted')",
                    (
                        "failed" if rolled_back else "succeeded",
                        "recovered_rolled_back" if rolled_back else "completed",
                        receipt.restore_plan_id,
                    ),
                )
                if updated.rowcount != 1:
                    raise PlanClaimError("memory restore receipt state did not match")
                connection.execute(
                    "INSERT INTO memory_receipts(receipt_id, plan_id, snapshot_id, source_id, "
                    "operation, field_names_json, before_revision, after_revision, created_at, "
                    "restore_plan_id) VALUES (?, NULL, ?, ?, ?, '[]', ?, ?, ?, ?)",
                    (
                        receipt.receipt_id,
                        receipt.snapshot_id,
                        receipt.source_id,
                        receipt.operation,
                        receipt.before_revision,
                        receipt.after_revision,
                        _utc_text(receipt.created_at),
                        receipt.restore_plan_id,
                    ),
                )
                connection.commit()
            except BaseException:
                connection.rollback()
                raise

        self._memory_journal_write(write_receipt)

    def list_memory_restore_reconciliation(self, source_id: str) -> tuple[RestoreAuthority, ...]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT * FROM memory_restore_plans WHERE source_id=? AND "
                "status='interrupted' AND phase='reconcile_required' ORDER BY created_at",
                (source_id,),
            ).fetchall()
        return tuple(self._memory_restore_from_row(row) for row in rows)

    def get_memory_restore_receipt(self, restore_plan_id: str) -> MemoryReceipt | None:
        from zombie_killer_engine.memory import MemoryReceipt

        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT * FROM memory_receipts WHERE restore_plan_id=? "
                "ORDER BY created_at DESC LIMIT 1",
                (restore_plan_id,),
            ).fetchone()
        if row is None:
            return None
        return MemoryReceipt(
            receipt_id=str(row["receipt_id"]),
            restore_plan_id=restore_plan_id,
            snapshot_id=str(row["snapshot_id"]),
            source_id=str(row["source_id"]),
            operation=str(row["operation"]),
            before_revision=str(row["before_revision"]),
            after_revision=str(row["after_revision"]),
            created_at=_parse_utc(str(row["created_at"])),
        )

    def get_memory_receipt_for_plan(self, plan_id: str) -> MemoryReceipt | None:
        from zombie_killer_engine.memory import MemoryReceipt

        validated_id = _IDENTIFIER_ADAPTER.validate_python(plan_id)
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT * FROM memory_receipts WHERE plan_id=? "
                "ORDER BY created_at DESC, receipt_id DESC LIMIT 1",
                (validated_id,),
            ).fetchone()
        if row is None:
            return None
        return MemoryReceipt(
            receipt_id=str(row["receipt_id"]),
            plan_id=validated_id,
            snapshot_id=str(row["snapshot_id"]),
            source_id=str(row["source_id"]),
            operation=str(row["operation"]),
            field_names=tuple(json.loads(str(row["field_names_json"]))),
            before_revision=str(row["before_revision"]),
            after_revision=str(row["after_revision"]),
            created_at=_parse_utc(str(row["created_at"])),
        )

    def save_memory_snapshot(self, snapshot: Snapshot) -> None:
        """Persist restricted snapshot location and immutable physical evidence."""
        from zombie_killer_engine.memory import Snapshot

        if not isinstance(snapshot, Snapshot):
            raise TypeError("snapshot must be a Snapshot")
        retention_until = snapshot.created_at + timedelta(days=30)
        backup_identity = self._serialize_json(snapshot.backup_identity.model_dump(mode="json"))
        source_identity = self._serialize_json(snapshot.source_identity.model_dump(mode="json"))
        with closing(self._connect()) as connection:
            connection.execute(
                "INSERT INTO memory_snapshots("
                "snapshot_id, source_id, source_path_binding, source_revision, digest, "
                "size, source_identity_json, backup_identity_json, backup_path, status, "
                "retention_until, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    snapshot.snapshot_id,
                    snapshot.source_id,
                    snapshot.source_path_binding,
                    snapshot.source_revision,
                    snapshot.digest,
                    snapshot.size,
                    source_identity,
                    backup_identity,
                    snapshot.backup_path,
                    snapshot.status.value,
                    _utc_text(retention_until),
                    _utc_text(snapshot.created_at),
                ),
            )

    def get_memory_snapshot(self, snapshot_id: str) -> Snapshot | None:
        from zombie_killer_engine.memory import FileIdentity, Snapshot, SnapshotStatus

        validated_id = _IDENTIFIER_ADAPTER.validate_python(snapshot_id)
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT snapshot_id, source_id, source_path_binding, source_revision, "
                "digest, size, source_identity_json, backup_identity_json, backup_path, "
                "status, memory_snapshots.created_at, source_path, format "
                "FROM memory_snapshots JOIN vault_sources USING(source_id) "
                "WHERE snapshot_id = ?",
                (validated_id,),
            ).fetchone()
            if row is not None and str(row["status"]) == "legacy_unbound":
                self._try_rebind_legacy_memory_snapshot(connection, row)
                row = connection.execute(
                    "SELECT snapshot_id, source_id, source_path_binding, source_revision, "
                    "digest, size, source_identity_json, backup_identity_json, backup_path, "
                    "status, memory_snapshots.created_at, source_path, format "
                    "FROM memory_snapshots JOIN vault_sources USING(source_id) "
                    "WHERE snapshot_id = ?",
                    (validated_id,),
                ).fetchone()
        if row is None:
            return None
        if str(row["status"]) == "legacy_unbound":
            raise StoreError("legacy memory snapshot authority is not safely bound")
        return Snapshot.model_validate(
            {
                "snapshot_id": row["snapshot_id"],
                "source_id": row["source_id"],
                "source_path_binding": row["source_path_binding"],
                "source_revision": row["source_revision"],
                "source_identity": FileIdentity.model_validate(
                    json.loads(str(row["source_identity_json"]))
                ),
                "digest": row["digest"],
                "size": row["size"],
                "backup_identity": FileIdentity.model_validate(
                    json.loads(str(row["backup_identity_json"]))
                ),
                "backup_path": row["backup_path"],
                "status": SnapshotStatus(str(row["status"])),
                "created_at": _parse_utc(str(row["created_at"])),
            }
        )

    def list_memory_snapshots(self, source_id: str, *, limit: int = 100) -> tuple[Snapshot, ...]:
        validated_id = _IDENTIFIER_ADAPTER.validate_python(source_id)
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
            raise ValueError("memory snapshot limit must be between one and five hundred")
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT snapshot_id FROM memory_snapshots WHERE source_id=? "
                "ORDER BY created_at DESC, snapshot_id DESC LIMIT ?",
                (validated_id, limit),
            ).fetchall()
        snapshots: list[Snapshot] = []
        for row in rows:
            snapshot = self.get_memory_snapshot(str(row["snapshot_id"]))
            if snapshot is not None:
                snapshots.append(snapshot)
        return tuple(snapshots)

    def _try_rebind_legacy_memory_snapshot(
        self, connection: sqlite3.Connection, row: sqlite3.Row
    ) -> None:
        """Recover only legacy JSON snapshots whose complete binding is provable."""
        from zombie_killer_engine.memory.base import (
            path_binding,
            read_pinned,
            sha256_bytes,
            source_id,
        )

        if str(row["format"]) not in {"json", "jsonl"}:
            return
        backup = Path(str(row["backup_path"]))
        source = Path(str(row["source_path"]))
        if (
            ".." in backup.parts
            or backup.parent != self._backups_dir
            or int(row["size"]) > 512 * 1024 * 1024
        ):
            return
        try:
            backup_data, backup_identity = read_pinned(backup, max_bytes=512 * 1024 * 1024)
            source_data, source_identity = read_pinned(source, max_bytes=512 * 1024 * 1024)
        except Exception:
            return
        if (
            len(backup_data) != int(row["size"])
            or sha256_bytes(backup_data) != str(row["digest"])
            or sha256_bytes(source_data) != str(row["source_revision"])
            or source_id(source) != str(row["source_id"])
            or path_binding(source) != str(row["source_path_binding"])
        ):
            return
        updated = connection.execute(
            "UPDATE memory_snapshots SET source_identity_json=?, "
            "backup_identity_json=?, status='verified' "
            "WHERE snapshot_id=? AND status='legacy_unbound' "
            "AND source_identity_json IS NULL AND backup_identity_json IS NULL",
            (
                self._serialize_json(source_identity.model_dump(mode="json")),
                self._serialize_json(backup_identity.model_dump(mode="json")),
                str(row["snapshot_id"]),
            ),
        )
        if updated.rowcount == 1:
            connection.commit()

    def save_memory_receipt(self, receipt: MemoryReceipt) -> None:
        """Persist a content-free mutation or restore receipt."""
        from zombie_killer_engine.memory import MemoryReceipt

        if not isinstance(receipt, MemoryReceipt):
            raise TypeError("receipt must be a MemoryReceipt")
        field_names = self._serialize_json(list(receipt.field_names))
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    "INSERT INTO memory_receipts("
                    "receipt_id, plan_id, snapshot_id, source_id, operation, "
                    "field_names_json, before_revision, after_revision, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        receipt.receipt_id,
                        receipt.plan_id,
                        receipt.snapshot_id,
                        receipt.source_id,
                        receipt.operation,
                        field_names,
                        receipt.before_revision,
                        receipt.after_revision,
                        _utc_text(receipt.created_at),
                    ),
                )
                connection.commit()
            except BaseException:
                connection.rollback()
                raise

    def finish_memory_plan(self, receipt: MemoryReceipt) -> None:
        if receipt.plan_id is None:
            raise ValueError("a mutation receipt must reference its plan")
        field_names = self._serialize_json(list(receipt.field_names))

        def write_receipt(connection: sqlite3.Connection) -> None:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._heartbeat_memory_session(connection)
                updated = connection.execute(
                    "UPDATE memory_mutation_plans SET status = 'succeeded', "
                    "phase = 'completed', claim_owner = NULL, claim_owner_pid = NULL, "
                    "claim_owner_create_time = NULL WHERE plan_id = ? "
                    "AND status = 'running' AND claim_owner = ? "
                    "AND snapshot_id = ?",
                    (
                        receipt.plan_id,
                        self._memory_session_nonce,
                        receipt.snapshot_id,
                    ),
                )
                if updated.rowcount != 1:
                    raise PlanClaimError(
                        "memory receipt did not match the claimed plan and snapshot"
                    )
                connection.execute(
                    "INSERT INTO memory_receipts("
                    "receipt_id, plan_id, snapshot_id, source_id, operation, "
                    "field_names_json, before_revision, after_revision, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        receipt.receipt_id,
                        receipt.plan_id,
                        receipt.snapshot_id,
                        receipt.source_id,
                        receipt.operation,
                        field_names,
                        receipt.before_revision,
                        receipt.after_revision,
                        _utc_text(receipt.created_at),
                    ),
                )
                connection.commit()
            except BaseException:
                connection.rollback()
                raise

        self._memory_journal_write(write_receipt)

    def _encode_setting(self, key: str, value: object) -> tuple[str, str]:
        cleaned_key = redact_text(key, max_length=128).strip()
        if not cleaned_key or cleaned_key != key or len(key) > 128:
            raise ValueError("setting key must be non-empty, bounded, and display-safe")
        encoded_wrapper = self._encode_json({"value": value})
        encoded = json.dumps(json.loads(encoded_wrapper)["value"], separators=(",", ":"))
        return key, encoded

    def get_settings(self) -> tuple[dict[str, object], int]:
        """Read all persisted settings and their single authoritative revision."""
        with closing(self._connect()) as connection:
            connection.execute("BEGIN")
            try:
                revision_row = connection.execute(
                    "SELECT revision FROM settings_metadata WHERE singleton = 1"
                ).fetchone()
                if revision_row is None:
                    raise StoreError("settings revision metadata is unavailable")
                rows = connection.execute(
                    "SELECT key, value_json FROM settings ORDER BY key"
                ).fetchall()
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
        return (
            {str(row["key"]): json.loads(str(row["value_json"])) for row in rows},
            int(revision_row["revision"]),
        )

    def update_settings(
        self,
        changes: Mapping[str, object],
        *,
        expected_revision: int,
        now: datetime,
    ) -> tuple[dict[str, object], int]:
        """Atomically apply every key only when the persisted revision matches."""
        if not changes:
            raise ValueError("at least one setting change is required")
        if isinstance(expected_revision, bool) or expected_revision < 0:
            raise ValueError("expected settings revision must be a non-negative integer")
        encoded_changes = [self._encode_setting(key, value) for key, value in changes.items()]
        timestamp = _utc_text(now)
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                revision_row = connection.execute(
                    "SELECT revision FROM settings_metadata WHERE singleton = 1"
                ).fetchone()
                if revision_row is None:
                    raise StoreError("settings revision metadata is unavailable")
                current_revision = int(revision_row["revision"])
                if current_revision != expected_revision:
                    raise SettingsRevisionConflict("settings revision no longer matches")
                for key, encoded in encoded_changes:
                    connection.execute(
                        "INSERT INTO settings(key, value_json, updated_at) VALUES (?, ?, ?) "
                        "ON CONFLICT(key) DO UPDATE SET "
                        "value_json = excluded.value_json, updated_at = excluded.updated_at",
                        (key, encoded, timestamp),
                    )
                next_revision = current_revision + 1
                changed = connection.execute(
                    "UPDATE settings_metadata SET revision = ? "
                    "WHERE singleton = 1 AND revision = ?",
                    (next_revision, current_revision),
                )
                if changed.rowcount != 1:
                    raise SettingsRevisionConflict("settings revision no longer matches")
                rows = connection.execute(
                    "SELECT key, value_json FROM settings ORDER BY key"
                ).fetchall()
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
        return (
            {str(row["key"]): json.loads(str(row["value_json"])) for row in rows},
            next_revision,
        )

    def set_setting(self, key: str, value: object, *, now: datetime) -> None:
        """Compatibility helper for internal callers; retry through persisted CAS."""
        for _attempt in range(3):
            _settings, revision = self.get_settings()
            try:
                self.update_settings({key: value}, expected_revision=revision, now=now)
                return
            except SettingsRevisionConflict:
                continue
        raise SettingsRevisionConflict("settings revision no longer matches")

    def get_setting(self, key: str) -> object | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT value_json FROM settings WHERE key = ?", (key,)
            ).fetchone()
        return None if row is None else json.loads(str(row[0]))

    def record_audit_event(
        self,
        *,
        correlation_id: str,
        event_type: str,
        details: AuditEventDetails | Mapping[str, object],
        now: datetime,
    ) -> str:
        import secrets

        event_id = secrets.token_urlsafe(24)
        validated_correlation = _IDENTIFIER_ADAPTER.validate_python(
            correlation_id,
            strict=True,
        )
        validated_details = (
            details
            if isinstance(details, AuditEventDetails)
            else AuditEventDetails.model_validate(details)
        )
        envelope = _AuditEventEnvelope(
            event_id=event_id,
            correlation_id=hashlib.sha256(
                f"correlation\0{validated_correlation}".encode()
            ).hexdigest(),
            event_type=redact_text(event_type, max_length=128).strip() or "[REDACTED]",
            details=validated_details,
            created_at=now,
        )
        encoded = self._encode_canonical_model(envelope.details)
        with closing(self._connect()) as connection:
            connection.execute(
                "INSERT INTO audit_events("
                "event_id, correlation_id, event_type, details_json, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    envelope.event_id,
                    envelope.correlation_id,
                    envelope.event_type,
                    encoded,
                    _utc_text(envelope.created_at),
                ),
            )
        return envelope.event_id

    def get_audit_event(self, event_id: str) -> dict[str, object]:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT event_id, correlation_id, event_type, details_json, created_at "
                "FROM audit_events WHERE event_id = ?",
                (event_id,),
            ).fetchone()
        if row is None:
            raise StoreError("audit event was not found")
        return {
            "event_id": str(row["event_id"]),
            "correlation_id": str(row["correlation_id"]),
            "event_type": str(row["event_type"]),
            "details": json.loads(str(row["details_json"])),
            "created_at": str(row["created_at"]),
        }
