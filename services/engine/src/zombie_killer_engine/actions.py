"""Immutable remediation plans and PID-safe action execution boundaries."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import math
import os
import platform
import secrets
import select
import signal
import time
from ctypes import wintypes
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Literal, Protocol, Self

import psutil  # type: ignore[import-untyped]
from pydantic import Field, StringConstraints, field_validator, model_validator

from zombie_killer_engine.identity import normalized_identity_fingerprint
from zombie_killer_engine.leases import (
    CANCELLATION_REQUEST_LIFETIME_SECONDS,
    CancellationNotPublishedError,
    CancellationPublicationUncertainError,
    cancellation_request_path,
    cancellation_user_fingerprint,
    write_cancellation_request,
)
from zombie_killer_engine.models import (
    AgentState,
    DisplayText,
    DomainModel,
    IdentifierText,
    ProcessIdentity,
    UtcDatetime,
)
from zombie_killer_engine.paths import AppPaths
from zombie_killer_engine.redaction import redact_text
from zombie_killer_engine.scanner import ScannedAgent, current_boot_id, is_current_user

if TYPE_CHECKING:
    from collections.abc import Callable

    from zombie_killer_engine.store import SQLiteStateStore

_DEFAULT_PLAN_LIFETIME = timedelta(seconds=30)
_SIGTERM = 15
_SIGKILL = 9

StableBindingKind = Literal["windows_handle", "pidfd", "unsupported"]


class ActionMode(StrEnum):
    REQUEST_STOP = "request_stop"
    TERMINATE = "terminate"
    FORCE = "force"


class PlanStatus(StrEnum):
    PLANNED = "planned"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    PARTIAL = "partial"
    EXPIRED = "expired"
    INTERRUPTED = "interrupted"


class ActionResult(StrEnum):
    REQUESTED = "requested"
    PENDING = "pending"
    COMPLETED = "completed"
    DISAPPEARED = "disappeared"
    ACCESS_DENIED = "access_denied"
    IDENTITY_MISMATCH = "identity_mismatch"
    INTERRUPTED = "interrupted"
    FAILED = "failed"


class PlanRejectedError(ValueError):
    """The candidate does not meet fail-closed action-planning policy."""


class ProcessControlError(RuntimeError):
    def __init__(self, pid: int) -> None:
        super().__init__(f"process {pid} could not be controlled")
        self.pid = pid


class ProcessActionNotIssued(ProcessControlError):
    """Controller failure contractually guaranteeing no process-side effect."""


class ProcessDisappeared(ProcessActionNotIssued):
    pass


class ProcessAccessDenied(ProcessActionNotIssued):
    pass


class ProcessIdentityMismatch(ProcessActionNotIssued):
    pass


class StableBindingUnavailable(ProcessActionNotIssued):
    pass


class StableProcessReference(Protocol):
    """One kernel-bound process reference retained through verification."""

    def validate(self, identity: ProcessIdentity) -> None: ...

    def is_running(self) -> bool: ...

    def close(self) -> None: ...


class ProcessController(Protocol):
    """Narrow injectable boundary for process identity and signaling."""

    @property
    def stable_binding_kind(self) -> StableBindingKind: ...

    def current_boot_id(self) -> str: ...

    def current_user_hash(self) -> str: ...

    def read_identity(self, pid: int) -> ProcessIdentity: ...

    def bind(self, identity: ProcessIdentity) -> StableProcessReference: ...

    def terminate(self, identity: ProcessIdentity) -> StableProcessReference: ...

    def kill(self, identity: ProcessIdentity) -> StableProcessReference: ...


def _read_psutil_identity(
    pid: int,
    *,
    boot_id: str,
    platform_name: str,
) -> ProcessIdentity:
    process = psutil.Process(pid)
    executable = process.exe()
    user = process.username()
    return ProcessIdentity(
        boot_id=boot_id,
        pid=pid,
        create_time=float(process.create_time()),
        executable=executable,
        user=user,
        executable_hash=normalized_identity_fingerprint(
            executable,
            platform_name=platform_name,
        ),
        user_hash=cancellation_user_fingerprint(
            pid,
            user,
            platform_name=platform_name,
        ),
    )


class PsutilProcessController:
    """Production controller; it never accepts shell command strings."""

    def __init__(self, *, platform_name: str | None = None) -> None:
        self._platform_name = platform_name or platform.system()

    @property
    def stable_binding_kind(self) -> StableBindingKind:
        system = self._platform_name.casefold()
        if system.startswith("win") and os.name == "nt":
            return "windows_handle"
        if (
            system.startswith("linux")
            and os.name == "posix"
            and callable(getattr(os, "pidfd_open", None))
            and callable(getattr(signal, "pidfd_send_signal", None))
        ):
            return "pidfd"
        return "unsupported"

    def current_boot_id(self) -> str:
        return current_boot_id(platform_name=self._platform_name)

    def current_user_hash(self) -> str:
        current = psutil.Process()
        return cancellation_user_fingerprint(
            os.getpid(),
            current.username(),
            platform_name=self._platform_name,
        )

    def read_identity(self, pid: int) -> ProcessIdentity:
        try:
            return _read_psutil_identity(
                pid,
                boot_id=self.current_boot_id(),
                platform_name=self._platform_name,
            )
        except (psutil.NoSuchProcess, psutil.ZombieProcess) as error:
            raise ProcessDisappeared(pid) from error
        except psutil.AccessDenied as error:
            raise ProcessAccessDenied(pid) from error
        except (OSError, ValueError) as error:
            raise ProcessAccessDenied(pid) from error

    def terminate(self, identity: ProcessIdentity) -> StableProcessReference:
        return self._signal_stable(identity, _SIGTERM)

    def kill(self, identity: ProcessIdentity) -> StableProcessReference:
        return self._signal_stable(identity, _SIGKILL)

    def bind(self, identity: ProcessIdentity) -> StableProcessReference:
        if self.stable_binding_kind == "windows_handle":
            return _open_windows_process(identity, self.current_boot_id())
        if self.stable_binding_kind == "pidfd":
            return _open_pidfd_process(
                identity,
                current_boot_id=self.current_boot_id(),
                platform_name=self._platform_name,
            )
        raise StableBindingUnavailable(identity.pid)

    def _signal_stable(
        self,
        identity: ProcessIdentity,
        selected_signal: int,
    ) -> StableProcessReference:
        if self.stable_binding_kind == "windows_handle":
            windows_reference = _open_windows_process(
                identity,
                self.current_boot_id(),
            )
            try:
                windows_reference.terminate()
                return windows_reference
            except BaseException:
                windows_reference.close()
                raise
        if self.stable_binding_kind == "pidfd":
            pidfd_reference = _open_pidfd_process(
                identity,
                current_boot_id=self.current_boot_id(),
                platform_name=self._platform_name,
            )
            try:
                sender = signal.pidfd_send_signal  # type: ignore[attr-defined]
                sender(pidfd_reference.file_descriptor, selected_signal, None, 0)
                return pidfd_reference
            except ProcessLookupError as error:
                pidfd_reference.close()
                raise ProcessDisappeared(identity.pid) from error
            except PermissionError as error:
                pidfd_reference.close()
                raise ProcessAccessDenied(identity.pid) from error
            except BaseException:
                pidfd_reference.close()
                raise
        raise StableBindingUnavailable(identity.pid)


class _FileTime(ctypes.Structure):
    _fields_ = (("low", wintypes.DWORD), ("high", wintypes.DWORD))


class _SidAndAttributes(ctypes.Structure):
    _fields_ = (("sid", ctypes.c_void_p), ("attributes", wintypes.DWORD))


class _TokenUser(ctypes.Structure):
    _fields_ = (("user", _SidAndAttributes),)


class _WindowsProcessReference:
    _WAIT_OBJECT_0 = 0
    _WAIT_TIMEOUT = 0x102

    def __init__(
        self,
        kernel32: Any,
        advapi32: Any,
        handle: int,
        pid: int,
        current_boot_id: str,
    ) -> None:
        self._kernel32 = kernel32
        self._advapi32 = advapi32
        self._handle = handle
        self._pid = pid
        self._current_boot_id = current_boot_id
        self._closed = False

    def validate(self, identity: ProcessIdentity) -> None:
        if self._closed or identity.pid != self._pid or not self.is_running():
            raise ProcessIdentityMismatch(identity.pid)
        creation_time = _windows_process_creation_time(self._kernel32, self._handle)
        executable = _windows_process_executable(self._kernel32, self._handle)
        process_sid = _windows_token_sid(
            self._advapi32,
            self._kernel32,
            self._handle,
        )
        current_process = int(self._kernel32.GetCurrentProcess())
        current_sid = _windows_token_sid(
            self._advapi32,
            self._kernel32,
            current_process,
        )
        if (
            identity.boot_id != self._current_boot_id
            or not math.isclose(
                creation_time,
                identity.create_time,
                rel_tol=0.0,
                abs_tol=0.000001,
            )
            or identity.executable_hash is None
            or not secrets.compare_digest(
                identity.executable_hash,
                _executable_hash(executable, platform_name="windows"),
            )
            or identity.user_hash is None
            or not process_sid
            or process_sid != current_sid
            or not secrets.compare_digest(identity.user_hash, _hash_text(process_sid))
            or not self.is_running()
        ):
            raise ProcessIdentityMismatch(identity.pid)

    def terminate(self) -> None:
        terminate = self._kernel32.TerminateProcess
        if not terminate(ctypes.c_void_p(self._handle), 1):
            error = ctypes.get_last_error()
            if error == 5:
                raise ProcessAccessDenied(self._pid)
            if error == 87:
                raise ProcessDisappeared(self._pid)
            raise OSError(error, "TerminateProcess failed")

    def is_running(self) -> bool:
        if self._closed:
            return False
        wait = self._kernel32.WaitForSingleObject
        result = int(wait(ctypes.c_void_p(self._handle), 0))
        if result == self._WAIT_TIMEOUT:
            return True
        if result == self._WAIT_OBJECT_0:
            return False
        raise OSError(ctypes.get_last_error(), "WaitForSingleObject failed")

    def close(self) -> None:
        if not self._closed:
            close_handle = self._kernel32.CloseHandle
            close_handle(ctypes.c_void_p(self._handle))
            self._closed = True


class _PidfdProcessReference:
    def __init__(
        self,
        file_descriptor: int,
        *,
        current_boot_id: str,
        platform_name: str,
    ) -> None:
        self.file_descriptor = file_descriptor
        self._current_boot_id = current_boot_id
        self._platform_name = platform_name
        self._closed = False

    def validate(self, identity: ProcessIdentity) -> None:
        if self._closed or not self.is_running():
            raise ProcessDisappeared(identity.pid)
        try:
            observed = _read_psutil_identity(
                identity.pid,
                boot_id=self._current_boot_id,
                platform_name=self._platform_name,
            )
        except (psutil.NoSuchProcess, psutil.ZombieProcess) as error:
            raise ProcessDisappeared(identity.pid) from error
        except psutil.AccessDenied as error:
            raise ProcessAccessDenied(identity.pid) from error
        except (OSError, ValueError) as error:
            raise ProcessAccessDenied(identity.pid) from error
        if (
            not same_process_instance(
                identity,
                observed,
                current_boot_id=self._current_boot_id,
                platform_name=self._platform_name,
            )
            or not self.is_running()
        ):
            raise ProcessIdentityMismatch(identity.pid)

    def is_running(self) -> bool:
        if self._closed:
            return False
        readable, _, _ = select.select([self.file_descriptor], [], [], 0)
        return not readable

    def close(self) -> None:
        if not self._closed:
            os.close(self.file_descriptor)
            self._closed = True


def _windows_token_sid(
    advapi32: Any,
    kernel32: Any,
    process_handle: int,
) -> str:
    open_token = advapi32.OpenProcessToken
    token_handle = ctypes.c_void_p()
    if not open_token(
        ctypes.c_void_p(process_handle),
        0x0008,
        ctypes.byref(token_handle),
    ):
        raise OSError(ctypes.get_last_error(), "OpenProcessToken failed")
    try:
        get_information = advapi32.GetTokenInformation
        required = wintypes.DWORD()
        get_information(token_handle, 1, None, 0, ctypes.byref(required))
        if required.value == 0:
            raise OSError(ctypes.get_last_error(), "GetTokenInformation size failed")
        token_buffer = ctypes.create_string_buffer(required.value)
        if not get_information(
            token_handle,
            1,
            token_buffer,
            required.value,
            ctypes.byref(required),
        ):
            raise OSError(ctypes.get_last_error(), "GetTokenInformation failed")
        token_user = ctypes.cast(token_buffer, ctypes.POINTER(_TokenUser)).contents
        rendered = ctypes.c_wchar_p()
        convert = advapi32.ConvertSidToStringSidW
        if not convert(token_user.user.sid, ctypes.byref(rendered)):
            raise OSError(ctypes.get_last_error(), "SID conversion failed")
        try:
            return rendered.value or ""
        finally:
            local_free = kernel32.LocalFree
            local_free(rendered)
    finally:
        close_handle = kernel32.CloseHandle
        close_handle(token_handle)


def _windows_process_creation_time(kernel32: Any, handle: int) -> float:
    creation = _FileTime()
    exit_time = _FileTime()
    kernel_time = _FileTime()
    user_time = _FileTime()
    get_times = kernel32.GetProcessTimes
    if not get_times(
        ctypes.c_void_p(handle),
        ctypes.byref(creation),
        ctypes.byref(exit_time),
        ctypes.byref(kernel_time),
        ctypes.byref(user_time),
    ):
        raise OSError(ctypes.get_last_error(), "GetProcessTimes failed")
    intervals = (creation.high << 32) | creation.low
    return float(intervals / 10_000_000 - 11_644_473_600)


def _windows_process_executable(kernel32: Any, handle: int) -> str:
    query_name = kernel32.QueryFullProcessImageNameW
    capacity = 32_768
    buffer = ctypes.create_unicode_buffer(capacity)
    length = wintypes.DWORD(capacity)
    if not query_name(
        ctypes.c_void_p(handle),
        0,
        buffer,
        ctypes.byref(length),
    ):
        raise OSError(ctypes.get_last_error(), "QueryFullProcessImageNameW failed")
    return buffer.value


def _open_windows_process(
    identity: ProcessIdentity,
    current_boot_id: str,
) -> _WindowsProcessReference:
    if os.name != "nt":
        raise StableBindingUnavailable(identity.pid)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    open_process = kernel32.OpenProcess
    open_process.restype = ctypes.c_void_p
    access = 0x0001 | 0x1000 | 0x00100000
    handle_value = open_process(access, False, identity.pid)
    if not handle_value:
        error = ctypes.get_last_error()
        if error == 5:
            raise ProcessAccessDenied(identity.pid)
        if error == 87:
            raise ProcessDisappeared(identity.pid)
        raise OSError(error, "OpenProcess failed")
    handle = int(handle_value)
    reference = _WindowsProcessReference(
        kernel32,
        advapi32,
        handle,
        identity.pid,
        current_boot_id,
    )
    try:
        reference.validate(identity)
        return reference
    except BaseException:
        reference.close()
        raise


def _open_pidfd_process(
    identity: ProcessIdentity,
    *,
    current_boot_id: str,
    platform_name: str,
) -> _PidfdProcessReference:
    opener = getattr(os, "pidfd_open", None)
    if not callable(opener):
        raise StableBindingUnavailable(identity.pid)
    try:
        descriptor = opener(identity.pid, 0)
    except ProcessLookupError as error:
        raise ProcessDisappeared(identity.pid) from error
    except PermissionError as error:
        raise ProcessAccessDenied(identity.pid) from error
    except OSError as error:
        if error.errno == errno.ESRCH:
            raise ProcessDisappeared(identity.pid) from error
        if error.errno in {errno.EACCES, errno.EPERM}:
            raise ProcessAccessDenied(identity.pid) from error
        raise StableBindingUnavailable(identity.pid) from error
    reference = _PidfdProcessReference(
        descriptor,
        current_boot_id=current_boot_id,
        platform_name=platform_name,
    )
    try:
        reference.validate(identity)
        return reference
    except BaseException:
        reference.close()
        raise


DigestText = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


def _new_id() -> str:
    return secrets.token_urlsafe(24)


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="strict")).hexdigest()


def process_instance_id(identity: ProcessIdentity) -> str:
    """Return an opaque binding for one PID/create-time instance on one boot."""
    payload = json.dumps(
        [
            "zombie-killer-process-instance-v1",
            identity.boot_id,
            identity.pid,
            identity.create_time.hex(),
        ],
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
    )
    return _hash_text(payload)


def _opaque_audit_identifier(kind: str, value: object) -> str:
    text = str(value)
    prefix = f"{kind}-"
    suffix = text.removeprefix(prefix)
    if (
        text.startswith(prefix)
        and len(suffix) == 64
        and all(character in "0123456789abcdef" for character in suffix)
    ):
        return text
    return prefix + _hash_text(f"{kind}\0{text}")


def _executable_hash(value: str, *, platform_name: str) -> str:
    return normalized_identity_fingerprint(value, platform_name=platform_name)


def _user_hash(value: str, *, platform_name: str) -> str:
    return normalized_identity_fingerprint(value, platform_name=platform_name)


def _display_executable(value: str) -> str:
    basename = value.replace("\\", "/").rsplit("/", 1)[-1]
    cleaned = redact_text(basename, max_length=256) or "process"
    return f"[REDACTED]/{cleaned}"


def _action_identity(
    identity: ProcessIdentity,
    *,
    platform_name: str,
) -> ProcessIdentity:
    if identity.executable is None or identity.user is None:
        raise ValueError("action identity requires executable and user")
    executable_hash = identity.executable_hash or _executable_hash(
        identity.executable,
        platform_name=platform_name,
    )
    user_hash = identity.user_hash or cancellation_user_fingerprint(
        identity.pid,
        identity.user,
        platform_name=platform_name,
    )
    return ProcessIdentity(
        boot_id=identity.boot_id,
        pid=identity.pid,
        create_time=identity.create_time,
        executable=_display_executable(identity.executable),
        user="[CURRENT USER]",
        executable_hash=executable_hash,
        user_hash=user_hash,
    )


def _canonical_plan_payload(values: dict[str, Any]) -> bytes:
    immutable = {key: value for key, value in values.items() if key not in {"digest", "status"}}
    return json.dumps(
        immutable,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
        default=lambda value: value.isoformat() if isinstance(value, datetime) else str(value),
    ).encode("utf-8")


class ActionPlan(DomainModel):
    """A short-lived, tamper-evident authorization for one exact process."""

    plan_id: IdentifierText
    correlation_id: IdentifierText
    identity: ProcessIdentity
    mode: ActionMode
    agent_id: IdentifierText | None = None
    registration_nonce: IdentifierText | None = None
    managed: bool
    child_resource_ids: tuple[IdentifierText, ...] = Field(default=(), max_length=128)
    warnings: tuple[DisplayText, ...] = Field(default=(), max_length=64)
    consequences: tuple[DisplayText, ...] = Field(min_length=1, max_length=64)
    created_at: UtcDatetime
    expires_at: UtcDatetime
    status: PlanStatus = PlanStatus.PLANNED
    digest: DigestText

    @model_validator(mode="after")
    def validate_lifetime_and_digest(self) -> Self:
        lifetime = self.expires_at - self.created_at
        if lifetime != _DEFAULT_PLAN_LIFETIME:
            raise ValueError("plan lifetime must be exactly thirty seconds")
        if self.child_resource_ids:
            raise ValueError("v0.1 plans do not support descendant or resource actions")
        if self.identity.executable_hash is None or self.identity.user_hash is None:
            raise ValueError("action plan identity requires stable executable and user hashes")
        if self.mode is ActionMode.REQUEST_STOP and (
            not self.managed or self.agent_id is None or self.registration_nonce is None
        ):
            raise ValueError("cooperative stop requires a bound managed lease registration")
        if not self.verify_digest():
            raise ValueError("action plan digest does not match immutable fields")
        return self

    def verify_digest(self) -> bool:
        values = self.model_dump(mode="json")
        expected = hashlib.sha256(_canonical_plan_payload(values)).hexdigest()
        return secrets.compare_digest(self.digest, expected)

    @classmethod
    def create(
        cls,
        *,
        identity: ProcessIdentity,
        mode: ActionMode,
        managed: bool,
        consequences: tuple[str, ...],
        agent_id: str | None = None,
        registration_nonce: str | None = None,
        warnings: tuple[str, ...] = (),
        child_resource_ids: tuple[str, ...] = (),
        created_at: datetime | None = None,
        plan_id: str | None = None,
        correlation_id: str | None = None,
        platform_name: str | None = None,
    ) -> ActionPlan:
        created = created_at or datetime.now(UTC)
        expiry = created + _DEFAULT_PLAN_LIFETIME
        if created.tzinfo is None or created.utcoffset() is None:
            raise ValueError("created_at must be timezone-aware")
        if expiry.tzinfo is None or expiry.utcoffset() is None:
            raise ValueError("expires_at must be timezone-aware")
        stored_identity = _action_identity(
            identity,
            platform_name=platform_name or platform.system(),
        )
        sanitized_warnings = tuple(redact_text(item, max_length=2048) for item in warnings)
        sanitized_consequences = tuple(redact_text(item, max_length=2048) for item in consequences)
        selected_plan_id = plan_id or _new_id()
        selected_correlation_id = correlation_id or _new_id()
        unsigned = cls.model_construct(
            plan_id=selected_plan_id,
            correlation_id=selected_correlation_id,
            identity=stored_identity,
            mode=mode,
            agent_id=agent_id,
            registration_nonce=registration_nonce,
            managed=managed,
            child_resource_ids=child_resource_ids,
            warnings=sanitized_warnings,
            consequences=sanitized_consequences,
            created_at=created.astimezone(UTC),
            expires_at=expiry.astimezone(UTC),
            status=PlanStatus.PLANNED,
            digest="0" * 64,
        )
        digest = hashlib.sha256(
            _canonical_plan_payload(unsigned.model_dump(mode="json"))
        ).hexdigest()
        return cls(
            plan_id=selected_plan_id,
            correlation_id=selected_correlation_id,
            identity=stored_identity,
            mode=mode,
            agent_id=agent_id,
            registration_nonce=registration_nonce,
            managed=managed,
            child_resource_ids=child_resource_ids,
            warnings=sanitized_warnings,
            consequences=sanitized_consequences,
            created_at=created,
            expires_at=expiry,
            status=PlanStatus.PLANNED,
            digest=digest,
        )


class ActionReceipt(DomainModel):
    """Bounded audit receipt for one claimed remediation plan."""

    receipt_id: IdentifierText
    correlation_id: IdentifierText
    plan_id: IdentifierText
    actor: IdentifierText
    session_id: IdentifierText
    action: ActionMode
    target: ProcessIdentity
    before: DisplayText
    after: DisplayText
    result: ActionResult
    action_issued: bool | None = False
    started_at: UtcDatetime
    finished_at: UtcDatetime
    partial_failures: tuple[DisplayText, ...] = Field(default=(), max_length=64)
    restore_reference: IdentifierText | None = None

    @field_validator("actor", mode="before")
    @classmethod
    def _opaque_actor(cls, value: object) -> str:
        return _opaque_audit_identifier("actor", value)

    @field_validator("session_id", mode="before")
    @classmethod
    def _opaque_session(cls, value: object) -> str:
        return _opaque_audit_identifier("session", value)

    @field_validator("before", "after", mode="before")
    @classmethod
    def _sanitize_state_text(cls, value: object) -> str:
        return redact_text(value, max_length=2048).strip() or "[REDACTED]"

    @field_validator("partial_failures", mode="before")
    @classmethod
    def _sanitize_failures(cls, values: object) -> object:
        if not isinstance(values, (tuple, list)):
            return values
        return tuple(
            redact_text(value, max_length=2048).strip() or "[REDACTED]" for value in values
        )

    @field_validator("restore_reference", mode="before")
    @classmethod
    def _sanitize_restore_reference(cls, value: object | None) -> str | None:
        if value is None:
            return None
        return redact_text(value, max_length=256).strip() or None

    @model_validator(mode="after")
    def timestamps_are_ordered(self) -> Self:
        if self.finished_at < self.started_at:
            raise ValueError("receipt finish time cannot precede start time")
        return self

    @classmethod
    def create(
        cls,
        *,
        plan: ActionPlan,
        actor: str,
        session_id: str,
        result: ActionResult,
        action_issued: bool | None = False,
        before: str,
        after: str,
        started_at: datetime,
        finished_at: datetime,
        partial_failures: tuple[str, ...] = (),
        restore_reference: str | None = None,
    ) -> ActionReceipt:
        return cls(
            receipt_id=_new_id(),
            correlation_id=plan.correlation_id,
            plan_id=plan.plan_id,
            actor=actor,
            session_id=session_id,
            action=plan.mode,
            target=plan.identity,
            before=before,
            after=after,
            result=result,
            action_issued=action_issued,
            started_at=started_at,
            finished_at=finished_at,
            partial_failures=partial_failures,
            restore_reference=restore_reference,
        )


def same_process_instance(
    expected: ProcessIdentity,
    observed: ProcessIdentity,
    *,
    current_boot_id: str,
    platform_name: str | None = None,
) -> bool:
    """Compare every identity field required for action authority."""
    if observed.executable is None or observed.user is None:
        return False
    if (
        expected.boot_id,
        expected.pid,
        expected.create_time,
    ) != (
        observed.boot_id,
        observed.pid,
        observed.create_time,
    ) or expected.boot_id != current_boot_id:
        return False
    system = platform_name or platform.system()
    if expected.executable_hash is not None or expected.user_hash is not None:
        if expected.executable_hash is None or expected.user_hash is None:
            return False
        observed_executable_hash = observed.executable_hash or _executable_hash(
            observed.executable,
            platform_name=system,
        )
        observed_user_hash = observed.user_hash or _user_hash(
            observed.user,
            platform_name=system,
        )
        return secrets.compare_digest(
            expected.executable_hash,
            observed_executable_hash,
        ) and secrets.compare_digest(expected.user_hash, observed_user_hash)
    if expected.executable is None or expected.user is None:
        return False
    if system.casefold().startswith("win"):
        executable_matches = expected.executable.casefold() == observed.executable.casefold()
    else:
        executable_matches = expected.executable == observed.executable
    return executable_matches and is_current_user(
        observed.user,
        expected.user,
        platform_name=system,
    )


class ActionPlanner:
    """Convert one conservative scan result into a short-lived confirmation plan."""

    _REJECTED_STATES = {
        AgentState.UNKNOWN,
        AgentState.DEFUNCT,
        AgentState.COMPLETED,
        AgentState.FAILED,
        AgentState.CANCELLED,
    }

    def __init__(
        self,
        controller: ProcessController,
        *,
        current_user: str,
        current_pid: int | None = None,
        parent_pid: int | None = None,
        protected_identities: tuple[ProcessIdentity, ...] = (),
        platform_name: str | None = None,
    ) -> None:
        if not current_user.strip() or len(current_user) > 256:
            raise ValueError("current_user must be non-empty and bounded")
        self._controller = controller
        self._current_user = current_user
        self._current_pid = os.getpid() if current_pid is None else current_pid
        self._parent_pid = os.getppid() if parent_pid is None else parent_pid
        self._protected_identities = protected_identities
        self._platform_name = platform_name or platform.system()

    def create_plan(
        self,
        candidate: ScannedAgent,
        *,
        mode: ActionMode,
        allow_unmanaged: bool = False,
        now: datetime | None = None,
    ) -> ActionPlan:
        created_at = now or datetime.now(UTC)
        if created_at.tzinfo is None or created_at.utcoffset() is None:
            raise ValueError("now must be timezone-aware")
        if candidate.classification.state in self._REJECTED_STATES:
            raise PlanRejectedError("terminal, defunct, or unknown records cannot be planned")
        managed = candidate.lease_matched and candidate.agent_id is not None
        unmanaged = candidate.classification.state is AgentState.UNMANAGED and not managed
        if unmanaged:
            if not allow_unmanaged:
                raise PlanRejectedError("unmanaged process policy is not enabled")
            if mode is ActionMode.REQUEST_STOP:
                raise PlanRejectedError("unmanaged processes have no cooperative stop authority")
        elif not managed or not candidate.actionable:
            raise PlanRejectedError("managed record is not actionable")
        if candidate.process is None or candidate.process.identity is None:
            raise PlanRejectedError("process identity is incomplete")
        target = candidate.process.identity
        if target.executable is None or target.user is None:
            raise PlanRejectedError("process identity requires executable and user")
        if target.pid <= 4:
            raise PlanRejectedError("kernel and system process IDs are protected")
        if target.pid in {self._current_pid, self._parent_pid}:
            raise PlanRejectedError("current and parent application processes are protected")
        if not is_current_user(
            target.user,
            self._current_user,
            platform_name=self._platform_name,
        ):
            raise PlanRejectedError("target user is not the exact current user")
        current_boot = self._controller.current_boot_id()
        if target.boot_id != current_boot:
            raise PlanRejectedError("target process belongs to a different boot")
        for protected in self._protected_identities:
            if same_process_instance(
                protected,
                target,
                current_boot_id=current_boot,
                platform_name=self._platform_name,
            ):
                raise PlanRejectedError("target is a protected Zombie Killer process")
        try:
            observed = self._controller.read_identity(target.pid)
        except ProcessDisappeared as error:
            raise PlanRejectedError("target process disappeared before planning") from error
        except ProcessAccessDenied as error:
            raise PlanRejectedError("target process identity could not be read") from error
        if not same_process_instance(
            target,
            observed,
            current_boot_id=current_boot,
            platform_name=self._platform_name,
        ):
            raise PlanRejectedError("target process identity was reused or changed")

        warnings: tuple[str, ...] = ()
        if unmanaged:
            warnings = (
                "This unmanaged process has no Zombie Killer cleanup or restoration authority.",
            )
        if mode is ActionMode.REQUEST_STOP:
            if candidate.registration_nonce is None:
                raise PlanRejectedError("managed lease lacks a cancellation registration nonce")
            consequences = (
                "A cooperative SDK cancellation request will be written; it will not escalate.",
            )
        elif mode is ActionMode.TERMINATE:
            consequences = (
                "Windows uses a forceful OS terminate, not a graceful shutdown."
                if self._platform_name.casefold().startswith("win")
                else "The exact process instance will receive the platform terminate operation.",
            )
        else:
            consequences = (
                "The exact process instance will receive a separately confirmed force kill.",
            )
        return ActionPlan.create(
            identity=observed,
            mode=mode,
            agent_id=candidate.agent_id if managed else None,
            registration_nonce=(candidate.registration_nonce if managed else None),
            managed=managed,
            warnings=warnings,
            consequences=consequences,
            created_at=created_at,
            platform_name=self._platform_name,
        )


def cancellation_path(paths: AppPaths, agent_id: str) -> Path:
    """Map an agent identifier to a traversal-safe cooperative cancellation file."""
    return cancellation_request_path(paths.cancellations_dir, agent_id)


class ActionExecutor:
    """Atomically claim, revalidate, execute, verify, and receipt one plan."""

    def __init__(
        self,
        store: SQLiteStateStore,
        controller: ProcessController,
        paths: AppPaths,
        *,
        actor: str,
        platform_name: str | None = None,
        current_pid: int | None = None,
        parent_pid: int | None = None,
        protected_identities: tuple[ProcessIdentity, ...] = (),
        now: Callable[[], datetime] | None = None,
        monotonic: Callable[[], float] | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        if not actor.strip():
            raise ValueError("actor must be non-empty")
        self._store = store
        self._controller = controller
        self._paths = paths
        self._actor = actor
        self._session_id = store.session_id
        self._platform_name = platform_name or platform.system()
        self._current_pid = os.getpid() if current_pid is None else current_pid
        self._parent_pid = os.getppid() if parent_pid is None else parent_pid
        self._protected_identities = protected_identities
        self._now = now or (lambda: datetime.now(UTC))
        self._monotonic = monotonic or time.monotonic
        self._sleep = sleep or time.sleep

    def _revalidate(self, plan: ActionPlan) -> None:
        if plan.identity.pid <= 4 or plan.identity.pid in {
            self._current_pid,
            self._parent_pid,
        }:
            raise ProcessIdentityMismatch(plan.identity.pid)
        current_boot = self._controller.current_boot_id()
        if current_boot != plan.identity.boot_id:
            raise ProcessIdentityMismatch(plan.identity.pid)
        if plan.identity.user_hash is None or not secrets.compare_digest(
            plan.identity.user_hash,
            self._controller.current_user_hash(),
        ):
            raise ProcessIdentityMismatch(plan.identity.pid)
        if any(
            same_process_instance(
                _action_identity(
                    protected,
                    platform_name=self._platform_name,
                ),
                plan.identity,
                current_boot_id=current_boot,
                platform_name=self._platform_name,
            )
            for protected in self._protected_identities
        ):
            raise ProcessIdentityMismatch(plan.identity.pid)
        observed = self._controller.read_identity(plan.identity.pid)
        if not same_process_instance(
            plan.identity,
            observed,
            current_boot_id=current_boot,
            platform_name=self._platform_name,
        ):
            raise ProcessIdentityMismatch(plan.identity.pid)

    def _write_cancellation(
        self,
        plan: ActionPlan,
        requested_at: datetime,
        reference: StableProcessReference,
    ) -> None:
        if plan.agent_id is None or plan.registration_nonce is None or not plan.managed:
            raise ValueError("cooperative stop requires a managed agent")
        write_cancellation_request(
            self._paths.cancellations_dir,
            plan.agent_id,
            target_identity=plan.identity,
            registration_nonce=plan.registration_nonce,
            plan_id=plan.plan_id,
            requested_at=requested_at,
            expires_at=requested_at + timedelta(seconds=CANCELLATION_REQUEST_LIFETIME_SECONDS),
            publication_guard=lambda: reference.validate(plan.identity),
        )

    def _original_is_running(self, plan: ActionPlan) -> bool:
        try:
            current_boot = self._controller.current_boot_id()
            observed = self._controller.read_identity(plan.identity.pid)
        except ProcessDisappeared:
            return False
        if current_boot != plan.identity.boot_id:
            return False
        return same_process_instance(
            plan.identity,
            observed,
            current_boot_id=current_boot,
            platform_name=self._platform_name,
        )

    def _wait_for_exit(
        self,
        plan: ActionPlan,
        *,
        reference: StableProcessReference | None,
        grace_period_seconds: float,
        poll_interval_seconds: float,
    ) -> bool:
        deadline = self._monotonic() + grace_period_seconds
        while True:
            running = (
                reference.is_running() if reference is not None else self._original_is_running(plan)
            )
            if not running:
                return True
            remaining = deadline - self._monotonic()
            if remaining <= 0:
                return False
            self._sleep(min(poll_interval_seconds, remaining))

    def execute(
        self,
        plan_id: str,
        *,
        expected_digest: str,
        grace_period_seconds: float = 2.0,
        poll_interval_seconds: float = 0.05,
    ) -> ActionReceipt:
        if (
            not math.isfinite(grace_period_seconds)
            or grace_period_seconds < 0
            or grace_period_seconds > 30
        ):
            raise ValueError("grace period must be finite and between 0 and 30 seconds")
        if (
            not math.isfinite(poll_interval_seconds)
            or poll_interval_seconds <= 0
            or poll_interval_seconds > 5
        ):
            raise ValueError("poll interval must be finite and between 0 and 5 seconds")
        plan = self._store.claim_plan(
            plan_id,
            expected_digest=expected_digest,
        )
        started_at = self._now()
        if started_at.tzinfo is None or started_at.utcoffset() is None:
            raise ValueError("clock must return timezone-aware timestamps")
        result = ActionResult.FAILED
        after = "action_failed"
        partial_failures: tuple[str, ...] = ()
        action_issued: bool | None = False
        stable_reference: StableProcessReference | None = None
        try:
            self._revalidate(plan)
            self._store.update_plan_phase(plan.plan_id, "validated")
            if plan.mode is ActionMode.REQUEST_STOP:
                stable_reference = self._controller.bind(plan.identity)
                stable_reference.validate(plan.identity)
                self._store.update_plan_phase(plan.plan_id, "action_issuing")
                action_issued = None
                self._write_cancellation(plan, started_at, stable_reference)
                action_issued = True
            elif plan.mode is ActionMode.TERMINATE:
                self._store.update_plan_phase(plan.plan_id, "action_issuing")
                action_issued = None
                stable_reference = self._controller.terminate(plan.identity)
                action_issued = True
            else:
                self._store.update_plan_phase(plan.plan_id, "action_issuing")
                action_issued = None
                stable_reference = self._controller.kill(plan.identity)
                action_issued = True
            self._store.update_plan_phase(plan.plan_id, "action_issued")
            self._store.update_plan_phase(plan.plan_id, "verifying")
            ended = self._wait_for_exit(
                plan,
                reference=stable_reference,
                grace_period_seconds=grace_period_seconds,
                poll_interval_seconds=poll_interval_seconds,
            )
            if ended:
                result = ActionResult.COMPLETED
                after = "original_instance_ended"
            elif plan.mode is ActionMode.REQUEST_STOP and grace_period_seconds == 0:
                result = ActionResult.REQUESTED
                after = "cancellation_requested"
            else:
                result = ActionResult.PENDING
                after = "original_instance_still_running"
        except ProcessDisappeared:
            if action_issued is None:
                action_issued = False
            result = ActionResult.DISAPPEARED
            after = "not_found"
        except ProcessAccessDenied:
            if action_issued is None:
                action_issued = False
            result = ActionResult.ACCESS_DENIED
            after = "verification_access_denied"
            partial_failures = ("Process access was denied; no escalation was attempted.",)
        except ProcessIdentityMismatch:
            if action_issued is None:
                action_issued = False
            result = ActionResult.IDENTITY_MISMATCH
            after = "identity_mismatch"
            partial_failures = ("Process identity changed; no signal was sent.",)
        except ProcessActionNotIssued as error:
            action_issued = False
            result = ActionResult.FAILED
            after = "action_not_issued"
            partial_failures = (
                "The controller rejected the action before any process-side effect "
                f"({type(error).__name__}).",
            )
        except CancellationNotPublishedError:
            action_issued = False
            result = ActionResult.FAILED
            after = "cancellation_not_published"
            partial_failures = (
                "The cancellation request could not be published safely; no "
                "process-side effect occurred.",
            )
        except CancellationPublicationUncertainError:
            action_issued = None
            result = ActionResult.INTERRUPTED
            after = "cancellation_publication_uncertain"
            partial_failures = (
                "A cancellation request was published but its final validation or "
                "compensating acknowledgement was uncertain.",
            )
        except (OSError, ValueError) as error:
            if action_issued is None:
                result = ActionResult.INTERRUPTED
                after = "execution_outcome_uncertain"
                partial_failures = (
                    "The controller failed after action issuance began; whether the "
                    f"effect occurred is uncertain ({type(error).__name__}).",
                )
            else:
                result = ActionResult.FAILED
                after = "action_failed"
                partial_failures = (
                    "Action failed safely "
                    f"({type(error).__name__}); no further action was attempted.",
                )
        except Exception as error:
            if action_issued is None:
                result = ActionResult.INTERRUPTED
                after = "execution_outcome_uncertain"
                partial_failures = (
                    "The controller failed after action issuance began; whether the "
                    f"effect occurred is uncertain ({type(error).__name__}).",
                )
            else:
                result = ActionResult.FAILED
                after = "action_failed"
                partial_failures = (
                    "The process controller failed safely "
                    f"({type(error).__name__}); no further action was attempted.",
                )
        finally:
            if stable_reference is not None:
                try:
                    stable_reference.close()
                except Exception as error:
                    partial_failures += (
                        f"Stable process reference cleanup failed safely ({type(error).__name__}).",
                    )
        finished_at = self._now()
        receipt = ActionReceipt.create(
            plan=plan,
            actor=self._actor,
            session_id=self._session_id,
            result=result,
            action_issued=action_issued,
            before="running",
            after=after,
            started_at=started_at,
            finished_at=finished_at,
            partial_failures=partial_failures,
        )
        self._store.finish_plan(receipt)
        return receipt
