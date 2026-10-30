"""Low-cost process scanning, lease merging, and explicit coverage reporting."""

from __future__ import annotations

import ctypes
import importlib
import math
import os
import platform
import re
import secrets
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Protocol

import psutil  # type: ignore[import-untyped]
from pydantic import Field, ValidationError, model_validator

from zombie_killer_engine.classifier import classify
from zombie_killer_engine.identity import normalized_identity_fingerprint
from zombie_killer_engine.leases import (
    LeaseDocument,
    LeaseLifecycle,
    cancellation_user_fingerprint,
    discover_leases,
)
from zombie_killer_engine.models import (
    AgentRecord,
    AgentState,
    Classification,
    DomainModel,
    HashText,
    ProcessIdentity,
    ProcessSnapshot,
)
from zombie_killer_engine.redaction import is_sensitive_key, redact_text

_PSUTIL_ATTRIBUTES = (
    "pid",
    "ppid",
    "create_time",
    "name",
    "exe",
    "username",
    "status",
    "cpu_percent",
    "memory_info",
    "cmdline",
)
_SIGNATURE_PATTERN = re.compile(
    r"(?i)(?:^|[^a-z0-9])(?:aider|claude|codex|gemini|zombie[-_ ]killer)(?:$|[^a-z0-9])"
)
_MAX_SCAN_WARNINGS = 128
_UNAVAILABLE = object()
_WINDOWS_EXPENSIVE_ATTRIBUTES = frozenset({"ppid", "status"})


class ProcessReadError(StrEnum):
    ACCESS_DENIED = "access_denied"
    VANISHED = "vanished"


class ProcessObservation(DomainModel):
    """Provider-neutral, bounded snapshot input used by the real and fake providers."""

    pid: int = Field(gt=0)
    ppid: int | None = Field(default=None, ge=0)
    create_time: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    name: str | None = Field(default=None, max_length=256)
    exe: str | None = Field(default=None, max_length=4096)
    executable_hash: HashText | None = None
    username: str | None = Field(default=None, max_length=256)
    status: str | None = Field(default=None, max_length=64)
    cpu_percent: float | None = Field(default=None, allow_inf_nan=False)
    rss_bytes: int | None = Field(default=None, ge=0)
    cmdline: tuple[str, ...] = Field(default=(), max_length=128)
    signature_matched: bool = False
    error: ProcessReadError | None = None

    @model_validator(mode="after")
    def successful_observation_has_identity(self) -> ProcessObservation:
        partial_zombie = self.status is not None and self.status.casefold() == "zombie"
        if self.error is None and self.status is None:
            raise ValueError("successful process observations require status")
        if self.error is None and self.create_time is None and not partial_zombie:
            raise ValueError("successful process observations require create_time and status")
        return self


class ProcessProvider(Protocol):
    """Minimal injectable process enumeration boundary."""

    pid_enumeration_complete: bool

    def snapshot(self) -> tuple[ProcessObservation, ...]: ...


class SnapshotProcessProvider:
    """Immutable fake adapter used by tests and deterministic demos."""

    def __init__(
        self,
        observations: Sequence[ProcessObservation],
        *,
        pid_enumeration_complete: bool = True,
    ) -> None:
        self._observations = tuple(observations)
        self.pid_enumeration_complete = pid_enumeration_complete

    def snapshot(self) -> tuple[ProcessObservation, ...]:
        return self._observations


def _known_pid(process: object) -> int | None:
    try:
        info = getattr(process, "info", {})
    except Exception:
        info = {}
    if isinstance(info, dict):
        candidate = info.get("pid")
        if isinstance(candidate, int) and not isinstance(candidate, bool) and candidate > 0:
            return candidate
    try:
        pid = getattr(process, "pid", None)
    except Exception:
        return None
    return pid if isinstance(pid, int) and not isinstance(pid, bool) and pid > 0 else None


def _exception_pid(error: BaseException) -> int | None:
    try:
        pid = getattr(error, "pid", None)
    except Exception:
        return None
    return pid if isinstance(pid, int) and not isinstance(pid, bool) and pid > 0 else None


def _bounded_optional_text(value: object, *, max_length: int) -> str | None:
    if value is None:
        return None
    cleaned = redact_text(value, max_length=max_length)
    return cleaned or None


def _bounded_cmdline(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    sanitized: list[str] = []
    redact_next = False
    for argument in value[:128]:
        raw = str(argument)
        if redact_next:
            sanitized.append("[REDACTED]")
            redact_next = False
            continue
        sanitized.append(redact_text(raw, max_length=2048))
        redact_next = is_sensitive_key(raw)
    return tuple(sanitized)


def _windows_parent_map() -> dict[int, int] | None:
    """Take psutil's pinned Windows parent snapshot, with a public-API fallback.

    psutil's Windows ``Process.ppid()`` rebuilds the complete system parent map
    for every PID.  The package-private map is the same implementation used by
    that public method.  It is guarded because this project must continue to
    scan correctly if a future psutil release removes or changes the helper.
    """

    platform_adapter = getattr(psutil, "_psplatform", None)
    parent_map_provider = getattr(platform_adapter, "ppid_map", None)
    if not callable(parent_map_provider):
        return None
    try:
        raw_parent_map = parent_map_provider()
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError, psutil.Error):
        return None
    if not isinstance(raw_parent_map, dict):
        return None
    return {
        pid: parent_pid
        for pid, parent_pid in raw_parent_map.items()
        if isinstance(pid, int)
        and not isinstance(pid, bool)
        and pid > 0
        and isinstance(parent_pid, int)
        and not isinstance(parent_pid, bool)
        and parent_pid >= 0
    }


class PsutilProcessProvider:
    """Default low-cost psutil provider; environments and network state are excluded."""

    def __init__(self, *, platform_name: str | None = None) -> None:
        self.pid_enumeration_complete = True
        self._platform_name = platform_name or platform.system()

    def snapshot(self) -> tuple[ProcessObservation, ...]:
        self.pid_enumeration_complete = True
        observations: list[ProcessObservation] = []
        windows = self._platform_name.casefold().startswith("win")
        parent_map = _windows_parent_map() if windows else None
        attributes = (
            tuple(
                attribute
                for attribute in _PSUTIL_ATTRIBUTES
                if attribute not in _WINDOWS_EXPENSIVE_ATTRIBUTES
            )
            if windows
            else _PSUTIL_ATTRIBUTES
        )
        try:
            processes = psutil.process_iter(
                attrs=list(attributes),
                ad_value=_UNAVAILABLE,
            )
            for process in processes:
                pid = _known_pid(process)
                if pid is None:
                    continue
                try:
                    info = dict(process.info)
                    if windows:
                        parent_pid = (
                            parent_map.get(pid, _UNAVAILABLE)
                            if parent_map is not None
                            else _UNAVAILABLE
                        )
                        if parent_pid is _UNAVAILABLE:
                            parent_pid = info.get("ppid", _UNAVAILABLE)
                        if parent_pid is _UNAVAILABLE:
                            parent_pid = process.ppid()
                        info["ppid"] = parent_pid

                        # psutil's Windows backend can report only RUNNING or
                        # STOPPED here; unlike POSIX it cannot expose defunct
                        # processes. Its status probe rebuilds and walks the
                        # complete system process/thread table for every PID.
                        # Record the intentionally unprobed state honestly.
                        raw_status = info.get("status", _UNAVAILABLE)
                        info["status"] = (
                            "zombie"
                            if raw_status is not _UNAVAILABLE
                            and str(raw_status).casefold() == "zombie"
                            else "unknown"
                        )
                    if any(info.get(attribute) is _UNAVAILABLE for attribute in _PSUTIL_ATTRIBUTES):
                        status_value = info.get("status")
                        if (
                            status_value is not _UNAVAILABLE
                            and str(status_value).casefold() == "zombie"
                        ):
                            create_time = info.get("create_time")
                            raw_executable = (
                                None if info.get("exe") is _UNAVAILABLE else info.get("exe")
                            )
                            observations.append(
                                ProcessObservation(
                                    pid=pid,
                                    ppid=(
                                        int(info["ppid"])
                                        if info.get("ppid") is not _UNAVAILABLE
                                        and info.get("ppid") is not None
                                        else None
                                    ),
                                    create_time=(
                                        float(create_time)
                                        if create_time is not _UNAVAILABLE
                                        and create_time is not None
                                        else None
                                    ),
                                    name=_bounded_optional_text(
                                        None
                                        if info.get("name") is _UNAVAILABLE
                                        else info.get("name"),
                                        max_length=256,
                                    ),
                                    exe=_bounded_optional_text(
                                        raw_executable,
                                        max_length=4096,
                                    ),
                                    executable_hash=_executable_authority_hash(
                                        raw_executable,
                                        platform_name=self._platform_name,
                                    ),
                                    username=_bounded_optional_text(
                                        None
                                        if info.get("username") is _UNAVAILABLE
                                        else info.get("username"),
                                        max_length=256,
                                    ),
                                    status="zombie",
                                    cmdline=_bounded_cmdline(
                                        ()
                                        if info.get("cmdline") is _UNAVAILABLE
                                        else info.get("cmdline")
                                    ),
                                )
                            )
                            continue
                        observations.append(
                            ProcessObservation(
                                pid=pid,
                                error=ProcessReadError.ACCESS_DENIED,
                            )
                        )
                        continue
                    memory_info = info.get("memory_info")
                    rss = getattr(memory_info, "rss", None)
                    raw_executable = info.get("exe")
                    observations.append(
                        ProcessObservation(
                            pid=pid,
                            ppid=int(info["ppid"]) if info.get("ppid") is not None else None,
                            create_time=float(info["create_time"]),
                            name=_bounded_optional_text(
                                info.get("name"),
                                max_length=256,
                            ),
                            exe=_bounded_optional_text(
                                raw_executable,
                                max_length=4096,
                            ),
                            executable_hash=_executable_authority_hash(
                                raw_executable,
                                platform_name=self._platform_name,
                            ),
                            username=(
                                _bounded_optional_text(
                                    info.get("username"),
                                    max_length=256,
                                )
                            ),
                            status=(
                                _bounded_optional_text(
                                    info.get("status"),
                                    max_length=64,
                                )
                                or "unknown"
                            ),
                            cpu_percent=(
                                float(info["cpu_percent"])
                                if info.get("cpu_percent") is not None
                                else None
                            ),
                            rss_bytes=int(rss) if rss is not None else None,
                            cmdline=_bounded_cmdline(info.get("cmdline")),
                        )
                    )
                except psutil.AccessDenied:
                    observations.append(
                        ProcessObservation(
                            pid=pid,
                            error=ProcessReadError.ACCESS_DENIED,
                        )
                    )
                except psutil.ZombieProcess:
                    observations.append(
                        ProcessObservation(
                            pid=pid,
                            status="zombie",
                        )
                    )
                except psutil.NoSuchProcess:
                    observations.append(
                        ProcessObservation(pid=pid, error=ProcessReadError.VANISHED)
                    )
                except (OverflowError, TypeError, ValueError, ValidationError):
                    observations.append(
                        ProcessObservation(
                            pid=pid,
                            error=ProcessReadError.ACCESS_DENIED,
                        )
                    )
        except psutil.AccessDenied as error:
            self.pid_enumeration_complete = False
            pid = _exception_pid(error)
            if pid is not None:
                observations.append(
                    ProcessObservation(pid=pid, error=ProcessReadError.ACCESS_DENIED)
                )
        except psutil.ZombieProcess as error:
            self.pid_enumeration_complete = False
            pid = _exception_pid(error)
            if pid is not None:
                observations.append(ProcessObservation(pid=pid, status="zombie"))
        except psutil.NoSuchProcess as error:
            self.pid_enumeration_complete = False
            pid = _exception_pid(error)
            if pid is not None:
                observations.append(ProcessObservation(pid=pid, error=ProcessReadError.VANISHED))
        return tuple(observations)


class ScanWarning(DomainModel):
    code: str = Field(min_length=1, max_length=128)
    message: str = Field(min_length=1, max_length=512)


class _ScanWarningCollector:
    def __init__(self) -> None:
        self._groups: dict[tuple[str, str], tuple[ScanWarning, int]] = {}

    def add(self, warning: ScanWarning) -> None:
        key = (warning.code, warning.message)
        existing = self._groups.get(key)
        self._groups[key] = (
            warning if existing is None else existing[0],
            1 if existing is None else existing[1] + 1,
        )

    def render(self) -> tuple[ScanWarning, ...]:
        collapsed = [
            warning
            if count == 1
            else ScanWarning(
                code=warning.code,
                message=redact_text(
                    f"{warning.message} Repeated {count} times.",
                    max_length=512,
                ),
            )
            for warning, count in self._groups.values()
        ]
        if len(collapsed) <= _MAX_SCAN_WARNINGS:
            return tuple(collapsed)
        retained = collapsed[: _MAX_SCAN_WARNINGS - 1]
        retained.append(
            ScanWarning(
                code="SCAN_WARNING_SUMMARY",
                message=(
                    f"{len(collapsed) - len(retained)} additional warning groups were omitted."
                ),
            )
        )
        return tuple(retained)


class ProcessDetails(DomainModel):
    identity: ProcessIdentity | None = None
    observed_at: datetime
    ppid: int | None = Field(default=None, ge=0)
    name: str | None = Field(default=None, max_length=256)
    status: str = Field(min_length=1, max_length=64)
    cpu_percent: float | None = Field(default=None, allow_inf_nan=False)
    rss_bytes: int | None = Field(default=None, ge=0)
    cmdline: tuple[str, ...] = Field(max_length=128)
    identity_authorization_complete: bool = True


class ScannedAgent(DomainModel):
    agent_id: str | None = Field(default=None, max_length=256)
    registration_nonce: str | None = Field(default=None, max_length=256)
    provider: str | None = Field(default=None, max_length=256)
    project: str | None = Field(default=None, max_length=256)
    role: str | None = Field(default=None, max_length=256)
    status: str | None = Field(default=None, max_length=2048)
    lifecycle: LeaseLifecycle | None = None
    terminal_at: datetime | None = None
    detached: bool = False
    lease_matched: bool = False
    actionable: bool = False
    process: ProcessDetails | None = None
    classification: Classification


class ScanCoverage(DomainModel):
    inspected_count: int = Field(ge=0)
    denied_count: int = Field(ge=0)
    vanished_count: int = Field(ge=0)
    malformed_lease_count: int = Field(ge=0)
    lease_file_count: int = Field(ge=0)
    skipped_lease_count: int = Field(ge=0)
    other_user_count: int = Field(ge=0)
    unknown_owner_count: int = Field(ge=0)
    identity_denied_count: int = Field(ge=0)
    complete: bool
    captured_at: datetime
    current_boot_id: str = Field(min_length=1, max_length=256)
    warnings: tuple[ScanWarning, ...]


class ScanResult(DomainModel):
    agents: tuple[ScannedAgent, ...]
    coverage: ScanCoverage


def _capture_time(value: datetime | None) -> datetime:
    captured = value or datetime.now(UTC)
    if captured.tzinfo is None or captured.utcoffset() is None:
        raise ValueError("captured_at must be timezone-aware")
    return captured.astimezone(UTC)


def current_boot_id(
    *,
    platform_name: str | None = None,
    linux_boot_id_path: Path = Path("/proc/sys/kernel/random/boot_id"),
    boot_time: Callable[[], float] | None = None,
) -> str:
    """Return a stable local boot token without persisting a host identifier."""
    system = (platform_name or platform.system()).casefold()
    if system == "linux":
        try:
            value = linux_boot_id_path.read_text(encoding="ascii").strip()
            if value and len(value) <= 256:
                return value
        except (OSError, UnicodeError):
            pass
    if boot_time is not None:
        resolved_boot_time = boot_time()
    elif system.startswith("win") and os.name == "nt":
        resolved_boot_time = _windows_exact_boot_time()
    elif system == "darwin" and platform.system().casefold() == "darwin":
        resolved_boot_time = _darwin_exact_boot_time()
    else:
        resolved_boot_time = psutil.boot_time()
    if not math.isfinite(resolved_boot_time) or resolved_boot_time < 0:
        raise RuntimeError("the operating-system boot time is invalid")
    stable_time = round(resolved_boot_time * 1_000_000)
    label = "windows" if system.startswith("win") else "darwin" if system == "darwin" else system
    return f"{label}-{stable_time:x}"


def _windows_exact_boot_time() -> float:
    """Return the OS boot epoch used by the dependency-free broadcaster SDK."""

    class TimeOfDay(ctypes.Structure):
        _fields_ = [
            ("boot_time", ctypes.c_longlong),
            ("current_time", ctypes.c_longlong),
            ("time_zone_bias", ctypes.c_longlong),
            ("current_time_zone_id", ctypes.c_ulong),
            ("reserved", ctypes.c_ulong),
            ("boot_time_bias", ctypes.c_ulonglong),
            ("sleep_time_bias", ctypes.c_ulonglong),
        ]

    information = TimeOfDay()
    status = ctypes.WinDLL("ntdll").NtQuerySystemInformation(
        3,
        ctypes.byref(information),
        ctypes.sizeof(information),
        None,
    )
    if status != 0:
        raise OSError("Windows boot time is unavailable")
    # Windows can apply a few 100 ns of clock correction between calls. Whole
    # seconds remain stable across independently running engine/SDK processes.
    return float(information.boot_time // 10_000_000 - 11_644_473_600)


def _darwin_exact_boot_time() -> float:
    """Return a stable macOS boot epoch shared with the broadcaster SDK."""

    class Timeval(ctypes.Structure):
        _fields_ = [("seconds", ctypes.c_long), ("microseconds", ctypes.c_int)]

    value = Timeval()
    size = ctypes.c_size_t(ctypes.sizeof(value))
    libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    if (
        libc.sysctlbyname(
            b"kern.boottime",
            ctypes.byref(value),
            ctypes.byref(size),
            None,
            0,
        )
        != 0
    ):
        raise OSError(ctypes.get_errno(), "kern.boottime query failed")
    return float(value.seconds)


def _windows_user_parts(value: str) -> tuple[str | None, str]:
    normalized = value.strip().replace("/", "\\").casefold()
    if "\\" not in normalized:
        return None, normalized
    domain, name = normalized.rsplit("\\", 1)
    return domain or None, name


def is_current_user(
    observed: str | None,
    current_user: str,
    *,
    platform_name: str | None = None,
) -> bool:
    """Conservatively compare platform user identities."""
    if observed is None or not observed.strip() or not current_user.strip():
        return False
    system = (platform_name or platform.system()).casefold()
    if system.startswith("win"):
        observed_domain, observed_name = _windows_user_parts(observed)
        current_domain, current_name = _windows_user_parts(current_user)
        if observed_name != current_name:
            return False
        if observed_domain is None or current_domain is None:
            return observed_domain is current_domain
        return observed_domain == current_domain
    return observed == current_user


def _executable_authority_hash(value: object, *, platform_name: str) -> str | None:
    if value is None or value is _UNAVAILABLE:
        return None
    raw = str(value)
    if not raw:
        return None
    return normalized_identity_fingerprint(raw, platform_name=platform_name)


def _identity_matches(
    document: LeaseDocument,
    observation: ProcessObservation,
    *,
    boot_id: str,
    platform_name: str,
) -> bool:
    identity = document.lease.identity
    if (identity.boot_id, identity.pid, identity.create_time) != (
        boot_id,
        observation.pid,
        observation.create_time,
    ):
        return False
    if identity.executable is not None and (
        observation.executable_hash is not None or observation.exe is not None
    ):
        expected_executable_hash = normalized_identity_fingerprint(
            identity.executable,
            platform_name=platform_name,
        )
        observed_executable_hash = observation.executable_hash or (
            normalized_identity_fingerprint(
                observation.exe,
                platform_name=platform_name,
            )
            if observation.exe is not None
            else None
        )
        if observed_executable_hash is None or not secrets.compare_digest(
            expected_executable_hash,
            observed_executable_hash,
        ):
            return False
    return not (
        identity.user is not None
        and observation.username is not None
        and not is_current_user(
            observation.username,
            identity.user,
            platform_name=platform_name,
        )
    )


def _signature_matches(observation: ProcessObservation) -> bool:
    if observation.signature_matched:
        return True
    text = " ".join(
        part for part in (observation.name, observation.exe, *observation.cmdline) if part
    )
    return bool(_SIGNATURE_PATTERN.search(text))


def _process_details(
    observation: ProcessObservation,
    *,
    boot_id: str,
    captured_at: datetime,
    platform_name: str,
    identity_fingerprint_provider: Callable[[int, str, str], str],
) -> ProcessDetails:
    if observation.status is None:
        raise ValueError("incomplete observation cannot become process details")
    user_hash: str | None = None
    identity_authorization_complete = True
    if observation.username is not None:
        try:
            user_hash = identity_fingerprint_provider(
                observation.pid,
                observation.username,
                platform_name,
            )
        except OSError:
            # Visibility of one protected process must not abort the snapshot.
            user_hash = None
            identity_authorization_complete = False
    identity = (
        ProcessIdentity(
            boot_id=boot_id,
            pid=observation.pid,
            create_time=observation.create_time,
            executable=observation.exe,
            user=observation.username,
            executable_hash=(
                observation.executable_hash
                or (
                    normalized_identity_fingerprint(
                        observation.exe,
                        platform_name=platform_name,
                    )
                    if observation.exe is not None
                    else None
                )
            ),
            user_hash=user_hash,
        )
        if observation.create_time is not None
        else None
    )
    return ProcessDetails(
        identity=identity,
        observed_at=captured_at,
        ppid=observation.ppid,
        name=redact_text(observation.name, max_length=256) if observation.name else None,
        status=observation.status,
        cpu_percent=observation.cpu_percent,
        rss_bytes=observation.rss_bytes,
        cmdline=_bounded_cmdline(observation.cmdline),
        identity_authorization_complete=identity_authorization_complete,
    )


def _snapshot(
    details: ProcessDetails,
    *,
    visibility_complete: bool,
    signature_matched: bool,
    parent_alive: bool | None = None,
    owner_alive: bool | None = None,
) -> ProcessSnapshot:
    return ProcessSnapshot(
        identity=details.identity,
        observed_at=details.observed_at,
        process_present=True,
        os_status=details.status,
        parent_alive=parent_alive,
        owner_alive=owner_alive,
        visibility_complete=visibility_complete,
        signature_matched=signature_matched,
    )


def _unknown_scope_agent(
    details: ProcessDetails,
    *,
    boot_id: str,
    captured_at: datetime,
) -> ScannedAgent:
    classification = classify(
        AgentRecord(
            current_boot_id=boot_id,
            process=_snapshot(
                details,
                visibility_complete=False,
                signature_matched=True,
            ),
        ),
        now=captured_at,
    )
    return ScannedAgent(
        process=details,
        classification=classification,
        actionable=False,
    )


def _default_current_user(platform_name: str) -> str:
    if platform_name.casefold().startswith("win"):
        secur32 = ctypes.WinDLL("secur32", use_last_error=True)
        size = ctypes.c_ulong()
        secur32.GetUserNameExW(2, None, ctypes.byref(size))
        if size.value == 0:
            raise RuntimeError("current Windows user identity is unavailable")
        buffer = ctypes.create_unicode_buffer(size.value)
        if not secur32.GetUserNameExW(2, buffer, ctypes.byref(size)):
            raise RuntimeError("current Windows user identity is unavailable")
        resolved = buffer.value.strip()
    else:
        try:
            pwd_module = importlib.import_module("pwd")
            user_entry = pwd_module.getpwuid(
                os.geteuid()  # type: ignore[attr-defined]
            )
            resolved = str(user_entry.pw_name).strip()
        except (ImportError, KeyError, OSError) as error:
            raise RuntimeError("current POSIX user identity is unavailable") from error
    if not resolved:
        raise RuntimeError("current user identity is unavailable")
    return resolved


def scan_agents(
    lease_dir: Path,
    *,
    process_provider: ProcessProvider | None = None,
    current_boot: str | None = None,
    current_user: str | None = None,
    platform_name: str | None = None,
    captured_at: datetime | None = None,
    identity_fingerprint_provider: Callable[[int, str, str], str] | None = None,
    heartbeat_grace_seconds: int | None = None,
) -> ScanResult:
    """Capture processes once, merge untrusted leases, and classify candidates."""
    capture = _capture_time(captured_at)
    if heartbeat_grace_seconds is not None and (
        isinstance(heartbeat_grace_seconds, bool)
        or not isinstance(heartbeat_grace_seconds, int)
        or not 10 <= heartbeat_grace_seconds <= 86_400
    ):
        raise ValueError("heartbeat grace must be an integer between ten and 86400 seconds")
    system = (platform_name or platform.system()).casefold()
    boot_id = current_boot_id(platform_name=system) if current_boot is None else current_boot
    user = _default_current_user(system) if current_user is None else current_user
    if not boot_id.strip() or len(boot_id) > 256:
        raise ValueError("current_boot must be non-empty and at most 256 characters")
    if not user.strip():
        raise ValueError("current_user must be non-empty")

    discovery = discover_leases(lease_dir, now=capture)
    provider = process_provider or PsutilProcessProvider()
    fingerprint_provider = identity_fingerprint_provider or (
        lambda pid, identity_user, identity_platform: cancellation_user_fingerprint(
            pid,
            identity_user,
            platform_name=identity_platform,
        )
    )
    observations = provider.snapshot()
    pid_enumeration_complete = bool(getattr(provider, "pid_enumeration_complete", True))
    warnings = _ScanWarningCollector()
    for warning in discovery.warnings:
        warnings.add(ScanWarning(code=warning.code, message=warning.message))
    denied_count = 0
    vanished_count = 0
    successful: list[ProcessObservation] = []
    details_by_pid: dict[int, ProcessDetails] = {}
    other_user_count = 0
    unknown_owner_count = 0
    identity_denied_count = 0
    for observation in observations:
        if observation.error is ProcessReadError.ACCESS_DENIED:
            denied_count += 1
            warnings.add(
                ScanWarning(
                    code="PROCESS_ACCESS_DENIED",
                    message="A process could not be inspected due to access restrictions.",
                )
            )
            continue
        if observation.error is ProcessReadError.VANISHED:
            vanished_count += 1
            warnings.add(
                ScanWarning(
                    code="PROCESS_VANISHED",
                    message="A process exited while the scan snapshot was being captured.",
                )
            )
            continue
        successful.append(observation)
        details = _process_details(
            observation,
            boot_id=boot_id,
            captured_at=capture,
            platform_name=system,
            identity_fingerprint_provider=fingerprint_provider,
        )
        details_by_pid[observation.pid] = details
        if not details.identity_authorization_complete:
            identity_denied_count += 1
            warnings.add(
                ScanWarning(
                    code="PROCESS_IDENTITY_DENIED",
                    message=(
                        "A process authorization identity could not be verified due "
                        "to access restrictions."
                    ),
                )
            )
        if observation.username is None:
            unknown_owner_count += 1
        elif not is_current_user(observation.username, user, platform_name=system):
            other_user_count += 1

    attribute_visibility_complete = (
        denied_count == 0
        and vanished_count == 0
        and unknown_owner_count == 0
        and identity_denied_count == 0
    )
    enumerated_pids = {observation.pid for observation in observations}
    successful_pids = {observation.pid for observation in successful}
    observations_by_pid = {observation.pid: observation for observation in successful}
    errors_by_pid = {
        observation.pid: observation.error
        for observation in observations
        if observation.error is not None
    }
    consumed_pids: set[int] = set()
    agents: list[ScannedAgent] = []

    lease_evidence: dict[
        str,
        tuple[
            ProcessObservation | None,
            ProcessDetails | None,
            bool,
            bool,
            bool,
        ],
    ] = {}
    documents_by_agent_id = {document.lease.agent_id: document for document in discovery.leases}
    for document in discovery.leases:
        lease = document.lease
        candidate_observation = observations_by_pid.get(lease.identity.pid)
        previous_boot = lease.identity.boot_id != boot_id
        if previous_boot:
            candidate_observation = None
        candidate_details = (
            details_by_pid.get(lease.identity.pid) if candidate_observation is not None else None
        )
        owner_is_current = candidate_observation is not None and is_current_user(
            candidate_observation.username,
            user,
            platform_name=system,
        )
        matched = (
            candidate_observation is not None
            and owner_is_current
            and _identity_matches(
                document,
                candidate_observation,
                boot_id=boot_id,
                platform_name=system,
            )
        )
        lease_evidence[lease.agent_id] = (
            candidate_observation,
            candidate_details,
            owner_is_current,
            matched,
            previous_boot,
        )

    def pid_is_alive(pid: int) -> bool | None:
        observation = observations_by_pid.get(pid)
        if observation is not None:
            return observation.status is None or observation.status.casefold() != "zombie"
        error = errors_by_pid.get(pid)
        if error is ProcessReadError.VANISHED:
            return False
        if error is ProcessReadError.ACCESS_DENIED:
            return True
        if not pid_enumeration_complete:
            return None
        return False

    def expected_owner_alive(expected_owner: str | None) -> bool | None:
        if expected_owner is None:
            return None
        owner_document = documents_by_agent_id.get(expected_owner)
        if owner_document is None:
            return None
        owner_evidence = lease_evidence[expected_owner]
        if owner_evidence[3]:
            return pid_is_alive(owner_document.lease.identity.pid)
        owner_pid = owner_document.lease.identity.pid
        if owner_pid in successful_pids:
            return False
        if errors_by_pid.get(owner_pid) is ProcessReadError.VANISHED:
            return False
        if not pid_enumeration_complete:
            return None
        if owner_pid not in enumerated_pids:
            return False
        return None

    for document in discovery.leases:
        lease = document.lease
        (
            candidate_observation,
            candidate_details,
            owner_is_current,
            matched,
            previous_boot,
        ) = lease_evidence[lease.agent_id]
        if matched and candidate_observation is not None:
            consumed_pids.add(candidate_observation.pid)
        if candidate_details is None:
            process_snapshot = ProcessSnapshot(
                observed_at=capture,
                process_present=False,
                os_status="not-found",
                visibility_complete=pid_enumeration_complete,
            )
        else:
            assert candidate_observation is not None
            parent_alive = (
                pid_is_alive(lease.expected_parent_pid)
                if lease.expected_parent_pid is not None
                else None
            )
            process_snapshot = _snapshot(
                candidate_details,
                visibility_complete=(
                    owner_is_current and candidate_details.identity_authorization_complete
                ),
                signature_matched=_signature_matches(candidate_observation),
                parent_alive=parent_alive,
                owner_alive=expected_owner_alive(lease.expected_owner),
            )
        classifier_lease = lease
        if matched and candidate_details is not None:
            classifier_lease = lease.model_copy(update={"identity": candidate_details.identity})
        if heartbeat_grace_seconds is not None:
            classifier_lease = classifier_lease.model_copy(
                update={"heartbeat_timeout_seconds": float(heartbeat_grace_seconds)}
            )
        classification = classify(
            AgentRecord(
                current_boot_id=boot_id,
                lease=classifier_lease,
                process=process_snapshot,
            ),
            now=capture,
        )
        expose_metadata = matched or previous_boot or document.lifecycle.terminal
        agents.append(
            ScannedAgent(
                agent_id=lease.agent_id,
                registration_nonce=lease.registration_nonce if expose_metadata else None,
                provider=document.provider if expose_metadata else None,
                project=document.project if expose_metadata else None,
                role=document.role if expose_metadata else None,
                status=document.status if expose_metadata else None,
                lifecycle=document.lifecycle if expose_metadata else None,
                terminal_at=document.terminal_at if expose_metadata else None,
                detached=lease.detached if expose_metadata else False,
                lease_matched=matched,
                actionable=(
                    matched
                    and candidate_details is not None
                    and candidate_details.identity_authorization_complete
                    and classification.state
                    not in {
                        AgentState.UNKNOWN,
                        AgentState.DEFUNCT,
                        AgentState.COMPLETED,
                        AgentState.FAILED,
                        AgentState.CANCELLED,
                    }
                ),
                process=candidate_details,
                classification=classification,
            )
        )

    for observation in successful:
        if observation.pid in consumed_pids or not _signature_matches(observation):
            continue
        details = details_by_pid[observation.pid]
        if not is_current_user(observation.username, user, platform_name=system):
            agents.append(
                _unknown_scope_agent(
                    details,
                    boot_id=boot_id,
                    captured_at=capture,
                )
            )
            continue
        classification = classify(
            AgentRecord(
                current_boot_id=boot_id,
                process=_snapshot(
                    details,
                    visibility_complete=details.identity_authorization_complete,
                    signature_matched=True,
                ),
            ),
            now=capture,
        )
        agents.append(
            ScannedAgent(
                process=details,
                classification=classification,
                actionable=False,
            )
        )

    complete = (
        attribute_visibility_complete
        and pid_enumeration_complete
        and discovery.malformed_count == 0
        and not discovery.warnings
    )
    coverage = ScanCoverage(
        inspected_count=len(successful),
        denied_count=denied_count,
        vanished_count=vanished_count,
        malformed_lease_count=discovery.malformed_count,
        lease_file_count=discovery.total_count,
        skipped_lease_count=discovery.skipped_count,
        other_user_count=other_user_count,
        unknown_owner_count=unknown_owner_count,
        identity_denied_count=identity_denied_count,
        complete=complete,
        captured_at=capture,
        current_boot_id=boot_id,
        warnings=warnings.render(),
    )
    return ScanResult(agents=tuple(agents), coverage=coverage)
