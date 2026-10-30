"""Public cooperative lifecycle broadcaster."""

from __future__ import annotations

import asyncio
import atexit
import math
import os
import random
import threading
import time
import uuid
import weakref
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, TypeAlias, TypeVar, cast

from .lease import (
    LeaseSecurityError,
    LeaseStore,
    ProcessIdentity,
    cancellation_target,
    current_process_identity,
    secure_random_nonce,
    validate_temp_resource,
)
from .redaction import redact_status

_T = TypeVar("_T")
_PROVIDERS = frozenset(
    {"anthropic-claude", "custom", "google-gemini", "local", "openai", "xai-grok"}
)
_RESULTS = frozenset({"completed", "failed", "cancelled"})
_MAX_RESOURCES = 64
LifecycleResult: TypeAlias = Literal["completed", "failed", "cancelled"]

_ACTIVE_AGENTS: weakref.WeakSet[Agent] = weakref.WeakSet()
_REGISTRY_LOCK = threading.RLock()
_REGISTRY_CALLBACKS_INSTALLED = False


def _close_registered_agents() -> None:
    with _REGISTRY_LOCK:
        agents = tuple(_ACTIVE_AGENTS)
    for agent in agents:
        with suppress(Exception):
            agent.close(result="cancelled" if agent.cancelled else "completed")


def _fork_registered_agents() -> None:
    global _REGISTRY_LOCK
    _REGISTRY_LOCK = threading.RLock()
    for agent in tuple(_ACTIVE_AGENTS):
        agent._after_fork_child()


def _register_active_agent(agent: Agent) -> None:
    global _REGISTRY_CALLBACKS_INSTALLED
    with _REGISTRY_LOCK:
        _ACTIVE_AGENTS.add(agent)
        if _REGISTRY_CALLBACKS_INSTALLED:
            return
        atexit.register(_close_registered_agents)
        register_at_fork = getattr(os, "register_at_fork", None)
        if register_at_fork is not None:
            register_at_fork(after_in_child=_fork_registered_agents)
        _REGISTRY_CALLBACKS_INSTALLED = True


def _discard_active_agent(agent: Agent) -> None:
    with _REGISTRY_LOCK:
        _ACTIVE_AGENTS.discard(agent)


class SDKError(RuntimeError):
    """A safe registration error raised only when strict mode is requested."""


class BudgetExceeded(SDKError):
    """A local cooperative budget prevented a caller action."""

    def __init__(self, reasons: tuple[str, ...]) -> None:
        self.reasons = reasons
        super().__init__("Zombie Killer cooperative budget exceeded: " + ", ".join(reasons))


@dataclass(frozen=True, slots=True)
class BudgetReservation:
    """Usage capacity reserved atomically around one provider callback."""

    requests: int = 1
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float | None = None
    runtime_seconds: float = 0.0

    def __post_init__(self) -> None:
        integer_values = (self.requests, self.input_tokens, self.output_tokens)
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in integer_values
        ):
            raise ValueError("reserved requests and tokens must be non-negative integers")
        numeric_values = (self.runtime_seconds,) + (
            () if self.cost_usd is None else (self.cost_usd,)
        )
        if any(
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value < 0
            for value in numeric_values
        ):
            raise ValueError("reserved cost and runtime must be finite and non-negative")


def _text(value: str, *, field: str, maximum: int = 256) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a string")
    cleaned = value.strip()
    if not cleaned or len(cleaned) > maximum:
        raise ValueError(f"{field} must contain 1 to {maximum} characters")
    if any(ord(character) < 32 or ord(character) == 127 for character in cleaned):
        raise ValueError(f"{field} cannot contain control characters")
    return cleaned


def _uuid(value: str | uuid.UUID | None, *, field: str) -> str:
    if value is None:
        return str(uuid.uuid4())
    try:
        parsed = value if isinstance(value, uuid.UUID) else uuid.UUID(value)
    except (AttributeError, TypeError, ValueError) as error:
        raise ValueError(f"{field} must be a UUID") from error
    if parsed.variant != uuid.RFC_4122:
        raise ValueError(f"{field} must be an RFC 4122 UUID")
    return str(parsed)


def _optional_limit(
    value: int | float | None, *, field: str, integer: bool = False
) -> float | int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{field} must be numeric")
    if not math.isfinite(value) or value <= 0:
        raise ValueError(f"{field} must be finite and positive")
    if integer and not isinstance(value, int):
        raise TypeError(f"{field} must be an integer")
    return value


def _utc(value: datetime | None = None) -> datetime:
    resolved = value or datetime.now(UTC)
    if resolved.tzinfo is None or resolved.utcoffset() is None:
        raise ValueError("clock must return a timezone-aware datetime")
    return resolved.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _rss_bytes() -> int | None:
    try:
        if os.name == "nt":
            import ctypes

            class Counters(ctypes.Structure):
                _fields_ = [
                    ("cb", ctypes.c_ulong),
                    ("page_fault_count", ctypes.c_ulong),
                    ("peak_working_set_size", ctypes.c_size_t),
                    ("working_set_size", ctypes.c_size_t),
                    ("quota_peak_paged_pool_usage", ctypes.c_size_t),
                    ("quota_paged_pool_usage", ctypes.c_size_t),
                    ("quota_peak_non_paged_pool_usage", ctypes.c_size_t),
                    ("quota_non_paged_pool_usage", ctypes.c_size_t),
                    ("pagefile_usage", ctypes.c_size_t),
                    ("peak_pagefile_usage", ctypes.c_size_t),
                ]

            counters = Counters()
            counters.cb = ctypes.sizeof(counters)
            kernel32 = ctypes.WinDLL("kernel32")
            kernel32.GetCurrentProcess.restype = ctypes.c_void_p
            if not ctypes.WinDLL("psapi").GetProcessMemoryInfo(
                kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb
            ):
                return None
            return int(counters.working_set_size)
        sysconf = getattr(os, "sysconf", None)
        if sysconf is None:
            return None
        page_size = int(sysconf("SC_PAGE_SIZE"))
        fields = Path("/proc/self/statm").read_text(encoding="ascii").split()
        return int(fields[1]) * page_size
    except (OSError, ValueError, IndexError):
        return None


class Agent:
    """Broadcast bounded local lifecycle evidence to Zombie Killer.

    Status strings are telemetry labels only. Do not put prompts, PII, credentials,
    response bodies, command lines, or other sensitive content in them.
    """

    def __init__(
        self,
        *,
        provider: str,
        project: str,
        role: str,
        state_dir: Path | str | None = None,
        agent_id: str | uuid.UUID | None = None,
        run_id: str | uuid.UUID | None = None,
        heartbeat_interval: float = 10.0,
        lease_ttl: float | None = None,
        detached: bool = False,
        survive_parent: bool = False,
        parent_pid: int | None = None,
        parent_identity: ProcessIdentity | None = None,
        parent_agent_id: str | uuid.UUID | None = None,
        strict: bool = False,
        on_cancel: Callable[[], object] | None = None,
        max_requests: int | None = None,
        max_tokens: int | None = None,
        max_runtime_seconds: float | None = None,
        max_idle_seconds: float | None = None,
        max_rss_bytes: int | None = None,
        _clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        _monotonic: Callable[[], float] = time.monotonic,
        _random: Callable[[], float] = random.random,
        _identity_provider: Callable[[], ProcessIdentity] = current_process_identity,
        _nonce_factory: Callable[[], str] = secure_random_nonce,
        _uuid_factory: Callable[[], uuid.UUID | str] = uuid.uuid4,
    ) -> None:
        normalized_provider = _text(provider, field="provider").casefold()
        if normalized_provider not in _PROVIDERS:
            raise ValueError(f"provider must be one of: {', '.join(sorted(_PROVIDERS))}")
        if isinstance(heartbeat_interval, bool) or not isinstance(heartbeat_interval, (int, float)):
            raise TypeError("heartbeat_interval must be numeric")
        if not math.isfinite(heartbeat_interval) or not 1 <= heartbeat_interval <= 300:
            raise ValueError("heartbeat_interval must be between 1 and 300 seconds")
        resolved_ttl = max(float(heartbeat_interval) * 3, float(heartbeat_interval) + 1)
        if lease_ttl is not None:
            if isinstance(lease_ttl, bool) or not isinstance(lease_ttl, (int, float)):
                raise TypeError("lease_ttl must be numeric")
            resolved_ttl = float(lease_ttl)
        if not math.isfinite(resolved_ttl) or not heartbeat_interval < resolved_ttl <= 3600:
            raise ValueError("lease_ttl must exceed heartbeat_interval and be at most 3600 seconds")
        if not isinstance(detached, bool) or not isinstance(survive_parent, bool):
            raise TypeError("detached and survive_parent must be booleans")
        if parent_pid is not None and (isinstance(parent_pid, bool) or parent_pid <= 0):
            raise ValueError("parent_pid must be positive")
        if parent_identity is not None:
            if parent_pid is not None and parent_identity.pid != parent_pid:
                raise ValueError("parent identity does not match parent_pid")
            parent_pid = parent_identity.pid

        self.provider = normalized_provider
        self.project = _text(project, field="project")
        self.role = _text(role, field="role")
        self.heartbeat_interval = float(heartbeat_interval)
        self.lease_ttl = resolved_ttl
        self.detached = detached or survive_parent
        self.survive_parent = survive_parent
        self.parent_identity = parent_identity
        self.parent_pid = None if self.detached else (parent_pid or os.getppid())
        self.parent_agent_id = (
            None
            if self.detached or parent_agent_id is None
            else _uuid(parent_agent_id, field="parent_agent_id")
        )
        self.run_id = _uuid(run_id, field="run_id")
        self.strict = strict
        self.on_cancel = on_cancel
        self._clock = _clock
        self._monotonic = _monotonic
        self._random = _random
        self._identity_provider = _identity_provider
        self._nonce_factory = _nonce_factory
        self._uuid_factory = _uuid_factory
        self._store = LeaseStore(state_dir, strict=strict)
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._started = False
        self._closed = False
        try:
            self._identity = self._identity_provider()
            self._identity_available = True
            identity_warning: str | None = None
        except OSError as error:
            self._identity = ProcessIdentity(
                boot_id="unavailable",
                pid=os.getpid(),
                create_time=0.0,
            )
            self._identity_available = False
            identity_warning = type(error).__name__
        self.agent_id = _uuid(agent_id, field="agent_id")
        self.registration_nonce = _text(self._nonce_factory(), field="registration_nonce")
        self._registration_generation = 1
        self._status: str | None = None
        self._lifecycle = "running"
        self._terminal_at: datetime | None = None
        self._resources: list[dict[str, object]] = []
        self._counters: dict[str, int | float] = {
            "requests": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "runtime_seconds": 0.0,
        }
        self._inflight = BudgetReservation(requests=0)
        self._cancelled = False
        self._cancel_callback_invoked = False
        self._warning = identity_warning
        self._started_monotonic = self._monotonic()
        self._last_activity = self._started_monotonic
        self._budget_reasons: tuple[str, ...] = ()
        self._max_requests = cast(
            int | None, _optional_limit(max_requests, field="max_requests", integer=True)
        )
        self._max_tokens = cast(
            int | None, _optional_limit(max_tokens, field="max_tokens", integer=True)
        )
        self._max_runtime = cast(
            float | None, _optional_limit(max_runtime_seconds, field="max_runtime_seconds")
        )
        self._max_idle = cast(
            float | None, _optional_limit(max_idle_seconds, field="max_idle_seconds")
        )
        self._max_rss = cast(
            int | None, _optional_limit(max_rss_bytes, field="max_rss_bytes", integer=True)
        )

    def __repr__(self) -> str:
        return (
            f"Agent(provider={self.provider!r}, project={self.project!r}, role={self.role!r}, "
            f"agent_id={self.agent_id!r}, started={self.started})"
        )

    @property
    def identity(self) -> ProcessIdentity:
        with self._lock:
            return self._identity

    @property
    def lease_path(self) -> Path:
        with self._lock:
            return self._store.lease_path(self.agent_id)

    @property
    def cancellation_target(self) -> dict[str, object]:
        with self._lock:
            return cancellation_target(self._identity)

    @property
    def started(self) -> bool:
        with self._lock:
            return self._started and not self._closed

    @property
    def available(self) -> bool:
        return self._identity_available and self._store.available

    @property
    def cancelled(self) -> bool:
        with self._lock:
            return self._cancelled

    @property
    def status_text(self) -> str | None:
        with self._lock:
            return self._status

    @property
    def warning(self) -> str | None:
        with self._lock:
            return self._warning or self._store.last_warning

    @property
    def budget_reasons(self) -> tuple[str, ...]:
        with self._lock:
            return self._compute_budget_reasons_locked()

    @property
    def budget_exceeded(self) -> bool:
        return bool(self.budget_reasons)

    def _new_uuid(self) -> str:
        return _uuid(self._uuid_factory(), field="generated UUID")

    def _ensure_process_locked(self) -> None:
        try:
            observed = self._identity_provider()
        except OSError as error:
            self._identity_available = False
            self._warning = type(error).__name__
            return
        self._identity_available = True
        if observed == self._identity:
            return
        self._identity = observed
        self.agent_id = self._new_uuid()
        self.registration_nonce = _text(self._nonce_factory(), field="registration_nonce")
        self._registration_generation += 1
        self.parent_pid = None if self.detached else os.getppid()
        self._closed = False
        self._lifecycle = "running"
        self._terminal_at = None
        self._cancelled = False
        self._cancel_callback_invoked = False
        self._status = None
        self._resources.clear()
        self._counters = {
            "requests": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "runtime_seconds": 0.0,
        }
        self._inflight = BudgetReservation(requests=0)
        self._budget_reasons = ()
        self._started_monotonic = self._monotonic()
        self._last_activity = self._started_monotonic
        if self._started and (self._thread is None or not self._thread.is_alive()):
            self._start_thread_locked()

    def _start_thread_locked(self) -> None:
        self._thread = threading.Thread(
            target=self._heartbeat_loop,
            name=f"zombie-killer-{self.agent_id[:8]}",
            daemon=True,
        )
        self._thread.start()

    def _after_fork_child(self) -> None:
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread = None
        self._identity_available = False

    def _payload_locked(
        self,
        at: datetime,
        *,
        resources: list[dict[str, object]] | None = None,
    ) -> dict[str, object]:
        runtime = max(0.0, self._monotonic() - self._started_monotonic)
        self._counters["runtime_seconds"] = runtime
        return {
            "protocol_version": 1,
            "agent_id": self.agent_id,
            "registration_nonce": self.registration_nonce,
            "identity": self._identity.as_dict(),
            "heartbeat_at": _timestamp(at),
            "heartbeat_timeout_seconds": self.lease_ttl,
            "provider": self.provider,
            "project": self.project,
            "role": self.role,
            "status": self._status,
            "detached": self.detached,
            "expected_parent_pid": self.parent_pid,
            "expected_owner": self.parent_agent_id,
            "run_id": self.run_id,
            "lifecycle": self._lifecycle,
            "terminal_at": _timestamp(self._terminal_at) if self._terminal_at else None,
            "resources": list(self._resources if resources is None else resources),
            "counters": dict(self._counters),
        }

    def _publish_locked(self, at: datetime | None = None) -> bool:
        if not self._identity_available:
            if self.strict:
                raise SDKError("process identity is unavailable")
            return False
        try:
            return self._store.write_lease(
                self.agent_id, self._payload_locked(_utc(at or self._clock()))
            )
        except Exception as error:
            self._warning = type(error).__name__
            if self.strict:
                raise SDKError("Zombie Killer lease publication failed safely") from error
            return False

    def start(self) -> Agent:
        with self._lock:
            if self._closed:
                return self
            if self._started and not self._closed:
                return self
            self._ensure_process_locked()
            if self.strict and not self._identity_available:
                self._started = False
                raise SDKError("Zombie Killer registration failed safely")
            self._closed = False
            self._started = True
            self._stop.clear()
            try:
                self._publish_locked()
            except (LeaseSecurityError, SDKError) as error:
                self._started = False
                raise SDKError("Zombie Killer registration failed safely") from error
            _register_active_agent(self)
            self._start_thread_locked()
            return self

    def _heartbeat_loop(self) -> None:
        backoff = 1.0
        while not self._stop.is_set():
            jitter = (self._random() - 0.5) * min(1.0, self.heartbeat_interval * 0.1)
            delay = max(0.1, self.heartbeat_interval + jitter) if self._store.available else backoff
            if self._stop.wait(delay):
                return
            try:
                success = self._heartbeat_once()
                backoff = 1.0 if success else min(backoff * 2, 30.0)
            except Exception as error:
                with self._lock:
                    self._warning = type(error).__name__
                backoff = min(backoff * 2, 30.0)

    def _heartbeat_once(self, *, now: datetime | None = None) -> bool:
        callback: Callable[[], object] | None = None
        with self._lock:
            if self._closed:
                return False
            self._ensure_process_locked()
            observed = _utc(now or self._clock())
            request = self._store.poll_cancellation(
                self.agent_id,
                registration_nonce=self.registration_nonce,
                identity=self._identity,
                now=observed,
            )
            if request is not None:
                self._cancelled = True
                if not self._cancel_callback_invoked and self.on_cancel is not None:
                    self._cancel_callback_invoked = True
                    callback = self.on_cancel
            success = self._publish_locked(observed)
        if callback is not None:
            try:
                callback()
            except Exception as error:
                with self._lock:
                    self._warning = f"cancel-callback-{type(error).__name__}"
        return success

    def status(self, value: str) -> None:
        cleaned = _text(redact_status(value), field="status", maximum=2048)
        with self._lock:
            self._ensure_process_locked()
            self._status = cleaned
            self._last_activity = self._monotonic()
            if self._started and not self._closed:
                self._publish_locked()

    def record_usage(
        self,
        *,
        requests: int = 0,
        input_tokens: int = 0,
        output_tokens: int = 0,
        cost_usd: float | None = None,
    ) -> None:
        values = {
            "requests": requests,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
        }
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in values.values()
        ):
            raise ValueError("request and token increments must be non-negative integers")
        if cost_usd is not None and (
            isinstance(cost_usd, bool)
            or not isinstance(cost_usd, (int, float))
            or not math.isfinite(cost_usd)
            or cost_usd < 0
        ):
            raise ValueError("cost_usd must be finite and non-negative")
        with self._lock:
            self._ensure_process_locked()
            for key, value in values.items():
                self._counters[key] += value
            if cost_usd is not None:
                self._counters["cost_usd"] = self._counters.get("cost_usd", 0.0) + cost_usd
            self._last_activity = self._monotonic()
            self._budget_reasons = self._compute_budget_reasons_locked()
            if self._started and not self._closed:
                self._publish_locked()

    def track_temp(self, path: Path | str, *, root: Path | str) -> bool:
        """Declare cleanup evidence, returning whether the candidate stayed publishable."""
        resource = validate_temp_resource(path, root=root)
        with self._lock:
            self._ensure_process_locked()
            if resource in self._resources:
                return True
            if len(self._resources) >= _MAX_RESOURCES:
                raise ValueError("at most 64 temporary resources may be tracked")
            candidate_resources = [*self._resources, resource]
            try:
                candidate = self._payload_locked(_utc(self._clock()), resources=candidate_resources)
                self._store.validate_lease(candidate)
            except (TypeError, ValueError) as error:
                self._warning = "LEASE_PAYLOAD_TOO_LARGE"
                if self.strict:
                    raise SDKError("temporary resource exceeds lease bounds") from error
                return False
            self._resources.append(resource)
            if self._started and not self._closed:
                return self._publish_locked()
            return True

    def expect_listening_port(self, port: int, *, loopback: bool = True) -> None:
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65_535:
            raise ValueError("port must be an integer between 1 and 65535")
        if loopback is not True:
            raise ValueError("only loopback listening intent can be declared")
        with self._lock:
            self._counters["expected_loopback_port"] = port
            if self._started and not self._closed:
                self._publish_locked()

    def _compute_budget_reasons_locked(self) -> tuple[str, ...]:
        reasons: list[str] = []
        requests = self._counters["requests"] + self._inflight.requests
        if self._max_requests is not None and requests >= self._max_requests:
            reasons.append("max_requests")
        tokens = (
            self._counters["input_tokens"]
            + self._counters["output_tokens"]
            + self._inflight.input_tokens
            + self._inflight.output_tokens
        )
        if self._max_tokens is not None and tokens >= self._max_tokens:
            reasons.append("max_tokens")
        elapsed = (
            max(0.0, self._monotonic() - self._started_monotonic) + self._inflight.runtime_seconds
        )
        if self._max_runtime is not None and elapsed >= self._max_runtime:
            reasons.append("max_runtime_seconds")
        idle = max(0.0, self._monotonic() - self._last_activity)
        if self._max_idle is not None and idle >= self._max_idle:
            reasons.append("max_idle_seconds")
        rss = _rss_bytes() if self._max_rss is not None else None
        if self._max_rss is not None and rss is not None and rss >= self._max_rss:
            reasons.append("max_rss_bytes")
        self._budget_reasons = tuple(reasons)
        for key in tuple(self._counters):
            if key == "budget_exceeded" or key.startswith("budget_max_"):
                del self._counters[key]
        if reasons:
            self._counters["budget_exceeded"] = 1
            for reason in reasons:
                self._counters[f"budget_{reason}"] = 1
        return self._budget_reasons

    def _reservation_reasons_locked(self, reservation: BudgetReservation) -> tuple[str, ...]:
        reasons: list[str] = []
        requests = self._counters["requests"] + self._inflight.requests + reservation.requests
        if self._max_requests is not None and requests > self._max_requests:
            reasons.append("max_requests")
        tokens = (
            self._counters["input_tokens"]
            + self._counters["output_tokens"]
            + self._inflight.input_tokens
            + self._inflight.output_tokens
            + reservation.input_tokens
            + reservation.output_tokens
        )
        if self._max_tokens is not None and tokens > self._max_tokens:
            reasons.append("max_tokens")
        runtime = (
            max(0.0, self._monotonic() - self._started_monotonic)
            + self._inflight.runtime_seconds
            + reservation.runtime_seconds
        )
        if self._max_runtime is not None and runtime > self._max_runtime:
            reasons.append("max_runtime_seconds")
        idle = max(0.0, self._monotonic() - self._last_activity)
        if self._max_idle is not None and idle >= self._max_idle:
            reasons.append("max_idle_seconds")
        rss = _rss_bytes() if self._max_rss is not None else None
        if self._max_rss is not None and rss is not None and rss >= self._max_rss:
            reasons.append("max_rss_bytes")
        return tuple(reasons)

    def _adjust_inflight_locked(self, reservation: BudgetReservation, *, add: bool) -> None:
        direction = 1 if add else -1
        current_cost = self._inflight.cost_usd or 0.0
        reserved_cost = reservation.cost_usd or 0.0
        self._inflight = BudgetReservation(
            requests=self._inflight.requests + direction * reservation.requests,
            input_tokens=self._inflight.input_tokens + direction * reservation.input_tokens,
            output_tokens=self._inflight.output_tokens + direction * reservation.output_tokens,
            cost_usd=max(0.0, current_cost + direction * reserved_cost),
            runtime_seconds=self._inflight.runtime_seconds
            + direction * reservation.runtime_seconds,
        )

    def _commit_reservation_locked(self, reservation: BudgetReservation) -> None:
        self._counters["requests"] += reservation.requests
        self._counters["input_tokens"] += reservation.input_tokens
        self._counters["output_tokens"] += reservation.output_tokens
        if reservation.cost_usd is not None:
            self._counters["cost_usd"] = self._counters.get("cost_usd", 0.0) + reservation.cost_usd
        self._last_activity = self._monotonic()

    def check_budget(self) -> None:
        with self._lock:
            reasons = self._compute_budget_reasons_locked()
            if reasons:
                if self._started and not self._closed:
                    self._publish_locked()
                raise BudgetExceeded(reasons)

    def before_request(
        self,
        callback: Callable[..., _T] | None = None,
        /,
        *args: object,
        reservation: BudgetReservation | None = None,
        **kwargs: object,
    ) -> _T | None:
        """Reserve capacity and commit it only after a successful callback.

        The default reservation accounts for one request. Pass a ``BudgetReservation``
        for token, cost, or concurrent runtime capacity. A callback exception releases
        the reservation without changing usage counters. With no callback, capacity is
        reserved and committed immediately for callers that perform the action themselves.
        """
        requested = reservation or BudgetReservation()
        with self._lock:
            self._ensure_process_locked()
            reasons = self._reservation_reasons_locked(requested)
            if reasons:
                self._budget_reasons = reasons
                self._compute_budget_reasons_locked()
                if self._started and not self._closed:
                    self._publish_locked()
                raise BudgetExceeded(reasons)
            self._adjust_inflight_locked(requested, add=True)
        if callback is None:
            with self._lock:
                self._adjust_inflight_locked(requested, add=False)
                self._commit_reservation_locked(requested)
                if self._started and not self._closed:
                    self._publish_locked()
            return None
        try:
            result = callback(*args, **kwargs)
        except BaseException:
            with self._lock:
                self._adjust_inflight_locked(requested, add=False)
            raise
        with self._lock:
            self._adjust_inflight_locked(requested, add=False)
            self._commit_reservation_locked(requested)
            if self._started and not self._closed:
                self._publish_locked()
        return result

    def close(self, result: LifecycleResult = "completed") -> None:
        if result not in _RESULTS:
            raise ValueError("result must be completed, failed, or cancelled")
        thread: threading.Thread | None
        failure: SDKError | None = None
        with self._lock:
            if self._closed:
                return
            self._ensure_process_locked()
            self._lifecycle = result
            self._terminal_at = _utc(self._clock())
            try:
                if self._started:
                    self._publish_locked(self._terminal_at)
            except SDKError as error:
                failure = error
                self._warning = type(error).__name__
            self._closed = True
            self._started = False
            self._stop.set()
            thread = self._thread
            _discard_active_agent(self)
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=min(2.0, self.heartbeat_interval + 0.25))
        if failure is not None:
            raise failure

    def __enter__(self) -> Agent:
        return self.start()

    def __exit__(self, exc_type: object, exc: BaseException | None, traceback: object) -> None:
        result: LifecycleResult
        if isinstance(exc, asyncio.CancelledError):
            result = "cancelled"
        else:
            result = "failed" if exc is not None else "cancelled" if self.cancelled else "completed"
        self.close(result=result)

    async def __aenter__(self) -> Agent:
        startup = asyncio.create_task(asyncio.to_thread(self.start))
        try:
            return await asyncio.shield(startup)
        except asyncio.CancelledError:

            async def finish_cancelled_start() -> None:
                with suppress(Exception, asyncio.CancelledError):
                    await startup
                with suppress(SDKError):
                    await asyncio.to_thread(self.close, result="cancelled")

            cleanup = asyncio.create_task(finish_cancelled_start())
            # Repeated cancellation must not leave the startup worker registered.
            while not cleanup.done():
                with suppress(asyncio.CancelledError):
                    await asyncio.shield(cleanup)
            cleanup.result()
            raise

    async def __aexit__(
        self, exc_type: object, exc: BaseException | None, traceback: object
    ) -> None:
        await asyncio.to_thread(self.__exit__, exc_type, exc, traceback)


def register(
    *,
    provider: str,
    project: str,
    role: str,
    state_dir: Path | str | None = None,
    agent_id: str | uuid.UUID | None = None,
    run_id: str | uuid.UUID | None = None,
    heartbeat_interval: float = 10.0,
    lease_ttl: float | None = None,
    detached: bool = False,
    survive_parent: bool = False,
    parent_pid: int | None = None,
    parent_identity: ProcessIdentity | None = None,
    parent_agent_id: str | uuid.UUID | None = None,
    strict: bool = False,
    on_cancel: Callable[[], object] | None = None,
    max_requests: int | None = None,
    max_tokens: int | None = None,
    max_runtime_seconds: float | None = None,
    max_idle_seconds: float | None = None,
    max_rss_bytes: int | None = None,
    _clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    _monotonic: Callable[[], float] = time.monotonic,
    _random: Callable[[], float] = random.random,
    _identity_provider: Callable[[], ProcessIdentity] = current_process_identity,
    _nonce_factory: Callable[[], str] = secure_random_nonce,
    _uuid_factory: Callable[[], uuid.UUID | str] = uuid.uuid4,
) -> Agent:
    """Construct and immediately start an :class:`Agent`."""
    return Agent(
        provider=provider,
        project=project,
        role=role,
        state_dir=state_dir,
        agent_id=agent_id,
        run_id=run_id,
        heartbeat_interval=heartbeat_interval,
        lease_ttl=lease_ttl,
        detached=detached,
        survive_parent=survive_parent,
        parent_pid=parent_pid,
        parent_identity=parent_identity,
        parent_agent_id=parent_agent_id,
        strict=strict,
        on_cancel=on_cancel,
        max_requests=max_requests,
        max_tokens=max_tokens,
        max_runtime_seconds=max_runtime_seconds,
        max_idle_seconds=max_idle_seconds,
        max_rss_bytes=max_rss_bytes,
        _clock=_clock,
        _monotonic=_monotonic,
        _random=_random,
        _identity_provider=_identity_provider,
        _nonce_factory=_nonce_factory,
        _uuid_factory=_uuid_factory,
    ).start()


__all__ = ["Agent", "BudgetExceeded", "BudgetReservation", "SDKError", "register"]
