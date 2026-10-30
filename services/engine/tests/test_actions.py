from __future__ import annotations

import hashlib
import importlib
import inspect
import json
import os
import secrets
import signal
import sqlite3
import subprocess
import sys
import sysconfig
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from zombie_killer_engine.actions import (
    ActionExecutor,
    ActionMode,
    ActionPlan,
    ActionPlanner,
    ActionResult,
    PlanRejectedError,
    ProcessAccessDenied,
    ProcessDisappeared,
    ProcessIdentityMismatch,
    PsutilProcessController,
    StableBindingUnavailable,
    cancellation_path,
    process_instance_id,
    same_process_instance,
)
from zombie_killer_engine.leases import LEASE_PROTOCOL_VERSION, observe_cancellation_request
from zombie_killer_engine.models import (
    AgentState,
    Classification,
    Evidence,
    EvidenceGrade,
    ProcessIdentity,
)
from zombie_killer_engine.paths import AppPaths
from zombie_killer_engine.scanner import ProcessDetails, ScanCoverage, ScannedAgent, ScanResult
from zombie_killer_engine.service import (
    PROTOCOL_VERSION,
    Capability,
    ClientKind,
    Method,
    RequestContext,
    RequestEnvelope,
    build_default_service,
)
from zombie_killer_engine.store import ExpiredPlanError, PlanClaimError, SQLiteStateStore

NOW = datetime(2026, 8, 12, 12, 0, tzinfo=UTC)
SECRET_SHAPED_EXECUTABLE = r"c:\tools\api_key=synthetic\python.exe"
JWT_SHAPED_EXECUTABLE = (
    "c:\\tools\\"
    + ".".join(
        (
            "ey" + "JhbGciOiJIUzI1NiJ9",
            "ey" + "JzdWIiOiJzeW50aGV0aWMifQ",
            "signature00",
        )
    )
    + "\\python.exe"
)
LONG_WINDOWS_EXECUTABLE = "c:\\" + "a" * 4_100 + r"\python.exe"


def fixture_python_environment() -> tuple[str, dict[str, str]]:
    executable = str(getattr(sys, "_base_executable", sys.executable))
    environment = os.environ.copy()
    site_packages = sysconfig.get_paths()["purelib"]
    existing = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        site_packages if not existing else site_packages + os.pathsep + existing
    )
    return executable, environment


def paths(tmp_path: Path) -> AppPaths:
    return AppPaths(
        data_dir=tmp_path / "data",
        state_dir=tmp_path / "state",
        runtime_dir=tmp_path / "runtime",
        backups_dir=tmp_path / "backups",
        graveyard_dir=tmp_path / "graveyard",
    )


def write_managed_lease(
    app_paths: AppPaths,
    target: ProcessIdentity,
    *,
    agent_id: str,
) -> None:
    app_paths.leases_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "protocol_version": LEASE_PROTOCOL_VERSION,
        "agent_id": agent_id,
        "registration_nonce": "scanner-action-registration",
        "identity": {
            "boot_id": target.boot_id,
            "pid": target.pid,
            "create_time": target.create_time,
            "executable": target.executable,
            "user": target.user,
        },
        "heartbeat_at": NOW.isoformat().replace("+00:00", "Z"),
        "heartbeat_timeout_seconds": 30.0,
        "provider": "custom",
        "project": "Scanner action identity",
        "role": "test fixture",
        "status": "Running synthetic local fixture",
        "detached": True,
        "expected_parent_pid": None,
        "expected_owner": None,
        "run_id": "scanner-action-run",
        "lifecycle": "running",
        "terminal_at": None,
        "resources": [],
        "counters": {},
    }
    (app_paths.leases_dir / f"{agent_id}.json").write_text(
        json.dumps(payload),
        encoding="utf-8",
    )


def identity(
    *,
    pid: int = 4242,
    boot_id: str = "synthetic-boot",
    create_time: float = 1_765_000_000.25,
    executable: str | None = "/synthetic/python",
    user: str | None = "synthetic-user",
) -> ProcessIdentity:
    return ProcessIdentity(
        boot_id=boot_id,
        pid=pid,
        create_time=create_time,
        executable=executable,
        user=user,
        executable_hash=(
            hashlib.sha256(executable.encode()).hexdigest() if executable is not None else None
        ),
        user_hash=(hashlib.sha256(user.encode()).hexdigest() if user is not None else None),
    )


def scanned_agent(
    target: ProcessIdentity,
    *,
    state: AgentState = AgentState.STALE,
    actionable: bool = True,
    managed: bool = True,
    name: str = "synthetic-agent",
) -> ScannedAgent:
    return ScannedAgent(
        agent_id="synthetic-agent" if managed else None,
        registration_nonce="synthetic-registration-1" if managed else None,
        lease_matched=managed,
        actionable=actionable,
        process=ProcessDetails(
            identity=target,
            observed_at=NOW,
            ppid=100,
            name=name,
            status="running",
            cmdline=(),
        ),
        classification=Classification(
            state=state,
            evidence_grade=EvidenceGrade.CONFIRMED,
            confidence=0.99,
            reason_codes=("SYNTHETIC",),
            explanation="Synthetic action-planning classification.",
            evidence=(
                Evidence(
                    code="SYNTHETIC",
                    grade=EvidenceGrade.CONFIRMED,
                    observed_at=NOW,
                    detail="Synthetic action-planning evidence.",
                ),
            ),
            classified_at=NOW,
        ),
    )


class FakeController:
    stable_binding_kind = "pidfd"

    def __init__(self, target: ProcessIdentity) -> None:
        self.target = target
        self.boot_id = target.boot_id
        self.alive = True
        self.deny = False
        self.terminate_calls: list[ProcessIdentity] = []
        self.kill_calls: list[ProcessIdentity] = []
        self.bind_calls: list[ProcessIdentity] = []
        self._lock = threading.Lock()

    def current_boot_id(self) -> str:
        return self.boot_id

    def current_user_hash(self) -> str:
        return hashlib.sha256(b"synthetic-user").hexdigest()

    def read_identity(self, pid: int) -> ProcessIdentity:
        if self.deny:
            raise ProcessAccessDenied(pid)
        if not self.alive or pid != self.target.pid:
            raise ProcessDisappeared(pid)
        return self.target

    def bind(self, expected: ProcessIdentity) -> FakeProcessReference:
        with self._lock:
            if not same_process_instance(
                expected,
                self.target,
                current_boot_id=self.boot_id,
                platform_name="linux",
            ):
                raise ProcessIdentityMismatch(expected.pid)
            self.bind_calls.append(expected)
            return FakeProcessReference(self, expected)

    def terminate(self, expected: int | ProcessIdentity) -> FakeProcessReference:
        with self._lock:
            if isinstance(expected, ProcessIdentity) and not same_process_instance(
                expected,
                self.target,
                current_boot_id=self.boot_id,
                platform_name="linux",
            ):
                raise ProcessIdentityMismatch(expected.pid)
            recorded = expected if isinstance(expected, ProcessIdentity) else self.target
            self.terminate_calls.append(recorded)
            self.alive = False
            return FakeProcessReference(self)

    def kill(self, expected: int | ProcessIdentity) -> FakeProcessReference:
        with self._lock:
            if isinstance(expected, ProcessIdentity) and not same_process_instance(
                expected,
                self.target,
                current_boot_id=self.boot_id,
                platform_name="linux",
            ):
                raise ProcessIdentityMismatch(expected.pid)
            recorded = expected if isinstance(expected, ProcessIdentity) else self.target
            self.kill_calls.append(recorded)
            self.alive = False
            return FakeProcessReference(self)


class ServiceProcessReference:
    def __init__(self, controller: ServiceController, bound_identity: ProcessIdentity) -> None:
        self._controller = controller
        self._bound_identity = bound_identity

    def validate(self, expected: ProcessIdentity) -> None:
        if not same_process_instance(
            expected,
            self._bound_identity,
            current_boot_id=self._controller.boot_id,
            platform_name="linux",
        ):
            raise ProcessIdentityMismatch(expected.pid)

    def is_running(self) -> bool:
        return True

    def close(self) -> None:
        self._controller.probe_close_calls += 1


class ServiceController(FakeController):
    """Expose the service process identity separately from the synthetic target."""

    def __init__(self, target: ProcessIdentity) -> None:
        super().__init__(target)
        self.current_identity = identity(pid=os.getpid())
        self.probe_bind_calls: list[ProcessIdentity] = []
        self.probe_close_calls = 0

    def read_identity(self, pid: int) -> ProcessIdentity:
        if pid == self.current_identity.pid:
            return self.current_identity
        return super().read_identity(pid)

    def bind(self, expected: ProcessIdentity) -> FakeProcessReference | ServiceProcessReference:
        if expected.pid == self.current_identity.pid:
            self.probe_bind_calls.append(expected)
            return ServiceProcessReference(self, expected)
        return super().bind(expected)


def scan_with(candidate: ScannedAgent) -> ScanResult:
    return ScanResult(
        agents=(candidate,),
        coverage=ScanCoverage(
            inspected_count=1,
            denied_count=0,
            vanished_count=0,
            malformed_lease_count=0,
            lease_file_count=1,
            skipped_lease_count=0,
            other_user_count=0,
            unknown_owner_count=0,
            identity_denied_count=0,
            complete=True,
            captured_at=NOW,
            current_boot_id=candidate.process.identity.boot_id,
            warnings=(),
        ),
    )


def planning_context() -> RequestContext:
    return RequestContext(
        client=ClientKind.CONTROLLER,
        capability=Capability.PLANNING,
        local_control=True,
    )


def test_scan_exposes_opaque_process_instance_binding(
    tmp_path: Path, request: pytest.FixtureRequest
) -> None:
    target = identity()
    controller = ServiceController(target)
    service = build_default_service(
        paths=paths(tmp_path),
        scanner=lambda: scan_with(scanned_agent(target)),
        controller=controller,
    )
    request.addfinalizer(lambda: getattr(service, "close", lambda: None)())

    response = service.dispatch(
        RequestEnvelope(
            protocol_version=PROTOCOL_VERSION,
            request_id=uuid4(),
            method=Method.SCAN_LIST.value,
            payload={},
        ),
        context=planning_context(),
    )

    assert response.ok is True
    assert response.result is not None
    projected = response.result.model_dump(mode="json")["agents"][0]
    assert projected["pid"] == target.pid
    assert len(projected["process_instance_id"]) == 64
    assert target.create_time.hex() not in projected["process_instance_id"]


def test_agent_detail_enforces_the_displayed_process_instance_binding(
    tmp_path: Path, request: pytest.FixtureRequest
) -> None:
    target = identity()
    service = build_default_service(
        paths=paths(tmp_path),
        scanner=lambda: scan_with(scanned_agent(target)),
    )
    request.addfinalizer(lambda: getattr(service, "close", lambda: None)())
    scan = service.dispatch(
        RequestEnvelope(
            protocol_version=PROTOCOL_VERSION,
            request_id=uuid4(),
            method=Method.SCAN_LIST.value,
            payload={},
        ),
        context=planning_context(),
    )
    assert scan.result is not None
    displayed = scan.result.model_dump(mode="json")["agents"][0]

    changed = service.dispatch(
        RequestEnvelope(
            protocol_version=PROTOCOL_VERSION,
            request_id=uuid4(),
            method=Method.AGENT_DETAIL.value,
            payload={
                "agent_id": displayed["agent_id"],
                "expected_pid": displayed["pid"],
                "expected_process_instance_id": "f" * 64,
            },
        ),
        context=planning_context(),
    )
    assert changed.ok is False
    assert changed.error is not None
    assert changed.error.code.value == "target_changed"

    exact = service.dispatch(
        RequestEnvelope(
            protocol_version=PROTOCOL_VERSION,
            request_id=uuid4(),
            method=Method.AGENT_DETAIL.value,
            payload={
                "agent_id": displayed["agent_id"],
                "expected_pid": displayed["pid"],
                "expected_process_instance_id": displayed["process_instance_id"],
            },
        ),
        context=planning_context(),
    )
    assert exact.ok is True
    assert exact.result is not None
    assert (
        exact.result.model_dump(mode="json")["process_instance_id"]
        == displayed["process_instance_id"]
    )


def test_action_plan_requires_and_returns_authoritative_target(
    tmp_path: Path, request: pytest.FixtureRequest
) -> None:
    target = identity()
    controller = ServiceController(target)
    service = build_default_service(
        paths=paths(tmp_path),
        scanner=lambda: scan_with(scanned_agent(target)),
        controller=controller,
    )
    request.addfinalizer(lambda: getattr(service, "close", lambda: None)())
    scan = service.dispatch(
        RequestEnvelope(
            protocol_version=PROTOCOL_VERSION,
            request_id=uuid4(),
            method=Method.SCAN_LIST.value,
            payload={},
        ),
        context=planning_context(),
    )
    assert scan.result is not None
    scanned_target = scan.result.model_dump(mode="json")["agents"][0]

    response = service.dispatch(
        RequestEnvelope(
            protocol_version=PROTOCOL_VERSION,
            request_id=uuid4(),
            method=Method.ACTION_PLAN.value,
            payload={
                "agent_id": "synthetic-agent",
                "mode": "terminate",
                "target": {
                    "pid": scanned_target["pid"],
                    "process_instance_id": scanned_target["process_instance_id"],
                },
            },
        ),
        context=planning_context(),
    )

    assert response.ok is True
    assert response.result is not None
    authoritative = response.result.model_dump(mode="json")["target"]
    assert authoritative == {
        "pid": target.pid,
        "process_instance_id": scanned_target["process_instance_id"],
        "state": "stale",
    }


def test_default_service_disables_action_methods_without_stable_kernel_binding(
    tmp_path: Path, request: pytest.FixtureRequest
) -> None:
    class UnsupportedController(ServiceController):
        stable_binding_kind = "unsupported"

    target = identity()
    controller = UnsupportedController(target)
    service = build_default_service(
        paths=paths(tmp_path),
        scanner=lambda: scan_with(scanned_agent(target)),
        controller=controller,
    )
    request.addfinalizer(lambda: getattr(service, "close", lambda: None)())
    doctor = service.dispatch(
        RequestEnvelope(
            protocol_version=PROTOCOL_VERSION,
            request_id=uuid4(),
            method=Method.DOCTOR.value,
            payload={},
        ),
        context=planning_context(),
    )

    assert doctor.ok is True
    assert doctor.result is not None
    doctor_result = doctor.result.model_dump(mode="json")
    checks = {check["name"]: check["ok"] for check in doctor_result["checks"]}
    assert checks["method:action.plan"] is False
    assert checks["method:action.execute"] is False
    assert "Unavailable capability: action.plan." in doctor_result["warnings"]
    assert "Unavailable capability: action.execute." in doctor_result["warnings"]

    plan = service.dispatch(
        RequestEnvelope(
            protocol_version=PROTOCOL_VERSION,
            request_id=uuid4(),
            method=Method.ACTION_PLAN.value,
            payload={
                "agent_id": "synthetic-agent",
                "mode": "terminate",
                "target": {
                    "pid": target.pid,
                    "process_instance_id": process_instance_id(target),
                },
            },
        ),
        context=planning_context(),
    )
    execute = service.dispatch(
        RequestEnvelope(
            protocol_version=PROTOCOL_VERSION,
            request_id=uuid4(),
            method=Method.ACTION_EXECUTE.value,
            payload={"plan_id": "plan-unsupported", "digest": "a" * 64},
        ),
        context=RequestContext(
            client=ClientKind.CONTROLLER,
            capability=Capability.EXECUTION,
            local_control=True,
        ),
    )

    assert plan.error is not None
    assert plan.error.code.value == "unsupported"
    assert execute.error is not None
    assert execute.error.code.value == "unsupported"
    assert controller.probe_bind_calls == []


@pytest.mark.parametrize(
    "failure_type",
    [StableBindingUnavailable, ProcessAccessDenied, OSError],
    ids=["runtime-syscall-unavailable", "runtime-binding-denied", "runtime-syscall-error"],
)
def test_default_service_disables_actions_when_stable_binding_probe_fails(
    tmp_path: Path,
    request: pytest.FixtureRequest,
    failure_type: type[Exception],
) -> None:
    class ProbeFailureController(ServiceController):
        def bind(self, expected: ProcessIdentity) -> FakeProcessReference | ServiceProcessReference:
            if expected.pid == self.current_identity.pid:
                self.probe_bind_calls.append(expected)
                raise failure_type(expected.pid)
            return super().bind(expected)

    target = identity()
    controller = ProbeFailureController(target)
    service = build_default_service(
        paths=paths(tmp_path),
        scanner=lambda: scan_with(scanned_agent(target)),
        controller=controller,
    )
    request.addfinalizer(lambda: getattr(service, "close", lambda: None)())

    doctor = service.dispatch(
        RequestEnvelope(
            protocol_version=PROTOCOL_VERSION,
            request_id=uuid4(),
            method=Method.DOCTOR.value,
            payload={},
        ),
        context=planning_context(),
    )

    assert doctor.ok is True
    assert doctor.result is not None
    checks = {
        check["name"]: check["ok"] for check in doctor.result.model_dump(mode="json")["checks"]
    }
    assert checks["method:action.plan"] is False
    assert checks["method:action.execute"] is False
    assert controller.probe_bind_calls == [controller.current_identity]
    assert controller.probe_close_calls == 0


def test_default_service_probes_and_closes_stable_binding_before_enabling_actions(
    tmp_path: Path,
    request: pytest.FixtureRequest,
) -> None:
    target = identity()
    controller = ServiceController(target)
    service = build_default_service(
        paths=paths(tmp_path),
        scanner=lambda: scan_with(scanned_agent(target)),
        controller=controller,
    )
    request.addfinalizer(lambda: getattr(service, "close", lambda: None)())

    doctor = service.dispatch(
        RequestEnvelope(
            protocol_version=PROTOCOL_VERSION,
            request_id=uuid4(),
            method=Method.DOCTOR.value,
            payload={},
        ),
        context=planning_context(),
    )

    assert doctor.ok is True
    assert doctor.result is not None
    checks = {
        check["name"]: check["ok"] for check in doctor.result.model_dump(mode="json")["checks"]
    }
    assert checks["method:action.plan"] is True
    assert checks["method:action.execute"] is True
    assert controller.probe_bind_calls == [controller.current_identity]
    assert controller.probe_close_calls == 1


def test_default_service_does_not_hide_unexpected_stable_binding_probe_failure(
    tmp_path: Path,
) -> None:
    class UnexpectedProbeFailureController(ServiceController):
        def bind(self, expected: ProcessIdentity) -> FakeProcessReference | ServiceProcessReference:
            if expected.pid == self.current_identity.pid:
                raise RuntimeError("synthetic unexpected probe failure")
            return super().bind(expected)

    target = identity()
    with pytest.raises(RuntimeError, match="synthetic unexpected probe failure"):
        build_default_service(
            paths=paths(tmp_path),
            scanner=lambda: scan_with(scanned_agent(target)),
            controller=UnexpectedProbeFailureController(target),
        )


def test_default_service_plans_live_sdk_agent_from_production_scanner(
    tmp_path: Path,
) -> None:
    fixture = Path(__file__).parent / "fixtures" / "sdk_agent.py"
    fixture_python, fixture_env = fixture_python_environment()
    app_paths = paths(tmp_path)
    agent_id = str(uuid4())
    target = subprocess.Popen(
        [
            fixture_python,
            str(fixture),
            "--runtime-dir",
            str(app_paths.runtime_dir),
            "--agent-id",
            agent_id,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=fixture_env,
    )
    service = None
    try:
        lease_path = app_paths.leases_dir / f"{agent_id}.json"
        deadline = time.monotonic() + 5
        while not lease_path.is_file() and time.monotonic() < deadline:
            if target.poll() is not None:
                pytest.fail("SDK fixture exited before publishing its lease")
            time.sleep(0.02)
        assert lease_path.is_file()

        service = build_default_service(paths=app_paths)
        scanned = service.dispatch(
            RequestEnvelope(
                protocol_version=PROTOCOL_VERSION,
                request_id=uuid4(),
                method=Method.SCAN_LIST.value,
                payload={},
            ),
            context=planning_context(),
        )
        assert scanned.ok is True
        assert scanned.result is not None
        candidate = next(
            agent
            for agent in scanned.result.model_dump(mode="json")["agents"]
            if agent["agent_id"] == agent_id
        )
        assert candidate["actionable"] is True

        planned = service.dispatch(
            RequestEnvelope(
                protocol_version=PROTOCOL_VERSION,
                request_id=uuid4(),
                method=Method.ACTION_PLAN.value,
                payload={
                    "agent_id": agent_id,
                    "mode": "terminate",
                    "target": {
                        "pid": candidate["pid"],
                        "process_instance_id": candidate["process_instance_id"],
                    },
                },
            ),
            context=planning_context(),
        )

        assert planned.ok is True
        assert planned.result is not None
        assert planned.result.model_dump(mode="json")["target"] == {
            "pid": candidate["pid"],
            "process_instance_id": candidate["process_instance_id"],
            "state": candidate["state"],
        }
    finally:
        if service is not None:
            service.close()
        _stop_fixture(target)


@pytest.mark.parametrize(
    "raw_executable",
    [SECRET_SHAPED_EXECUTABLE, JWT_SHAPED_EXECUTABLE, LONG_WINDOWS_EXECUTABLE],
    ids=["named-secret", "jwt-shaped", "longer-than-display-bound"],
)
def test_default_service_plans_redacted_production_scanner_executable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    raw_executable: str,
) -> None:
    import zombie_killer_engine.scanner as scanner_module

    class FakeMemory:
        rss = 1

    target = identity(executable=raw_executable).model_copy(
        update={
            "executable_hash": hashlib.sha256(raw_executable.casefold().encode("utf-8")).hexdigest()
        }
    )

    class FakeProcess:
        info: dict[str, object] = {
            "pid": target.pid,
            "ppid": 1,
            "create_time": target.create_time,
            "name": "python",
            "exe": raw_executable,
            "username": target.user,
            "status": "running",
            "cpu_percent": 0.0,
            "memory_info": FakeMemory(),
            "cmdline": ["python", "fixture.py"],
        }

    monkeypatch.setattr(
        scanner_module.psutil,
        "process_iter",
        lambda **_kwargs: iter((FakeProcess(),)),
    )
    app_paths = paths(tmp_path)
    agent_id = "scanner-action-agent"
    write_managed_lease(app_paths, target, agent_id=agent_id)

    def production_scan() -> ScanResult:
        return scanner_module.scan_agents(
            app_paths.leases_dir,
            process_provider=scanner_module.PsutilProcessProvider(platform_name="windows"),
            identity_fingerprint_provider=lambda _pid, _user, _platform: target.user_hash,
            current_boot=target.boot_id,
            current_user=target.user,
            platform_name="windows",
            captured_at=NOW,
        )

    scanned = production_scan()
    candidate = next(agent for agent in scanned.agents if agent.agent_id == agent_id)
    assert candidate.lease_matched is True
    assert candidate.actionable is True
    assert candidate.process is not None
    assert candidate.process.identity is not None
    assert candidate.process.identity.executable != raw_executable
    serialized_scan = scanned.model_dump_json()
    assert raw_executable not in serialized_scan
    if "api_key=" in raw_executable:
        assert "api_key=synthetic" not in serialized_scan
    if "\\eyJ" in raw_executable:
        assert "eyJ" not in serialized_scan

    service = build_default_service(
        paths=app_paths,
        scanner=production_scan,
        controller=ServiceController(target),
    )
    try:
        listed = service.dispatch(
            RequestEnvelope(
                protocol_version=PROTOCOL_VERSION,
                request_id=uuid4(),
                method=Method.SCAN_LIST.value,
                payload={},
            ),
            context=planning_context(),
        )
        assert listed.ok is True
        assert listed.result is not None
        displayed = next(
            agent
            for agent in listed.result.model_dump(mode="json")["agents"]
            if agent["agent_id"] == agent_id
        )
        planned = service.dispatch(
            RequestEnvelope(
                protocol_version=PROTOCOL_VERSION,
                request_id=uuid4(),
                method=Method.ACTION_PLAN.value,
                payload={
                    "agent_id": agent_id,
                    "mode": "terminate",
                    "target": {
                        "pid": displayed["pid"],
                        "process_instance_id": displayed["process_instance_id"],
                    },
                },
            ),
            context=planning_context(),
        )
        assert planned.ok is True
    finally:
        service.close()


def test_action_plan_rejects_same_agent_restart_as_target_changed(
    tmp_path: Path, request: pytest.FixtureRequest
) -> None:
    current = [identity()]
    controller = ServiceController(current[0])
    service = build_default_service(
        paths=paths(tmp_path),
        scanner=lambda: scan_with(scanned_agent(current[0])),
        controller=controller,
    )
    request.addfinalizer(lambda: getattr(service, "close", lambda: None)())
    scan = service.dispatch(
        RequestEnvelope(
            protocol_version=PROTOCOL_VERSION,
            request_id=uuid4(),
            method=Method.SCAN_LIST.value,
            payload={},
        ),
        context=planning_context(),
    )
    assert scan.result is not None
    old_target = scan.result.model_dump(mode="json")["agents"][0]
    current[0] = current[0].model_copy(
        update={"pid": current[0].pid + 1, "create_time": current[0].create_time + 1}
    )
    controller.target = current[0]

    response = service.dispatch(
        RequestEnvelope(
            protocol_version=PROTOCOL_VERSION,
            request_id=uuid4(),
            method=Method.ACTION_PLAN.value,
            payload={
                "agent_id": "synthetic-agent",
                "mode": "terminate",
                "target": {
                    "pid": old_target["pid"],
                    "process_instance_id": old_target["process_instance_id"],
                },
            },
        ),
        context=planning_context(),
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.code.value == "target_changed"
    assert response.error.details == {"reason": "process_instance_changed"}


def test_action_plan_rejects_same_pid_reuse_as_target_changed(
    tmp_path: Path, request: pytest.FixtureRequest
) -> None:
    current = [identity()]
    controller = ServiceController(current[0])
    service = build_default_service(
        paths=paths(tmp_path),
        scanner=lambda: scan_with(scanned_agent(current[0])),
        controller=controller,
    )
    request.addfinalizer(lambda: getattr(service, "close", lambda: None)())
    scan = service.dispatch(
        RequestEnvelope(
            protocol_version=PROTOCOL_VERSION,
            request_id=uuid4(),
            method=Method.SCAN_LIST.value,
            payload={},
        ),
        context=planning_context(),
    )
    assert scan.result is not None
    old_target = scan.result.model_dump(mode="json")["agents"][0]
    current[0] = current[0].model_copy(update={"create_time": current[0].create_time + 1})
    controller.target = current[0]

    response = service.dispatch(
        RequestEnvelope(
            protocol_version=PROTOCOL_VERSION,
            request_id=uuid4(),
            method=Method.ACTION_PLAN.value,
            payload={
                "agent_id": "synthetic-agent",
                "mode": "terminate",
                "target": {
                    "pid": old_target["pid"],
                    "process_instance_id": old_target["process_instance_id"],
                },
            },
        ),
        context=planning_context(),
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.code.value == "target_changed"
    assert response.error.details == {"reason": "process_instance_changed"}


class FakeProcessReference:
    def __init__(
        self,
        controller: FakeController,
        identity: ProcessIdentity | None = None,
    ) -> None:
        self._controller = controller
        self._identity = identity or controller.target

    def validate(self, expected: ProcessIdentity) -> None:
        if not self._controller.alive:
            raise ProcessDisappeared(expected.pid)
        if not same_process_instance(
            expected,
            self._controller.target,
            current_boot_id=self._controller.boot_id,
            platform_name="linux",
        ) or not same_process_instance(
            self._identity,
            self._controller.target,
            current_boot_id=self._controller.boot_id,
            platform_name="linux",
        ):
            raise ProcessIdentityMismatch(expected.pid)

    def is_running(self) -> bool:
        return self._controller.alive

    def close(self) -> None:
        pass


class FakeClock:
    def __init__(self) -> None:
        self.value = 0.0

    def monotonic(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.value += seconds


class MutableUtcClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


def planner(
    controller: FakeController,
    *,
    protected_identities: tuple[ProcessIdentity, ...] = (),
) -> ActionPlanner:
    return ActionPlanner(
        controller,
        current_user="synthetic-user",
        current_pid=9000,
        parent_pid=8999,
        platform_name="linux",
        protected_identities=protected_identities,
    )


@pytest.mark.parametrize(
    "state",
    [
        AgentState.UNKNOWN,
        AgentState.DEFUNCT,
        AgentState.COMPLETED,
        AgentState.FAILED,
        AgentState.CANCELLED,
    ],
)
def test_planning_rejects_unknown_defunct_and_terminal_records(state: AgentState) -> None:
    target = identity()
    controller = FakeController(target)

    with pytest.raises(PlanRejectedError):
        planner(controller).create_plan(
            scanned_agent(target, state=state, actionable=False),
            mode=ActionMode.TERMINATE,
            now=NOW,
        )

    assert controller.terminate_calls == []


def test_planning_rejects_nonactionable_managed_record() -> None:
    target = identity()
    with pytest.raises(PlanRejectedError, match="actionable"):
        planner(FakeController(target)).create_plan(
            scanned_agent(target, actionable=False),
            mode=ActionMode.TERMINATE,
            now=NOW,
        )


@pytest.mark.parametrize("pid", [1, 2, 3, 4, 8999, 9000])
def test_planning_protects_system_current_and_parent_processes(pid: int) -> None:
    target = identity(pid=pid)
    with pytest.raises(PlanRejectedError):
        planner(FakeController(target)).create_plan(
            scanned_agent(target), mode=ActionMode.TERMINATE, now=NOW
        )


def test_planning_protects_registered_engine_process_identity() -> None:
    target = identity(pid=7000)
    with pytest.raises(PlanRejectedError, match="protected"):
        planner(FakeController(target), protected_identities=(target,)).create_plan(
            scanned_agent(target), mode=ActionMode.TERMINATE, now=NOW
        )


@pytest.mark.parametrize(
    "target",
    [
        identity(user=None),
        identity(user="other-user"),
        identity(executable=None),
    ],
)
def test_planning_requires_exact_current_user_and_complete_identity(
    target: ProcessIdentity,
) -> None:
    with pytest.raises(PlanRejectedError):
        planner(FakeController(target)).create_plan(
            scanned_agent(target), mode=ActionMode.TERMINATE, now=NOW
        )


def test_planning_rejects_pid_reuse_detected_during_confirmation() -> None:
    scanned = identity(create_time=100.0)
    current = identity(create_time=101.0)
    controller = FakeController(current)

    with pytest.raises(PlanRejectedError, match="identity"):
        planner(controller).create_plan(scanned_agent(scanned), mode=ActionMode.TERMINATE, now=NOW)


def test_unmanaged_requires_explicit_policy_and_never_gets_request_stop() -> None:
    target = identity()
    candidate = scanned_agent(
        target,
        state=AgentState.UNMANAGED,
        actionable=False,
        managed=False,
    )
    action_planner = planner(FakeController(target))

    with pytest.raises(PlanRejectedError, match="unmanaged"):
        action_planner.create_plan(candidate, mode=ActionMode.TERMINATE, now=NOW)
    plan = action_planner.create_plan(
        candidate,
        mode=ActionMode.TERMINATE,
        allow_unmanaged=True,
        now=NOW,
    )
    assert plan.managed is False
    assert plan.agent_id is None
    with pytest.raises(PlanRejectedError, match="cooperative"):
        action_planner.create_plan(
            candidate,
            mode=ActionMode.REQUEST_STOP,
            allow_unmanaged=True,
            now=NOW,
        )


def test_request_stop_rejects_legacy_lease_without_registration_nonce() -> None:
    target = identity()
    controller = FakeController(target)
    candidate = scanned_agent(target).model_copy(update={"registration_nonce": None})

    with pytest.raises(PlanRejectedError, match="registration nonce"):
        planner(controller).create_plan(
            candidate,
            mode=ActionMode.REQUEST_STOP,
            now=NOW,
        )


def test_plan_is_random_short_lived_bounded_and_tamper_evident() -> None:
    target = identity()
    action_planner = planner(FakeController(target))
    first = action_planner.create_plan(scanned_agent(target), mode=ActionMode.TERMINATE, now=NOW)
    second = action_planner.create_plan(scanned_agent(target), mode=ActionMode.TERMINATE, now=NOW)

    assert first.plan_id != second.plan_id
    assert first.expires_at == NOW + timedelta(seconds=30)
    assert first.child_resource_ids == ()
    assert first.verify_digest()
    tampered = first.model_dump(mode="json")
    tampered["identity"]["pid"] = 5000
    with pytest.raises(ValidationError, match="digest"):
        type(first).model_validate_json(__import__("json").dumps(tampered))


def test_plan_ttl_is_fixed_at_exactly_thirty_seconds() -> None:
    target = identity()
    plan = planner(FakeController(target)).create_plan(
        scanned_agent(target),
        mode=ActionMode.TERMINATE,
        now=NOW,
    )

    assert plan.expires_at - plan.created_at == timedelta(seconds=30)
    assert "lifetime_seconds" not in inspect.signature(ActionPlanner.create_plan).parameters
    assert "lifetime" not in inspect.signature(ActionPlan.create).parameters
    assert "expires_at" not in inspect.signature(ActionPlan.create).parameters


def test_windows_terminate_plan_labels_os_operation_as_forceful() -> None:
    target = identity(executable=r"C:\Synthetic\python.exe")
    plan = ActionPlanner(
        FakeController(target),
        current_user="synthetic-user",
        current_pid=9000,
        parent_pid=8999,
        platform_name="windows",
    ).create_plan(scanned_agent(target), mode=ActionMode.TERMINATE, now=NOW)

    assert any("forceful OS terminate" in item for item in plan.consequences)


def test_ten_thousand_pid_reuse_variants_never_match() -> None:
    expected = identity(create_time=10_000.0)
    for offset in range(1, 10_001):
        reused = expected.model_copy(update={"create_time": expected.create_time + offset})
        assert not same_process_instance(
            expected, reused, current_boot_id=expected.boot_id, platform_name="linux"
        )


def prepared_execution(
    tmp_path: Path,
    *,
    mode: ActionMode,
    controller: FakeController | None = None,
) -> tuple[SQLiteStateStore, FakeController, ActionPlan, AppPaths]:
    target = identity()
    selected = controller or FakeController(target)
    app_paths = paths(tmp_path)
    store = SQLiteStateStore(
        app_paths,
        clock=lambda: NOW + timedelta(seconds=1),
        session_id="synthetic-session",
    )
    store.initialize(now=NOW - timedelta(seconds=1))
    plan = planner(selected).create_plan(scanned_agent(target), mode=mode, now=NOW)
    store.save_plan(plan)
    return store, selected, plan, app_paths


def executor(
    store: SQLiteStateStore,
    controller: FakeController,
    app_paths: AppPaths,
    *,
    clock: FakeClock | None = None,
) -> ActionExecutor:
    selected_clock = clock or FakeClock()
    return ActionExecutor(
        store,
        controller,
        app_paths,
        actor="synthetic-user",
        platform_name="linux",
        now=lambda: NOW + timedelta(seconds=1),
        monotonic=selected_clock.monotonic,
        sleep=selected_clock.sleep,
    )


def test_terminate_revalidates_then_signals_and_verifies_exact_instance(
    tmp_path: Path,
) -> None:
    store, controller, plan, app_paths = prepared_execution(tmp_path, mode=ActionMode.TERMINATE)

    action_receipt = executor(store, controller, app_paths).execute(
        plan.plan_id, expected_digest=plan.digest
    )

    assert action_receipt.result is ActionResult.COMPLETED
    assert controller.terminate_calls == [plan.identity]
    assert controller.kill_calls == []
    assert store.list_receipts(plan.plan_id) == (action_receipt,)


def test_force_is_separate_plan_and_calls_kill_only(tmp_path: Path) -> None:
    store, controller, plan, app_paths = prepared_execution(tmp_path, mode=ActionMode.FORCE)

    receipt = executor(store, controller, app_paths).execute(
        plan.plan_id, expected_digest=plan.digest
    )

    assert receipt.result is ActionResult.COMPLETED
    assert controller.kill_calls == [plan.identity]
    assert controller.terminate_calls == []


def test_execution_rejects_reused_pid_without_signaling_and_writes_receipt(
    tmp_path: Path,
) -> None:
    store, controller, plan, app_paths = prepared_execution(tmp_path, mode=ActionMode.TERMINATE)
    controller.target = controller.target.model_copy(
        update={"create_time": controller.target.create_time + 1}
    )

    receipt = executor(store, controller, app_paths).execute(
        plan.plan_id, expected_digest=plan.digest
    )

    assert receipt.result is ActionResult.IDENTITY_MISMATCH
    assert receipt.action_issued is False
    assert controller.terminate_calls == []
    assert controller.kill_calls == []
    assert store.list_receipts(plan.plan_id) == (receipt,)


def test_pid_swap_inside_signal_binding_never_signals_reused_process(
    tmp_path: Path,
) -> None:
    class SwapInsideTerminateController(FakeController):
        def terminate(self, expected: int | ProcessIdentity) -> FakeProcessReference:
            self.target = self.target.model_copy(
                update={"create_time": self.target.create_time + 1}
            )
            return super().terminate(expected)

    original = identity()
    special_controller = SwapInsideTerminateController(original)
    store, controller, plan, app_paths = prepared_execution(
        tmp_path,
        mode=ActionMode.TERMINATE,
        controller=special_controller,
    )

    receipt = executor(store, controller, app_paths).execute(
        plan.plan_id,
        expected_digest=plan.digest,
    )

    assert receipt.result is ActionResult.IDENTITY_MISMATCH
    assert controller.terminate_calls == []


@pytest.mark.parametrize("protected_pid", [1, os.getpid(), os.getppid()])
def test_execution_defensively_rejects_system_self_and_parent_plans(
    tmp_path: Path,
    protected_pid: int,
) -> None:
    target = identity(pid=protected_pid)
    controller = FakeController(target)
    app_paths = paths(tmp_path)
    store = SQLiteStateStore(app_paths, clock=lambda: NOW + timedelta(seconds=1))
    store.initialize(now=NOW - timedelta(seconds=1))
    action_plan = ActionPlan.create(
        identity=target,
        mode=ActionMode.TERMINATE,
        agent_id="synthetic-agent",
        managed=True,
        consequences=("Synthetic malicious bypass plan.",),
        created_at=NOW,
    )
    store.save_plan(action_plan)

    receipt = executor(store, controller, app_paths).execute(
        action_plan.plan_id,
        expected_digest=action_plan.digest,
    )

    assert receipt.result is ActionResult.IDENTITY_MISMATCH
    assert controller.terminate_calls == []
    assert controller.kill_calls == []


def test_execution_defensively_rejects_other_user_bypass_plan(tmp_path: Path) -> None:
    target = identity(user="other-user")
    controller = FakeController(target)
    app_paths = paths(tmp_path)
    store = SQLiteStateStore(app_paths, clock=lambda: NOW + timedelta(seconds=1))
    store.initialize(now=NOW - timedelta(seconds=1))
    action_plan = ActionPlan.create(
        identity=target,
        mode=ActionMode.TERMINATE,
        agent_id="synthetic-agent",
        managed=True,
        consequences=("Synthetic malicious bypass plan.",),
        created_at=NOW,
        platform_name="linux",
    )
    store.save_plan(action_plan)

    receipt = executor(store, controller, app_paths).execute(
        action_plan.plan_id,
        expected_digest=action_plan.digest,
    )

    assert receipt.result is ActionResult.IDENTITY_MISMATCH
    assert controller.terminate_calls == []


@pytest.mark.parametrize(
    ("failure", "expected"),
    [("gone", ActionResult.DISAPPEARED), ("denied", ActionResult.ACCESS_DENIED)],
)
def test_execution_reports_disappeared_and_access_denied_structurally(
    tmp_path: Path,
    failure: str,
    expected: ActionResult,
) -> None:
    store, controller, plan, app_paths = prepared_execution(tmp_path, mode=ActionMode.TERMINATE)
    if failure == "gone":
        controller.alive = False
    else:
        controller.deny = True

    receipt = executor(store, controller, app_paths).execute(
        plan.plan_id, expected_digest=plan.digest
    )

    assert receipt.result is expected
    assert controller.terminate_calls == []


def test_post_signal_verification_denial_is_recorded_as_partial(tmp_path: Path) -> None:
    class VerificationDeniedReference(FakeProcessReference):
        def is_running(self) -> bool:
            raise ProcessAccessDenied(self._controller.target.pid)

    class VerificationDeniedController(FakeController):
        def terminate(self, expected: int | ProcessIdentity) -> FakeProcessReference:
            recorded = expected if isinstance(expected, ProcessIdentity) else self.target
            self.terminate_calls.append(recorded)
            return VerificationDeniedReference(self)

    target = identity()
    special_controller = VerificationDeniedController(target)
    store, controller, plan, app_paths = prepared_execution(
        tmp_path,
        mode=ActionMode.TERMINATE,
        controller=special_controller,
    )

    receipt = executor(store, controller, app_paths).execute(
        plan.plan_id,
        expected_digest=plan.digest,
    )

    assert receipt.result is ActionResult.ACCESS_DENIED
    assert receipt.partial_failures
    loaded = store.get_plan(plan.plan_id)
    assert loaded is not None
    assert loaded.status.value == "partial"


def test_unexpected_controller_failure_is_receipted_and_terminal(tmp_path: Path) -> None:
    class FailingController(FakeController):
        def kill(self, expected: int | ProcessIdentity) -> FakeProcessReference:
            raise RuntimeError("synthetic controller failure")

    target = identity()
    special_controller = FailingController(target)
    store, controller, plan, app_paths = prepared_execution(
        tmp_path,
        mode=ActionMode.FORCE,
        controller=special_controller,
    )

    receipt = executor(store, controller, app_paths).execute(
        plan.plan_id,
        expected_digest=plan.digest,
    )

    assert receipt.result is ActionResult.INTERRUPTED
    assert receipt.action_issued is None
    assert receipt.partial_failures
    assert store.list_receipts(plan.plan_id) == (receipt,)
    loaded = store.get_plan(plan.plan_id)
    assert loaded is not None
    assert loaded.status.value == "interrupted"


def test_side_effect_then_controller_raise_is_persisted_as_uncertain(
    tmp_path: Path,
) -> None:
    class SignalThenRaiseController(FakeController):
        def terminate(self, expected: int | ProcessIdentity) -> FakeProcessReference:
            recorded = expected if isinstance(expected, ProcessIdentity) else self.target
            self.terminate_calls.append(recorded)
            self.alive = False
            raise RuntimeError("controller lost response after signal")

    target = identity()
    special_controller = SignalThenRaiseController(target)
    store, controller, plan, app_paths = prepared_execution(
        tmp_path,
        mode=ActionMode.TERMINATE,
        controller=special_controller,
    )

    receipt = executor(store, controller, app_paths).execute(
        plan.plan_id,
        expected_digest=plan.digest,
    )

    assert receipt.result is ActionResult.INTERRUPTED
    assert receipt.action_issued is None
    assert controller.terminate_calls == [plan.identity]
    loaded = store.get_plan(plan.plan_id)
    assert loaded is not None
    assert loaded.status.value == "interrupted"


def test_typed_pre_side_effect_failure_remains_definite(tmp_path: Path) -> None:
    class DeniedBeforeSignalController(FakeController):
        def terminate(self, expected: int | ProcessIdentity) -> FakeProcessReference:
            raise ProcessAccessDenied(self.target.pid)

    target = identity()
    special_controller = DeniedBeforeSignalController(target)
    store, controller, plan, app_paths = prepared_execution(
        tmp_path,
        mode=ActionMode.TERMINATE,
        controller=special_controller,
    )

    receipt = executor(store, controller, app_paths).execute(
        plan.plan_id,
        expected_digest=plan.digest,
    )

    assert receipt.result is ActionResult.ACCESS_DENIED
    assert receipt.action_issued is False
    assert controller.terminate_calls == []
    loaded = store.get_plan(plan.plan_id)
    assert loaded is not None
    assert loaded.status.value == "failed"


def test_typed_stable_binding_failure_remains_definitely_not_issued(
    tmp_path: Path,
) -> None:
    class UnavailableController(FakeController):
        def terminate(self, expected: int | ProcessIdentity) -> FakeProcessReference:
            raise StableBindingUnavailable(self.target.pid)

    target = identity()
    special_controller = UnavailableController(target)
    store, controller, plan, app_paths = prepared_execution(
        tmp_path,
        mode=ActionMode.TERMINATE,
        controller=special_controller,
    )

    receipt = executor(store, controller, app_paths).execute(
        plan.plan_id,
        expected_digest=plan.digest,
    )

    assert receipt.result is ActionResult.FAILED
    assert receipt.action_issued is False
    assert controller.terminate_calls == []


def test_post_publication_acknowledgement_failure_is_uncertain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import zombie_killer_engine.leases as leases_module

    class GuardChangesAfterPublishReference(FakeProcessReference):
        def __init__(self, controller: FakeController) -> None:
            super().__init__(controller)
            self.validations = 0

        def validate(self, expected: ProcessIdentity) -> None:
            self.validations += 1
            if self.validations >= 3:
                raise ProcessIdentityMismatch(expected.pid)
            super().validate(expected)

    class GuardChangesAfterPublishController(FakeController):
        def bind(self, expected: ProcessIdentity) -> FakeProcessReference:
            self.bind_calls.append(expected)
            return GuardChangesAfterPublishReference(self)

    real_prepare = leases_module._prepare_verified_cancellation_directory
    preparation_count = 0

    def acknowledgement_prepare_fails(path: Path) -> object:
        nonlocal preparation_count
        preparation_count += 1
        if preparation_count == 2:
            raise OSError("synthetic acknowledgement failure")
        return real_prepare(path)

    monkeypatch.setattr(
        leases_module,
        "_prepare_verified_cancellation_directory",
        acknowledgement_prepare_fails,
    )
    target = identity()
    special_controller = GuardChangesAfterPublishController(target)
    store, controller, plan, app_paths = prepared_execution(
        tmp_path,
        mode=ActionMode.REQUEST_STOP,
        controller=special_controller,
    )

    receipt = executor(store, controller, app_paths).execute(
        plan.plan_id,
        expected_digest=plan.digest,
        grace_period_seconds=0,
    )

    assert receipt.result is ActionResult.INTERRUPTED
    assert receipt.action_issued is None
    assert (app_paths.cancellations_dir / f"{plan.agent_id}.json").is_file()


def test_stable_reference_close_failure_is_receipted_after_claim(tmp_path: Path) -> None:
    class CloseFailureReference(FakeProcessReference):
        def close(self) -> None:
            raise OSError("synthetic close failure")

    class CloseFailureController(FakeController):
        def terminate(self, expected: int | ProcessIdentity) -> FakeProcessReference:
            recorded = expected if isinstance(expected, ProcessIdentity) else self.target
            self.terminate_calls.append(recorded)
            self.alive = False
            return CloseFailureReference(self)

    target = identity()
    special_controller = CloseFailureController(target)
    store, controller, plan, app_paths = prepared_execution(
        tmp_path,
        mode=ActionMode.TERMINATE,
        controller=special_controller,
    )

    receipt = executor(store, controller, app_paths).execute(
        plan.plan_id,
        expected_digest=plan.digest,
    )

    assert receipt.partial_failures
    assert store.list_receipts(plan.plan_id) == (receipt,)
    loaded = store.get_plan(plan.plan_id)
    assert loaded is not None
    assert loaded.status.value == "partial"


def test_request_stop_writes_cancellation_and_never_escalates(tmp_path: Path) -> None:
    store, controller, plan, app_paths = prepared_execution(tmp_path, mode=ActionMode.REQUEST_STOP)
    clock = FakeClock()

    receipt = executor(store, controller, app_paths, clock=clock).execute(
        plan.plan_id,
        expected_digest=plan.digest,
        grace_period_seconds=0.2,
        poll_interval_seconds=0.05,
    )

    assert receipt.result is ActionResult.PENDING
    request_path = cancellation_path(app_paths, "synthetic-agent")
    assert request_path.is_file()
    request_payload = json.loads(request_path.read_text(encoding="utf-8"))
    assert request_payload["protocol_version"] == 2
    assert request_payload["plan_id"] == plan.plan_id
    assert request_payload["registration_nonce"] == "synthetic-registration-1"
    assert request_payload["target"]["boot_id"] == plan.identity.boot_id
    assert request_payload["target"]["pid"] == plan.identity.pid
    assert request_payload["target"]["create_time_hash"]
    assert request_payload["target"]["executable_hash"] == plan.identity.executable_hash
    assert request_payload["target"]["user_hash"] == plan.identity.user_hash
    assert controller.terminate_calls == []
    assert controller.kill_calls == []
    assert controller.bind_calls == [plan.identity]
    assert clock.value <= 0.25


def test_request_stop_pid_swap_inside_publication_is_not_consumable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, controller, plan, app_paths = prepared_execution(tmp_path, mode=ActionMode.REQUEST_STOP)
    destination = cancellation_path(app_paths, "synthetic-agent")
    real_replace = os.replace
    swapped = False

    def swap_during_publish(
        source: str | os.PathLike[str],
        target: str | os.PathLike[str],
        *args: object,
        **kwargs: object,
    ) -> None:
        nonlocal swapped
        if Path(target).name == destination.name and not swapped:
            swapped = True
            controller.target = controller.target.model_copy(
                update={"create_time": controller.target.create_time + 1}
            )
        real_replace(source, target, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "replace", swap_during_publish)

    receipt = executor(store, controller, app_paths).execute(
        plan.plan_id,
        expected_digest=plan.digest,
        grace_period_seconds=0,
    )

    assert swapped
    assert receipt.result is ActionResult.INTERRUPTED
    assert receipt.action_issued is None
    assert controller.terminate_calls == []
    assert controller.kill_calls == []
    assert not tuple(app_paths.cancellations_dir.glob("*.tmp"))
    assert (
        observe_cancellation_request(
            app_paths.cancellations_dir,
            "synthetic-agent",
            observer_identity=controller.target,
            registration_nonce="synthetic-registration-1",
            now=NOW + timedelta(seconds=1),
        )
        is None
    )


def test_request_stop_replace_failure_is_definitely_not_published(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, controller, plan, app_paths = prepared_execution(tmp_path, mode=ActionMode.REQUEST_STOP)
    destination = cancellation_path(app_paths, "synthetic-agent")
    real_replace = os.replace

    def fail_request_replace(
        source: str | os.PathLike[str],
        target: str | os.PathLike[str],
        *args: object,
        **kwargs: object,
    ) -> None:
        if Path(target).name == destination.name:
            raise OSError("synthetic pre-publication replace failure")
        real_replace(source, target, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "replace", fail_request_replace)

    receipt = executor(store, controller, app_paths).execute(
        plan.plan_id,
        expected_digest=plan.digest,
        grace_period_seconds=0,
    )

    assert receipt.result is ActionResult.FAILED
    assert receipt.action_issued is False
    assert destination.exists() is False


def test_request_stop_rejects_redirected_runtime_directory(tmp_path: Path) -> None:
    actual_runtime = tmp_path / "actual-runtime"
    actual_cancellations = actual_runtime / "cancellations"
    actual_cancellations.mkdir(parents=True)
    redirected_runtime = tmp_path / "redirected-runtime"
    if os.name == "nt":
        create_junction = importlib.import_module("_winapi").CreateJunction
        try:
            create_junction(str(actual_runtime), str(redirected_runtime))
        except OSError:
            pytest.skip("junction creation is unavailable on this host")
    else:
        redirected_runtime.symlink_to(actual_runtime, target_is_directory=True)
    app_paths = AppPaths(
        data_dir=tmp_path / "data",
        state_dir=tmp_path / "state",
        runtime_dir=redirected_runtime,
        backups_dir=tmp_path / "backups",
        graveyard_dir=tmp_path / "graveyard",
    )
    target = identity()
    controller = FakeController(target)
    store = SQLiteStateStore(
        app_paths,
        clock=lambda: NOW + timedelta(seconds=1),
        session_id="synthetic-session",
    )
    store.initialize(now=NOW)
    action_plan = planner(controller).create_plan(
        scanned_agent(target),
        mode=ActionMode.REQUEST_STOP,
        now=NOW,
    )
    store.save_plan(action_plan)

    receipt = executor(store, controller, app_paths).execute(
        action_plan.plan_id,
        expected_digest=action_plan.digest,
        grace_period_seconds=0,
    )

    assert receipt.result is ActionResult.FAILED
    assert not tuple(actual_cancellations.glob("*.json"))
    assert not tuple(actual_cancellations.glob("*.tmp"))


def test_concurrent_execution_claims_plan_once(tmp_path: Path) -> None:
    store, controller, plan, app_paths = prepared_execution(tmp_path, mode=ActionMode.TERMINATE)
    action_executor = executor(store, controller, app_paths)

    def run() -> object:
        try:
            return action_executor.execute(plan.plan_id, expected_digest=plan.digest)
        except PlanClaimError as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = tuple(pool.map(lambda _: run(), range(2)))

    assert len(controller.terminate_calls) == 1
    assert sum(not isinstance(item, PlanClaimError) for item in outcomes) == 1


def test_database_contention_past_expiry_never_signals_target(tmp_path: Path) -> None:
    target = identity()
    controller = FakeController(target)
    app_paths = paths(tmp_path)
    clock = MutableUtcClock(NOW)
    store = SQLiteStateStore(
        app_paths,
        clock=clock,
        session_id="synthetic-session",
        busy_timeout_ms=5_000,
    )
    store.initialize(now=NOW)
    action_plan = planner(controller).create_plan(
        scanned_agent(target),
        mode=ActionMode.TERMINATE,
        now=NOW,
    )
    store.save_plan(action_plan)
    lock = sqlite3.connect(store.database_path, isolation_level=None)
    lock.execute("BEGIN IMMEDIATE")
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(
                executor(store, controller, app_paths).execute,
                action_plan.plan_id,
                expected_digest=action_plan.digest,
            )
            time.sleep(0.05)
            assert future.done() is False
            clock.value = action_plan.expires_at
            lock.commit()
            with pytest.raises(ExpiredPlanError):
                future.result(timeout=3)
    finally:
        if lock.in_transaction:
            lock.rollback()
        lock.close()

    assert controller.terminate_calls == []
    assert controller.kill_calls == []


def _stop_fixture(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


@pytest.mark.skipif(os.name != "nt", reason="Windows stable-handle contract")
def test_windows_controller_reports_kernel_stable_handle_binding() -> None:
    assert PsutilProcessController().stable_binding_kind == "windows_handle"


def test_darwin_controller_reports_stable_binding_unavailable() -> None:
    assert PsutilProcessController(platform_name="Darwin").stable_binding_kind == "unsupported"


def test_controller_fails_closed_when_kernel_stable_binding_is_unavailable() -> None:
    controller = PsutilProcessController(platform_name="unsupported-platform")

    with pytest.raises(StableBindingUnavailable):
        controller.terminate(identity())


@pytest.mark.skipif(
    not sys.platform.startswith("linux")
    or not callable(getattr(os, "pidfd_open", None))
    or not callable(getattr(signal, "pidfd_send_signal", None)),
    reason="Linux pidfd identity integration",
)
def test_linux_pidfd_validates_controller_uid_identity() -> None:
    controller = PsutilProcessController(platform_name="Linux")
    target = controller.read_identity(os.getpid())

    reference = controller.bind(target)
    try:
        reference.validate(target)
        assert reference.is_running() is True
    finally:
        reference.close()


@pytest.mark.skipif(os.name != "nt", reason="Windows stable-handle integration")
def test_windows_stable_handle_terminates_only_selected_fixture(tmp_path: Path) -> None:
    fixture = Path(__file__).parent / "fixtures" / "sleeper.py"
    fixture_python, fixture_env = fixture_python_environment()
    target = subprocess.Popen(
        [
            fixture_python,
            str(fixture),
            "--token",
            secrets.token_hex(16),
            "--idle",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=fixture_env,
    )
    sibling = subprocess.Popen(
        [
            fixture_python,
            str(fixture),
            "--token",
            secrets.token_hex(16),
            "--idle",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=fixture_env,
    )
    reference = None
    try:
        controller = PsutilProcessController()
        target_identity = controller.read_identity(target.pid)
        reference = controller.terminate(target_identity)
        deadline = time.monotonic() + 3
        while reference.is_running() and time.monotonic() < deadline:
            time.sleep(0.02)

        assert reference.is_running() is False
        assert sibling.poll() is None
    finally:
        if reference is not None:
            reference.close()
        _stop_fixture(target)
        _stop_fixture(sibling)


def test_real_cooperative_fixture_stops_only_selected_same_name_process(
    tmp_path: Path,
) -> None:
    fixture = Path(__file__).parent / "fixtures" / "sleeper.py"
    fixture_python, fixture_env = fixture_python_environment()
    app_paths = paths(tmp_path)
    target_agent = f"target-{secrets.token_hex(8)}"
    sibling_agent = f"sibling-{secrets.token_hex(8)}"
    target_nonce = f"registration-{secrets.token_hex(16)}"
    sibling_nonce = f"registration-{secrets.token_hex(16)}"
    app_paths.cancellations_dir.mkdir(parents=True)
    target = subprocess.Popen(
        [
            fixture_python,
            str(fixture),
            "--token",
            secrets.token_hex(16),
            "--cancellation-dir",
            str(app_paths.cancellations_dir),
            "--agent-id",
            target_agent,
            "--registration-nonce",
            target_nonce,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=fixture_env,
    )
    sibling = subprocess.Popen(
        [
            fixture_python,
            str(fixture),
            "--token",
            secrets.token_hex(16),
            "--cancellation-dir",
            str(app_paths.cancellations_dir),
            "--agent-id",
            sibling_agent,
            "--registration-nonce",
            sibling_nonce,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=fixture_env,
    )
    try:
        controller = PsutilProcessController()
        deadline = time.monotonic() + 3
        target_identity: ProcessIdentity | None = None
        while time.monotonic() < deadline:
            try:
                target_identity = controller.read_identity(target.pid)
                controller.read_identity(sibling.pid)
                break
            except ProcessDisappeared:
                time.sleep(0.02)
        assert target_identity is not None
        assert target_identity.user is not None
        store = SQLiteStateStore(app_paths)
        store.initialize()
        candidate = scanned_agent(target_identity).model_copy(
            update={
                "agent_id": target_agent,
                "registration_nonce": target_nonce,
            }
        )
        plan = ActionPlanner(
            controller,
            current_user=target_identity.user,
            current_pid=os.getpid(),
            parent_pid=os.getppid(),
        ).create_plan(candidate, mode=ActionMode.REQUEST_STOP)
        store.save_plan(plan)

        receipt = ActionExecutor(
            store,
            controller,
            app_paths,
            actor=target_identity.user,
        ).execute(
            plan.plan_id,
            expected_digest=plan.digest,
            grace_period_seconds=3,
            poll_interval_seconds=0.02,
        )

        assert receipt.result is ActionResult.COMPLETED
        assert target.wait(timeout=3) == 0
        assert sibling.poll() is None
        assert not cancellation_path(app_paths, sibling_agent).exists()
        assert cancellation_path(app_paths, target_agent).with_suffix(".cleared").exists()
    finally:
        _stop_fixture(target)
        _stop_fixture(sibling)
