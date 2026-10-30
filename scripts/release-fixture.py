#!/usr/bin/env python3
"""Run the bounded, local-only Zombie Killer release fixture and emit one JSON report."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import sysconfig
import tempfile
import time
from contextlib import suppress
from pathlib import Path
from typing import Any
from uuid import uuid4

import psutil  # type: ignore[import-untyped]

from zombie_killer_engine.actions import (
    ProcessDisappeared,
    ProcessIdentityMismatch,
    PsutilProcessController,
    process_instance_id,
)
from zombie_killer_engine.models import ProcessIdentity
from zombie_killer_engine.paths import (
    AppPaths,
    PosixPermissionBackend,
    WindowsPermissionBackend,
)
from zombie_killer_engine.quarantine import (
    CleanupManifest,
    InMemoryCleanupRegistry,
    QuarantineExecutor,
    QuarantinePlanner,
    QuarantineResult,
    ResourceType,
)
from zombie_killer_engine.scanner import (
    ProcessObservation,
    ProcessReadError,
    scan_agents,
)
from zombie_killer_engine.service import (
    PROTOCOL_VERSION,
    Capability,
    ClientKind,
    EngineService,
    Method,
    RequestContext,
    RequestEnvelope,
    build_default_service,
)
from zombie_killer_engine.store import SQLiteStateStore

TARGET_AGENT_ID = "00000000-0000-4000-8000-000000000001"
SIBLING_AGENT_ID = "00000000-0000-4000-8000-000000000002"
TARGET_RUN_ID = "10000000-0000-4000-8000-000000000001"
SIBLING_RUN_ID = "10000000-0000-4000-8000-000000000002"
TARGET_CONTENT = b"Zombie Killer release fixture target artifact\n"
SIBLING_CONTENT = b"Zombie Killer release fixture sibling artifact\n"
_SAFE_CHILD_ENVIRONMENT = (
    "COMSPEC",
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "WINDIR",
)


class FixtureError(RuntimeError):
    """A bounded release-fixture assertion failed."""


class _ExactLiveProcessProvider:
    """Read only the two fixture PIDs while retaining the production scanner."""

    pid_enumeration_complete = False

    def __init__(self, pids: tuple[int, int]) -> None:
        self._pids = pids

    def snapshot(self) -> tuple[ProcessObservation, ...]:
        observations: list[ProcessObservation] = []
        for pid in self._pids:
            try:
                process = psutil.Process(pid)
                with process.oneshot():
                    memory = process.memory_info()
                    observations.append(
                        ProcessObservation(
                            pid=pid,
                            ppid=process.ppid(),
                            create_time=process.create_time(),
                            name=process.name(),
                            exe=process.exe(),
                            username=process.username(),
                            status=process.status(),
                            rss_bytes=memory.rss,
                            cmdline=tuple(process.cmdline()),
                        )
                    )
            except psutil.NoSuchProcess:
                observations.append(ProcessObservation(pid=pid, error=ProcessReadError.VANISHED))
            except psutil.AccessDenied:
                observations.append(
                    ProcessObservation(pid=pid, error=ProcessReadError.ACCESS_DENIED)
                )
        return tuple(observations)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workspace",
        type=Path,
        help="new empty fixture directory; an owned temporary directory is used by default",
    )
    parser.add_argument("--deadline-seconds", type=float, default=20.0)
    arguments = parser.parse_args()
    if not 8 <= arguments.deadline_seconds <= 45:
        parser.error("--deadline-seconds must be between 8 and 45")
    return arguments


def _child_environment() -> dict[str, str]:
    repository = Path(__file__).resolve().parents[1]
    import_roots = (
        repository / "packages" / "sdk-python" / "src",
        repository / "services" / "engine" / "src",
        Path(sysconfig.get_path("purelib")),
    )
    environment = {
        key: value for key in _SAFE_CHILD_ENVIRONMENT if (value := os.environ.get(key)) is not None
    }
    environment.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONIOENCODING": "utf-8",
            "PYTHONPATH": os.pathsep.join(os.fspath(path) for path in import_roots),
            "PYTHONUTF8": "1",
        }
    )
    return environment


def _secure_directory(path: Path) -> None:
    backend = WindowsPermissionBackend() if os.name == "nt" else PosixPermissionBackend()
    backend.restrict(path)
    backend.verify(path)


def _app_paths(workspace: Path) -> AppPaths:
    return AppPaths(
        data_dir=workspace / "app" / "data",
        state_dir=workspace / "app" / "state",
        runtime_dir=workspace / "app" / "runtime",
        backups_dir=workspace / "app" / "backups",
        graveyard_dir=workspace / "app" / "graveyard",
    )


def _dispatch(
    service: EngineService,
    method: Method,
    payload: dict[str, object],
    *,
    capability: Capability,
    local_control: bool = False,
) -> dict[str, Any]:
    response = service.dispatch(
        RequestEnvelope(
            protocol_version=PROTOCOL_VERSION,
            request_id=uuid4(),
            method=method.value,
            payload=payload,
        ),
        context=RequestContext(
            client=ClientKind.CONTROLLER,
            capability=capability,
            local_control=local_control,
        ),
    )
    if not response.ok or response.result is None:
        code = response.error.code.value if response.error is not None else "missing_error"
        raise FixtureError(f"{method.value} failed safely ({code})")
    return response.result.model_dump(mode="json")


def _wait_for_ready(
    processes: dict[str, subprocess.Popen[bytes]],
    ready_files: dict[str, Path],
    *,
    deadline: float,
) -> dict[str, dict[str, object]]:
    while time.monotonic() < deadline:
        for name, process in processes.items():
            if process.poll() is not None and not ready_files[name].is_file():
                raise FixtureError(f"{name} agent exited before registration")
        if all(path.is_file() for path in ready_files.values()):
            ready = {
                name: json.loads(path.read_text(encoding="utf-8"))
                for name, path in ready_files.items()
            }
            for name, payload in ready.items():
                if not isinstance(payload, dict):
                    raise FixtureError(f"{name} readiness record is malformed")
            return ready
        time.sleep(0.025)
    raise FixtureError("agents did not register before the fixture deadline")


def _scan_agents(
    service: EngineService,
    *,
    deadline: float,
) -> dict[str, dict[str, Any]]:
    expected = {TARGET_AGENT_ID, SIBLING_AGENT_ID}
    while time.monotonic() < deadline:
        result = _dispatch(
            service,
            Method.SCAN_LIST,
            {"include_unmanaged": False, "limit": 10},
            capability=Capability.READ,
        )
        agents = {
            item["agent_id"]: item for item in result["agents"] if item.get("agent_id") in expected
        }
        if set(agents) == expected and all(
            item.get("managed") is True
            and isinstance(item.get("pid"), int)
            and isinstance(item.get("process_instance_id"), str)
            for item in agents.values()
        ):
            return agents
        time.sleep(0.025)
    raise FixtureError("the real scanner did not resolve both synthetic agents")


def _request_stop(
    service: EngineService,
    agent: dict[str, Any],
) -> dict[str, Any]:
    target = {
        "pid": agent["pid"],
        "process_instance_id": agent["process_instance_id"],
    }
    plan = _dispatch(
        service,
        Method.ACTION_PLAN,
        {"agent_id": agent["agent_id"], "mode": "request_stop", "target": target},
        capability=Capability.PLANNING,
    )
    if plan["target"]["pid"] != target["pid"] or (
        plan["target"]["process_instance_id"] != target["process_instance_id"]
    ):
        raise FixtureError("the action plan changed process identity")
    return _dispatch(
        service,
        Method.ACTION_EXECUTE,
        {"plan_id": plan["plan_id"], "digest": plan["digest"]},
        capability=Capability.EXECUTION,
        local_control=True,
    )


def _wait_for_process_exit(process: subprocess.Popen[bytes], *, deadline: float) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise FixtureError("the fixture deadline expired while waiting for process exit")
    try:
        process.wait(timeout=remaining)
    except subprocess.TimeoutExpired as error:
        raise FixtureError("the selected process did not exit before the deadline") from error


def _quarantine_round_trip(
    *,
    paths: AppPaths,
    approved_root: Path,
    target: Path,
    target_identity: ProcessIdentity,
) -> dict[str, object]:
    before = hashlib.sha256(target.read_bytes()).hexdigest()
    registry = InMemoryCleanupRegistry()
    manifest = CleanupManifest.create(
        agent_id=TARGET_AGENT_ID,
        creating_identity=target_identity,
        approved_root=approved_root,
        target=target,
        resource_type=ResourceType.FILE,
        declaration_source="wrapper",
        managed=True,
    )
    registry.register(manifest)
    planner = QuarantinePlanner(
        (approved_root,),
        registration_resolver=registry,
    )
    plan = planner.create_plan(manifest)
    store = SQLiteStateStore(paths, session_id="release-fixture-quarantine")
    store.initialize()
    try:
        store.save_quarantine_plan(plan)
        executor = QuarantineExecutor(
            store,
            paths,
            actor="release-fixture-local-controller",
            registration_resolver=registry,
        )
        quarantine_receipt = executor.execute(plan.plan_id, expected_digest=plan.digest)
        if (
            quarantine_receipt.result is not QuarantineResult.QUARANTINED
            or quarantine_receipt.entry_id is None
            or target.exists()
        ):
            raise FixtureError("the separately authorized quarantine did not complete")
        restore_receipt = executor.restore(quarantine_receipt.entry_id)
        if restore_receipt.result not in {
            QuarantineResult.RESTORED,
            QuarantineResult.ALREADY_RESTORED,
        }:
            raise FixtureError("the separately authorized restore did not complete")
    finally:
        store.close()
    after = hashlib.sha256(target.read_bytes()).hexdigest()
    return {
        # SDK resource evidence and cleanup-domain authority are not yet composed
        # automatically. This fixture deliberately exercises the domain operation
        # as a separate, explicit, approved-root action and reports that boundary.
        "automatic_sdk_cleanup_composition": False,
        "exercise": "separate_explicit_domain_operation",
        "approved_root_explicit": True,
        "quarantined": True,
        "restored": True,
        "sha256_before": before,
        "sha256_after": after,
        "sha256_verified": before == after,
    }


def _cleanup_exact_instance(
    process: subprocess.Popen[bytes],
    expected: ProcessIdentity | None,
    controller: PsutilProcessController,
) -> None:
    if process.poll() is not None:
        return
    identity = expected or controller.read_identity(process.pid)
    observed = controller.read_identity(process.pid)
    if process_instance_id(observed) != process_instance_id(identity):
        raise FixtureError("cleanup refused a changed process instance")
    reference = controller.terminate(identity)
    try:
        deadline = time.monotonic() + 1.5
        while reference.is_running() and time.monotonic() < deadline:
            time.sleep(0.025)
    finally:
        reference.close()
    if process.poll() is None:
        observed = controller.read_identity(process.pid)
        if process_instance_id(observed) != process_instance_id(identity):
            raise FixtureError("cleanup refused a changed process instance")
        reference = controller.kill(identity)
        try:
            deadline = time.monotonic() + 1.5
            while reference.is_running() and time.monotonic() < deadline:
                time.sleep(0.025)
        finally:
            reference.close()
    with suppress(subprocess.TimeoutExpired):
        process.wait(timeout=0.5)
    if process.poll() is None:
        raise FixtureError("exact-identity cleanup did not stop the fixture process")


def _run(workspace: Path, *, deadline_seconds: float) -> dict[str, object]:
    paths = _app_paths(workspace)
    warnings = paths.ensure()
    if warnings:
        raise FixtureError("isolated application paths could not be prepared securely")
    approved_root = workspace / "artifacts"
    approved_root.mkdir(mode=0o700)
    _secure_directory(approved_root)
    control_root = workspace / "control"
    control_root.mkdir(mode=0o700)
    _secure_directory(control_root)

    script = Path(__file__).with_name("demo-agent.py").resolve(strict=True)
    artifacts = {
        "target": approved_root / "target.bin",
        "sibling": approved_root / "sibling.bin",
    }
    ready_files = {
        "target": control_root / "target.ready.json",
        "sibling": control_root / "sibling.ready.json",
    }
    identifiers = {
        "target": (TARGET_AGENT_ID, TARGET_RUN_ID),
        "sibling": (SIBLING_AGENT_ID, SIBLING_RUN_ID),
    }
    environment = _child_environment()
    child_python = os.fspath(getattr(sys, "_base_executable", sys.executable))
    child_lifetime = min(60.0, deadline_seconds + 10.0)
    processes: dict[str, subprocess.Popen[bytes]] = {}
    identities: dict[str, ProcessIdentity] = {}
    service: EngineService | None = None
    controller = PsutilProcessController()
    absolute_deadline = time.monotonic() + deadline_seconds
    cleanup_error: BaseException | None = None
    report: dict[str, object] | None = None
    try:
        for name in ("target", "sibling"):
            agent_id, run_id = identifiers[name]
            processes[name] = subprocess.Popen(
                [
                    child_python,
                    os.fspath(script),
                    "--state-dir",
                    os.fspath(paths.runtime_dir),
                    "--approved-root",
                    os.fspath(approved_root),
                    "--artifact",
                    os.fspath(artifacts[name]),
                    "--ready-file",
                    os.fspath(ready_files[name]),
                    "--agent-id",
                    agent_id,
                    "--run-id",
                    run_id,
                    "--kind",
                    name,
                    "--max-runtime-seconds",
                    str(child_lifetime),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=environment,
                close_fds=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        ready = _wait_for_ready(processes, ready_files, deadline=absolute_deadline)
        for name, process in processes.items():
            payload = ready[name]
            agent_id, _run_id = identifiers[name]
            expected_content = TARGET_CONTENT if name == "target" else SIBLING_CONTENT
            if (
                payload.get("agent_id") != agent_id
                or payload.get("pid") != process.pid
                or payload.get("artifact_sha256") != hashlib.sha256(expected_content).hexdigest()
                or payload.get("provider_credentials_present") is not False
                or payload.get("network_guard_active") is not True
            ):
                raise FixtureError(f"{name} agent readiness evidence was inconsistent")
            identities[name] = controller.read_identity(process.pid)
        sibling_artifact_hash_before = hashlib.sha256(artifacts["sibling"].read_bytes()).hexdigest()

        process_provider = _ExactLiveProcessProvider(
            (processes["target"].pid, processes["sibling"].pid)
        )
        service = build_default_service(
            paths=paths,
            scanner=lambda: scan_agents(
                paths.leases_dir,
                process_provider=process_provider,
            ),
        )
        scanned = _scan_agents(service, deadline=absolute_deadline)
        for name, (agent_id, _run_id) in identifiers.items():
            identity = identities[name]
            item = scanned[agent_id]
            if item["pid"] != identity.pid or (
                item["process_instance_id"] != process_instance_id(identity)
            ):
                raise FixtureError(f"{name} scan evidence changed process identity")

        target_receipt = _request_stop(service, scanned[TARGET_AGENT_ID])
        if target_receipt["outcome"] != "completed" or (
            target_receipt["action_issued"] is not True
        ):
            raise FixtureError("the exact target did not cooperatively stop")
        _wait_for_process_exit(processes["target"], deadline=absolute_deadline)

        sibling_observed = controller.read_identity(processes["sibling"].pid)
        sibling_unchanged = process_instance_id(sibling_observed) == process_instance_id(
            identities["sibling"]
        )
        if processes["sibling"].poll() is not None or not sibling_unchanged:
            raise FixtureError("the same-script sibling did not remain unchanged")

        artifact_result = _quarantine_round_trip(
            paths=paths,
            approved_root=approved_root,
            target=artifacts["target"],
            target_identity=identities["target"],
        )
        if not artifact_result["sha256_verified"]:
            raise FixtureError("the restored artifact hash did not match")
        sibling_after_round_trip = controller.read_identity(processes["sibling"].pid)
        sibling_artifact_hash_after = hashlib.sha256(artifacts["sibling"].read_bytes()).hexdigest()
        if (
            process_instance_id(sibling_after_round_trip)
            != process_instance_id(identities["sibling"])
            or sibling_artifact_hash_before != sibling_artifact_hash_after
        ):
            raise FixtureError("the sibling changed during artifact round-trip")

        sibling_receipt = _request_stop(service, scanned[SIBLING_AGENT_ID])
        if sibling_receipt["outcome"] != "completed":
            raise FixtureError("the sibling did not cooperatively stop during cleanup")
        _wait_for_process_exit(processes["sibling"], deadline=absolute_deadline)
        report = {
            "schema_version": 1,
            "fixture": "zombie-killer-release-fixture",
            "synthetic": True,
            "scanner": {
                "implementation": "production_scan_agents",
                "process_scope": "exact_spawned_processes",
            },
            "spawned": {
                "agent_count": 2,
                "same_script": True,
                "distinct_agent_ids": True,
                "provider_credentials_forwarded": False,
                "network_access": False,
            },
            "cooperative_stop": {
                "mode": "request_stop",
                "target": {
                    "agent_id": TARGET_AGENT_ID,
                    "pid": scanned[TARGET_AGENT_ID]["pid"],
                    "process_instance_id": scanned[TARGET_AGENT_ID]["process_instance_id"],
                    "exited": True,
                },
                "sibling": {
                    "agent_id": SIBLING_AGENT_ID,
                    "pid": scanned[SIBLING_AGENT_ID]["pid"],
                    "process_instance_id": scanned[SIBLING_AGENT_ID]["process_instance_id"],
                    "alive_after_target_stop": True,
                    "instance_unchanged": True,
                    "artifact_sha256_before": sibling_artifact_hash_before,
                    "artifact_sha256_after": sibling_artifact_hash_after,
                    "artifact_unchanged": True,
                },
                "receipt": {
                    "outcome": target_receipt["outcome"],
                    "action_issued": target_receipt["action_issued"],
                },
            },
            "artifact_round_trip": artifact_result,
            "cleanup": {
                "exact_identity_only": True,
                "process_name_killing": False,
                "children_remaining": sum(process.poll() is None for process in processes.values()),
            },
        }
    finally:
        if service is not None:
            try:
                service.close()
            except BaseException as error:
                cleanup_error = error
        for name, process in processes.items():
            try:
                _cleanup_exact_instance(process, identities.get(name), controller)
            except (ProcessDisappeared, ProcessIdentityMismatch):
                if process.poll() is None and cleanup_error is None:
                    cleanup_error = FixtureError(
                        f"{name} cleanup could not prove exact process identity"
                    )
            except BaseException as error:
                if cleanup_error is None:
                    cleanup_error = error
        if cleanup_error is not None:
            raise cleanup_error
    if report is None:
        raise FixtureError("the release fixture produced no report")
    report["cleanup"] = {
        "exact_identity_only": True,
        "process_name_killing": False,
        "children_remaining": sum(process.poll() is None for process in processes.values()),
    }
    return report


def main() -> int:
    arguments = _arguments()
    temporary: tempfile.TemporaryDirectory[str] | None = None
    if arguments.workspace is None:
        temporary = tempfile.TemporaryDirectory(prefix="zombie-killer-release-fixture-")
        workspace = Path(temporary.name).resolve(strict=True)
    else:
        requested = arguments.workspace.absolute()
        if requested.exists():
            raise FixtureError("--workspace must name a new directory")
        requested.mkdir(parents=True, mode=0o700)
        workspace = requested.resolve(strict=True)
        _secure_directory(workspace)
    try:
        report = _run(workspace, deadline_seconds=arguments.deadline_seconds)
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 0
    finally:
        if temporary is not None:
            temporary.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
