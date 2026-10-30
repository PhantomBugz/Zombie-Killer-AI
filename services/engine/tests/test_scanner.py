from __future__ import annotations

import hashlib
import json
import os
import platform
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import psutil
import pytest

import zombie_killer_engine.scanner as scanner_module
from zombie_killer_engine.leases import LEASE_PROTOCOL_VERSION, LeaseLifecycle
from zombie_killer_engine.models import AgentState
from zombie_killer_engine.scanner import (
    ProcessObservation,
    ProcessReadError,
    PsutilProcessProvider,
    SnapshotProcessProvider,
    current_boot_id,
    is_current_user,
    scan_agents,
)

NOW = datetime(2026, 8, 12, 12, 0, tzinfo=UTC)


def write_lease(
    lease_dir: Path,
    *,
    agent_id: str = "agent-1",
    registration_nonce: str | None = "registration-generation-1",
    boot_id: str = "boot-current",
    pid: int = 4242,
    create_time: float = NOW.timestamp() - 60,
    executable: str | None = "/synthetic/bin/agent",
    user: str | None = "synthetic-user",
    heartbeat_at: datetime = NOW,
    detached: bool = False,
    status: str = "Processing local fixtures",
    expected_parent_pid: int | None = None,
    expected_owner: str | None = None,
    lifecycle: str = "running",
    terminal_at: datetime | None = None,
) -> None:
    lease_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "protocol_version": LEASE_PROTOCOL_VERSION,
        "agent_id": agent_id,
        "registration_nonce": registration_nonce,
        "identity": {
            "boot_id": boot_id,
            "pid": pid,
            "create_time": create_time,
            "executable": executable,
            "user": user,
        },
        "heartbeat_at": heartbeat_at.isoformat().replace("+00:00", "Z"),
        "heartbeat_timeout_seconds": 30.0,
        "provider": "synthetic-provider",
        "project": "Synthetic Project",
        "role": "worker",
        "status": status,
        "detached": detached,
        "expected_parent_pid": expected_parent_pid,
        "expected_owner": expected_owner,
        "run_id": "run-1",
        "lifecycle": lifecycle,
        "terminal_at": (
            terminal_at.isoformat().replace("+00:00", "Z") if terminal_at is not None else None
        ),
        "resources": [],
        "counters": {},
    }
    (lease_dir / f"{agent_id}.json").write_text(json.dumps(payload), encoding="utf-8")


def process(
    *,
    pid: int = 4242,
    create_time: float = NOW.timestamp() - 60,
    exe: str | None = "/synthetic/bin/agent",
    username: str | None = "synthetic-user",
    signature_matched: bool = False,
    cmdline: tuple[str, ...] = ("agent", "--local"),
) -> ProcessObservation:
    return ProcessObservation(
        pid=pid,
        ppid=4000,
        create_time=create_time,
        name="agent",
        exe=exe,
        username=username,
        status="running",
        cpu_percent=2.5,
        rss_bytes=1024,
        cmdline=cmdline,
        signature_matched=signature_matched,
    )


def scan(
    lease_dir: Path,
    *observations: ProcessObservation,
    captured_at: datetime = NOW,
    pid_enumeration_complete: bool = True,
):
    return scan_agents(
        lease_dir,
        process_provider=SnapshotProcessProvider(
            observations,
            pid_enumeration_complete=pid_enumeration_complete,
        ),
        current_boot="boot-current",
        current_user="synthetic-user",
        platform_name="linux",
        captured_at=captured_at,
    )


def test_matching_core_identity_enriches_and_classifies_agent(tmp_path: Path) -> None:
    write_lease(tmp_path, detached=True)

    result = scan(tmp_path, process())

    assert result.coverage.complete is True
    assert result.coverage.inspected_count == 1
    assert len(result.agents) == 1
    agent = result.agents[0]
    assert agent.lease_matched is True
    assert agent.agent_id == "agent-1"
    assert agent.registration_nonce == "registration-generation-1"
    assert agent.provider == "synthetic-provider"
    assert agent.project == "Synthetic Project"
    assert agent.role == "worker"
    assert agent.status == "Processing local fixtures"
    assert agent.detached is True
    assert agent.actionable is True
    assert agent.classification.state is AgentState.HEALTHY


def test_controller_heartbeat_grace_changes_classification_without_rewriting_lease(
    tmp_path: Path,
) -> None:
    write_lease(tmp_path, detached=True, heartbeat_at=NOW - timedelta(seconds=40))
    original = (tmp_path / "agent-1.json").read_bytes()
    arguments = dict(
        process_provider=SnapshotProcessProvider((process(),)),
        current_boot="boot-current",
        current_user="synthetic-user",
        platform_name="linux",
        captured_at=NOW,
    )
    default = scan_agents(tmp_path, **arguments)
    extended = scan_agents(tmp_path, heartbeat_grace_seconds=120, **arguments)
    assert default.agents[0].classification.state is AgentState.STALE
    assert extended.agents[0].classification.state is AgentState.HEALTHY
    assert (tmp_path / "agent-1.json").read_bytes() == original


@pytest.mark.parametrize(
    "observation",
    [
        process(create_time=NOW.timestamp() - 30),
        process(exe="/synthetic/bin/different"),
        process(username="different-user"),
    ],
)
def test_pid_reuse_or_optional_identity_conflict_rejects_enrichment(
    tmp_path: Path, observation: ProcessObservation
) -> None:
    write_lease(tmp_path)

    result = scan(tmp_path, observation)

    assert len(result.agents) == 1
    agent = result.agents[0]
    assert agent.lease_matched is False
    assert agent.provider is None
    assert agent.project is None
    assert agent.role is None
    assert agent.status is None
    assert agent.actionable is False
    assert agent.classification.state is AgentState.UNKNOWN
    expected_reason = (
        "PROCESS_VISIBILITY_INCOMPLETE"
        if observation.username == "different-user"
        else "PROCESS_IDENTITY_MISMATCH"
    )
    assert expected_reason in agent.classification.reason_codes


def test_mismatched_lease_does_not_consume_signature_positive_pid_replacement(
    tmp_path: Path,
) -> None:
    write_lease(tmp_path, create_time=NOW.timestamp() - 60)
    replacement = process(
        create_time=NOW.timestamp() - 30,
        signature_matched=True,
    )

    result = scan(tmp_path, replacement)

    assert len(result.agents) == 2
    lease_record = next(agent for agent in result.agents if agent.agent_id == "agent-1")
    replacement_record = next(agent for agent in result.agents if agent.agent_id is None)
    assert lease_record.lease_matched is False
    assert lease_record.classification.state is AgentState.UNKNOWN
    assert replacement_record.classification.state is AgentState.UNMANAGED
    assert replacement_record.process is not None
    assert replacement_record.process.identity.create_time == NOW.timestamp() - 30


def test_previous_boot_lease_is_interrupted_only_with_complete_visibility(
    tmp_path: Path,
) -> None:
    write_lease(tmp_path, boot_id="boot-previous")

    complete = scan(tmp_path)
    denied = ProcessObservation(pid=9999, error=ProcessReadError.ACCESS_DENIED)
    partial = scan(tmp_path, denied)

    assert complete.agents[0].classification.state is AgentState.INTERRUPTED
    assert partial.coverage.complete is False
    assert partial.agents[0].classification.state is AgentState.INTERRUPTED


def test_signature_only_process_is_unmanaged_and_plain_process_is_omitted(
    tmp_path: Path,
) -> None:
    signature = process(pid=5001, signature_matched=True)
    plain = process(pid=5002, signature_matched=False)

    result = scan(tmp_path, signature, plain)

    assert result.coverage.inspected_count == 2
    assert len(result.agents) == 1
    assert result.agents[0].classification.state is AgentState.UNMANAGED
    assert result.agents[0].agent_id is None
    assert result.agents[0].actionable is False


def test_access_denial_and_vanished_process_make_coverage_partial(tmp_path: Path) -> None:
    denied = ProcessObservation(pid=5001, error=ProcessReadError.ACCESS_DENIED)
    vanished = ProcessObservation(pid=5002, error=ProcessReadError.VANISHED)

    result = scan(tmp_path, denied, vanished)

    assert result.agents == ()
    assert result.coverage.inspected_count == 0
    assert result.coverage.denied_count == 1
    assert result.coverage.vanished_count == 1
    assert result.coverage.complete is False
    assert {warning.code for warning in result.coverage.warnings} == {
        "PROCESS_ACCESS_DENIED",
        "PROCESS_VANISHED",
    }


def test_repeated_process_warnings_are_aggregated_without_losing_counts(
    tmp_path: Path,
) -> None:
    denied = tuple(
        ProcessObservation(pid=pid, error=ProcessReadError.ACCESS_DENIED) for pid in range(1, 201)
    )

    result = scan(tmp_path, *denied)

    assert result.coverage.denied_count == 200
    assert len(result.coverage.warnings) == 1
    assert result.coverage.warnings[0].code == "PROCESS_ACCESS_DENIED"
    assert "200" in result.coverage.warnings[0].message


def test_unrelated_access_denial_does_not_downgrade_observed_live_agent(
    tmp_path: Path,
) -> None:
    write_lease(tmp_path)
    denied = ProcessObservation(pid=9999, error=ProcessReadError.ACCESS_DENIED)

    result = scan(tmp_path, process(), denied)

    assert result.coverage.complete is False
    assert result.agents[0].classification.state is AgentState.HEALTHY


def test_command_line_and_lease_warnings_are_redacted_before_result(
    tmp_path: Path,
) -> None:
    secret = "header.payload.signaturevalue"
    signature = process(
        signature_matched=True,
        cmdline=("agent", f"--api-key={secret}"),
    )
    (tmp_path / f"bad-{secret}.json").write_text("{", encoding="utf-8")

    result = scan(tmp_path, signature)

    rendered = result.model_dump_json()
    assert secret not in rendered
    assert "[REDACTED]" in rendered
    assert result.coverage.malformed_lease_count == 1


def test_scan_capture_time_is_used_for_process_snapshot_freshness(tmp_path: Path) -> None:
    captured_at = NOW + timedelta(minutes=20)
    write_lease(tmp_path, heartbeat_at=captured_at)

    result = scan(tmp_path, process(), captured_at=captured_at)

    agent = result.agents[0]
    assert agent.process is not None
    assert agent.process.observed_at == captured_at
    assert agent.classification.state is AgentState.HEALTHY
    assert "PROCESS_SNAPSHOT_TOO_OLD" not in agent.classification.reason_codes


@pytest.mark.parametrize(
    ("platform_name", "current_user", "observed", "expected"),
    [
        ("windows", "DOMAIN\\Alice", "domain\\alice", True),
        ("windows", "Alice", "DOMAIN\\ALICE", False),
        ("windows", "ONE\\Alice", "TWO\\Alice", False),
        ("linux", "Alice", "alice", False),
        ("linux", "1000", "1000", True),
        ("linux", "alice", None, False),
    ],
)
def test_current_user_matching_is_platform_conservative(
    platform_name: str,
    current_user: str,
    observed: str | None,
    expected: bool,
) -> None:
    assert is_current_user(observed, current_user, platform_name=platform_name) is expected


@pytest.mark.parametrize("username", ["other-user", None])
def test_other_or_unknown_user_signature_is_unknown_and_non_actionable(
    tmp_path: Path, username: str | None
) -> None:
    candidate = process(username=username, signature_matched=True)

    result = scan(tmp_path, candidate)

    assert len(result.agents) == 1
    assert result.agents[0].classification.state is AgentState.UNKNOWN
    assert result.agents[0].actionable is False
    if username is None:
        assert result.coverage.unknown_owner_count == 1
        assert result.coverage.complete is False
    else:
        assert result.coverage.other_user_count == 1


def test_boot_id_is_stable_injected_platform_evidence(tmp_path: Path) -> None:
    linux_boot = tmp_path / "boot_id"
    linux_boot.write_text("linux-boot-id\n", encoding="ascii")

    assert current_boot_id(platform_name="linux", linux_boot_id_path=linux_boot) == "linux-boot-id"
    assert current_boot_id(platform_name="windows", boot_time=lambda: 1234.5) == "windows-4994f9a0"
    assert current_boot_id(platform_name="darwin", boot_time=lambda: 1234.5) == "darwin-4994f9a0"


def test_psutil_provider_requests_only_low_cost_fields_and_never_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_attrs: list[tuple[str, ...]] = []

    class FakeMemory:
        rss = 2048

    class FakeProcess:
        info: dict[str, object] = {
            "pid": 42,
            "ppid": 1,
            "create_time": 123.0,
            "name": "python",
            "exe": "/synthetic/python",
            "username": "synthetic-user",
            "status": "running",
            "cpu_percent": 0.0,
            "memory_info": FakeMemory(),
            "cmdline": ["python", "worker.py"],
        }

    def fake_process_iter(*, attrs: list[str], ad_value: object):
        captured_attrs.append(tuple(attrs))
        return iter((FakeProcess(),))

    monkeypatch.setattr("zombie_killer_engine.scanner.psutil.process_iter", fake_process_iter)

    observations = PsutilProcessProvider(platform_name="linux").snapshot()

    assert len(observations) == 1
    assert "environ" not in captured_attrs[0]
    assert set(captured_attrs[0]) == {
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
    }


def test_windows_psutil_provider_takes_one_parent_snapshot_without_per_pid_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process_count = 512
    captured_attrs: list[tuple[str, ...]] = []
    parent_map_calls = 0

    class FakeMemory:
        rss = 2048

    class FakeProcess:
        def __init__(self, pid: int, attrs: list[str]) -> None:
            self.pid = pid
            values: dict[str, object] = {
                "pid": pid,
                "ppid": pid - 1,
                "create_time": 123.0 + pid,
                "name": "python",
                "exe": "/synthetic/python",
                "username": "synthetic-user",
                "status": "running",
                "cpu_percent": 0.0,
                "memory_info": FakeMemory(),
                "cmdline": ["python", "worker.py"],
            }
            self.info = {attribute: values[attribute] for attribute in attrs}

        def ppid(self) -> int:
            raise AssertionError("bulk Windows parent evidence must avoid per-process ppid()")

        def status(self) -> str:
            raise AssertionError("Windows suspension status must not be probed per process")

    def fake_process_iter(*, attrs: list[str], ad_value: object):
        del ad_value
        captured_attrs.append(tuple(attrs))
        return iter(FakeProcess(pid, attrs) for pid in range(1, process_count + 1))

    def fake_windows_parent_map() -> dict[int, int]:
        nonlocal parent_map_calls
        parent_map_calls += 1
        return {pid: pid - 1 for pid in range(1, process_count + 1)}

    monkeypatch.setattr(scanner_module.psutil, "process_iter", fake_process_iter)
    monkeypatch.setattr(
        scanner_module,
        "_windows_parent_map",
        fake_windows_parent_map,
        raising=False,
    )

    observations = PsutilProcessProvider(platform_name="windows").snapshot()

    assert len(observations) == process_count
    assert parent_map_calls == 1
    assert "ppid" not in captured_attrs[0]
    assert "status" not in captured_attrs[0]
    assert all(observation.ppid == observation.pid - 1 for observation in observations)
    assert all(observation.status == "unknown" for observation in observations)


def test_windows_psutil_provider_falls_back_when_bulk_parent_map_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent_calls = 0

    class FakeMemory:
        rss = 2048

    class FakeProcess:
        pid = 42
        info: dict[str, object] = {
            "pid": 42,
            "create_time": 123.0,
            "name": "python",
            "exe": "/synthetic/python",
            "username": "synthetic-user",
            "cpu_percent": 0.0,
            "memory_info": FakeMemory(),
            "cmdline": ["python", "worker.py"],
        }

        def ppid(self) -> int:
            nonlocal parent_calls
            parent_calls += 1
            return 7

    monkeypatch.setattr(
        scanner_module.psutil,
        "process_iter",
        lambda **_kwargs: iter((FakeProcess(),)),
    )
    monkeypatch.setattr(scanner_module, "_windows_parent_map", lambda: None)

    observation = PsutilProcessProvider(platform_name="windows").snapshot()[0]

    assert parent_calls == 1
    assert observation.ppid == 7
    assert observation.status == "unknown"


def test_windows_missing_parent_evidence_remains_access_denied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeProcess:
        pid = 42
        info: dict[str, object] = {"pid": 42}

        def ppid(self) -> int:
            raise psutil.AccessDenied(self.pid)

    monkeypatch.setattr(
        scanner_module.psutil,
        "process_iter",
        lambda **_kwargs: iter((FakeProcess(),)),
    )
    monkeypatch.setattr(scanner_module, "_windows_parent_map", lambda: {})

    assert PsutilProcessProvider(platform_name="windows").snapshot() == (
        ProcessObservation(pid=42, error=ProcessReadError.ACCESS_DENIED),
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows psutil private backend")
def test_windows_parent_snapshot_rejects_malformed_private_api_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        scanner_module.psutil._psplatform,
        "ppid_map",
        lambda: {
            42: 7,
            43: -1,
            44: True,
            True: 0,
            "45": 1,
        },
    )

    assert scanner_module._windows_parent_map() == {42: 7}


def test_psutil_iteration_race_is_reported_as_vanished(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def vanished_process_iter(*, attrs: list[str], ad_value: object):
        raise psutil.NoSuchProcess(42)

    monkeypatch.setattr(
        "zombie_killer_engine.scanner.psutil.process_iter",
        vanished_process_iter,
    )

    observations = PsutilProcessProvider().snapshot()

    assert observations == (ProcessObservation(pid=42, error=ProcessReadError.VANISHED),)


def test_psutil_provider_bounds_and_redacts_large_command_lines(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "header.payload.signaturevalue"

    class FakeMemory:
        rss = 2048

    class FakeProcess:
        info: dict[str, object] = {
            "pid": 42,
            "ppid": 1,
            "create_time": 123.0,
            "name": "python",
            "exe": "/synthetic/python",
            "username": "synthetic-user",
            "status": "running",
            "cpu_percent": 0.0,
            "memory_info": FakeMemory(),
            "cmdline": [f"--api-key={secret}", *("argument" for _ in range(200))],
        }

    def fake_process_iter(*, attrs: list[str], ad_value: object):
        return iter((FakeProcess(),))

    monkeypatch.setattr("zombie_killer_engine.scanner.psutil.process_iter", fake_process_iter)

    observations = PsutilProcessProvider().snapshot()

    assert len(observations) == 1
    assert observations[0].error is None
    assert len(observations[0].cmdline) == 128
    assert secret not in " ".join(observations[0].cmdline)


@pytest.mark.parametrize(
    "raw_executable",
    [
        r"c:\tools\api_key=synthetic\python.exe",
        "c:\\tools\\"
        + ".".join(
            (
                "ey" + "JhbGciOiJIUzI1NiJ9",
                "ey" + "JzdWIiOiJzeW50aGV0aWMifQ",
                "signature00",
            )
        )
        + "\\python.exe",
        "c:\\" + "a" * 4_100 + r"\python.exe",
    ],
    ids=["named-secret", "jwt-shaped", "longer-than-display-bound"],
)
def test_psutil_provider_separates_executable_authority_from_redacted_display(
    monkeypatch: pytest.MonkeyPatch,
    raw_executable: str,
) -> None:
    class FakeMemory:
        rss = 1

    class FakeProcess:
        info: dict[str, object] = {
            "pid": 42,
            "ppid": 1,
            "create_time": 123.0,
            "name": "python",
            "exe": raw_executable,
            "username": "synthetic-user",
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

    observation = PsutilProcessProvider(platform_name="windows").snapshot()[0]

    assert observation.exe != raw_executable
    assert len(observation.exe or "") <= 4_096
    assert (
        observation.executable_hash
        == hashlib.sha256(raw_executable.casefold().encode("utf-8")).hexdigest()
    )
    serialized_observation = observation.model_dump_json()
    assert raw_executable not in serialized_observation
    if "api_key=" in raw_executable:
        assert "api_key=synthetic" not in serialized_observation
    if "\\eyJ" in raw_executable:
        assert "eyJ" not in serialized_observation


def test_psutil_provider_skips_kernel_pseudo_pid_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeProcess:
        pid = 0
        info: dict[str, object] = {
            "pid": 0,
            "ppid": 0,
            "create_time": 0.0,
            "name": "System Idle Process",
            "exe": None,
            "username": None,
            "status": "running",
            "cpu_percent": 0.0,
            "memory_info": None,
            "cmdline": [],
        }

    monkeypatch.setattr(
        "zombie_killer_engine.scanner.psutil.process_iter",
        lambda **kwargs: iter((FakeProcess(),)),
    )

    assert PsutilProcessProvider().snapshot() == ()


def test_psutil_provider_converts_info_property_zombie_without_raising(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeProcess:
        pid = 42

        @property
        def info(self) -> dict[str, object]:
            raise psutil.ZombieProcess(self.pid)

    monkeypatch.setattr(
        "zombie_killer_engine.scanner.psutil.process_iter",
        lambda **kwargs: iter((FakeProcess(),)),
    )

    assert PsutilProcessProvider().snapshot() == (ProcessObservation(pid=42, status="zombie"),)


def test_psutil_provider_drops_nonpositive_pid_from_iteration_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def denied_process_iter(*, attrs: list[str], ad_value: object):
        raise psutil.AccessDenied(0)

    monkeypatch.setattr(
        "zombie_killer_engine.scanner.psutil.process_iter",
        denied_process_iter,
    )

    provider = PsutilProcessProvider()

    assert provider.snapshot() == ()
    assert provider.pid_enumeration_complete is False


def test_psutil_provider_error_pid_conversion_never_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import zombie_killer_engine.scanner as scanner_module

    class MalformedAccessDenied(Exception):
        @property
        def pid(self) -> int:
            raise RuntimeError("unreadable pid")

    def denied_process_iter(*, attrs: list[str], ad_value: object):
        raise MalformedAccessDenied

    monkeypatch.setattr(scanner_module.psutil, "AccessDenied", MalformedAccessDenied)
    monkeypatch.setattr(scanner_module.psutil, "process_iter", denied_process_iter)

    provider = PsutilProcessProvider()

    assert provider.snapshot() == ()
    assert provider.pid_enumeration_complete is False


@pytest.mark.skipif(os.name != "nt", reason="Windows provider smoke test")
def test_real_windows_provider_skips_nonpositive_pids() -> None:
    observations = PsutilProcessProvider().snapshot()

    assert all(observation.pid > 0 for observation in observations)


@pytest.mark.skipif(os.name != "nt", reason="Windows provider performance regression")
def test_real_windows_provider_snapshot_is_bounded_and_keeps_parent_evidence(
    tmp_path: Path,
) -> None:
    provider = PsutilProcessProvider(platform_name="windows")
    started_at = time.perf_counter()

    observations = provider.snapshot()

    elapsed_seconds = time.perf_counter() - started_at
    successful = [observation for observation in observations if observation.error is None]
    assert observations
    assert successful
    assert all(observation.ppid is not None for observation in successful)
    assert elapsed_seconds < 20.0, (
        f"Windows process snapshot took {elapsed_seconds:.2f}s for {len(observations)} processes"
    )
    result = scan_agents(
        tmp_path,
        process_provider=SnapshotProcessProvider(
            observations,
            pid_enumeration_complete=provider.pid_enumeration_complete,
        ),
        current_boot="benchmark-boot",
        current_user=scanner_module._default_current_user("windows"),
        platform_name="windows",
        captured_at=NOW,
        identity_fingerprint_provider=lambda _pid, _user, _platform: "a" * 64,
    )
    assert result.coverage.inspected_count == len(successful)
    assert result.coverage.denied_count == sum(
        observation.error is ProcessReadError.ACCESS_DENIED for observation in observations
    )
    assert result.coverage.vanished_count == sum(
        observation.error is ProcessReadError.VANISHED for observation in observations
    )


@pytest.mark.parametrize(
    "switch",
    ["--api-key", "-client-secret", "--access-token", "--refresh_token"],
)
def test_split_sensitive_switch_redacts_following_argv_value(tmp_path: Path, switch: str) -> None:
    secret = "plain-sensitive-value"
    candidate = process(
        signature_matched=True,
        cmdline=("agent", switch, secret, "safe-value"),
    )

    result = scan(tmp_path, candidate)

    assert secret not in result.model_dump_json()
    assert result.agents[0].process is not None
    assert "[REDACTED]" in result.agents[0].process.cmdline
    assert "safe-value" in result.agents[0].process.cmdline


def test_unrelated_denial_does_not_hide_confirmed_missing_parent(
    tmp_path: Path,
) -> None:
    write_lease(
        tmp_path,
        create_time=NOW.timestamp() - 600,
        heartbeat_at=NOW - timedelta(minutes=5),
        expected_parent_pid=4000,
    )
    denied = ProcessObservation(pid=9999, error=ProcessReadError.ACCESS_DENIED)

    result = scan(tmp_path, process(create_time=NOW.timestamp() - 600), denied)

    assert result.coverage.complete is False
    assert result.agents[0].classification.state is AgentState.ORPHANED
    assert "EXPECTED_PARENT_ABSENT" in result.agents[0].classification.reason_codes


@pytest.mark.parametrize(
    ("owner_live", "expected_state"),
    [(True, AgentState.STALE), (False, AgentState.ORPHANED)],
)
def test_expected_owner_is_resolved_from_owner_lease_identity_second_pass(
    tmp_path: Path,
    owner_live: bool,
    expected_state: AgentState,
) -> None:
    write_lease(
        tmp_path,
        agent_id="owner-agent",
        pid=5000,
        create_time=NOW.timestamp() - 120,
    )
    write_lease(
        tmp_path,
        agent_id="child-agent",
        pid=5001,
        create_time=NOW.timestamp() - 600,
        heartbeat_at=NOW - timedelta(minutes=5),
        expected_owner="owner-agent",
    )
    observations = [process(pid=5001, create_time=NOW.timestamp() - 600)]
    if owner_live:
        observations.append(process(pid=5000, create_time=NOW.timestamp() - 120))

    result = scan(tmp_path, *observations)

    child = next(agent for agent in result.agents if agent.agent_id == "child-agent")
    assert child.classification.state is expected_state
    if not owner_live:
        assert "EXPECTED_OWNER_ABSENT" in child.classification.reason_codes


@pytest.mark.parametrize("relationship", ["parent", "owner"])
@pytest.mark.parametrize("pid_enumeration_complete", [True, False])
def test_true_os_zombie_cannot_satisfy_expected_liveness(
    tmp_path: Path,
    relationship: str,
    pid_enumeration_complete: bool,
) -> None:
    child_kwargs: dict[str, object] = {}
    if relationship == "parent":
        child_kwargs["expected_parent_pid"] = 5000
    else:
        write_lease(
            tmp_path,
            agent_id="owner-agent",
            pid=5000,
            create_time=NOW.timestamp() - 120,
        )
        child_kwargs["expected_owner"] = "owner-agent"
    write_lease(
        tmp_path,
        agent_id="child-agent",
        pid=5001,
        create_time=NOW.timestamp() - 600,
        heartbeat_at=NOW - timedelta(minutes=5),
        **child_kwargs,
    )
    zombie = process(
        pid=5000,
        create_time=NOW.timestamp() - 120,
    ).model_copy(update={"status": "zombie"})

    result = scan(
        tmp_path,
        process(pid=5001, create_time=NOW.timestamp() - 600),
        zombie,
        pid_enumeration_complete=pid_enumeration_complete,
    )

    child = next(agent for agent in result.agents if agent.agent_id == "child-agent")
    assert child.classification.state is AgentState.ORPHANED
    assert f"EXPECTED_{relationship.upper()}_ABSENT" in (child.classification.reason_codes)


def test_partial_os_zombie_is_defunct_and_never_actionable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import zombie_killer_engine.scanner as scanner_module

    write_lease(tmp_path)

    class FakeProcess:
        info: dict[str, object] = {
            "pid": 4242,
            "ppid": 4000,
            "create_time": NOW.timestamp() - 60,
            "name": "agent",
            "exe": scanner_module._UNAVAILABLE,
            "username": "synthetic-user",
            "status": "zombie",
            "cpu_percent": scanner_module._UNAVAILABLE,
            "memory_info": scanner_module._UNAVAILABLE,
            "cmdline": scanner_module._UNAVAILABLE,
        }

    monkeypatch.setattr(
        scanner_module.psutil,
        "process_iter",
        lambda **kwargs: iter((FakeProcess(),)),
    )
    result = scan_agents(
        tmp_path,
        process_provider=PsutilProcessProvider(),
        current_boot="boot-current",
        current_user="synthetic-user",
        platform_name="linux",
        captured_at=NOW,
    )

    assert result.agents[0].classification.state is AgentState.DEFUNCT
    assert result.agents[0].actionable is False


@pytest.mark.parametrize(
    ("lifecycle", "state"),
    [
        ("completed", AgentState.COMPLETED),
        ("failed", AgentState.FAILED),
        ("cancelled", AgentState.CANCELLED),
    ],
)
def test_terminal_lease_is_history_and_non_actionable(
    tmp_path: Path, lifecycle: str, state: AgentState
) -> None:
    write_lease(
        tmp_path,
        create_time=NOW.timestamp() - 7200,
        heartbeat_at=NOW - timedelta(hours=1),
        lifecycle=lifecycle,
        terminal_at=NOW - timedelta(hours=1),
    )

    result = scan(tmp_path)

    agent = result.agents[0]
    assert agent.lifecycle is LeaseLifecycle(lifecycle)
    assert agent.classification.state is state
    assert f"TERMINAL_{lifecycle.upper()}" in agent.classification.reason_codes
    assert agent.actionable is False


def test_true_os_zombie_overrides_terminal_lease_history(tmp_path: Path) -> None:
    write_lease(
        tmp_path,
        lifecycle="completed",
        terminal_at=NOW - timedelta(seconds=5),
    )
    zombie = process().model_copy(update={"status": "zombie"})

    result = scan(tmp_path, zombie)

    agent = result.agents[0]
    assert agent.classification.state is AgentState.DEFUNCT
    assert agent.classification.reason_codes == ("OS_ZOMBIE",)
    assert agent.actionable is False


def test_default_user_resolution_ignores_environment_fallbacks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import zombie_killer_engine.scanner as scanner_module

    for key in ("LOGNAME", "USER", "LNAME", "USERNAME"):
        monkeypatch.setenv(key, "environment-derived-user")
    monkeypatch.setattr(
        scanner_module.psutil,
        "Process",
        lambda: (_ for _ in ()).throw(psutil.AccessDenied()),
    )

    resolved = scanner_module._default_current_user(platform.system())

    assert resolved
    assert resolved != "environment-derived-user"


def test_windows_protected_process_fingerprint_failure_is_process_local(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def denied(*_args: object, **_kwargs: object) -> str:
        raise OSError("protected process")

    monkeypatch.setattr(scanner_module, "cancellation_user_fingerprint", denied)

    snapshot = scan_agents(
        tmp_path / "leases",
        process_provider=SnapshotProcessProvider(
            (
                process(
                    pid=4,
                    username="SYSTEM",
                    exe="System",
                    signature_matched=True,
                ),
            )
        ),
        current_boot="boot-current",
        current_user="synthetic-user",
        platform_name="windows",
        captured_at=NOW,
    )

    assert len(snapshot.agents) == 1
    assert snapshot.agents[0].process.identity is not None
    assert (
        snapshot.agents[0].process.identity.executable_hash == hashlib.sha256(b"system").hexdigest()
    )
    assert snapshot.agents[0].process.identity.user_hash is None


def test_scanned_identity_contains_cross_platform_executable_fingerprint(
    tmp_path: Path,
) -> None:
    executable = "C:/Synthetic/AGENT.EXE"

    snapshot = scan_agents(
        tmp_path / "leases",
        process_provider=SnapshotProcessProvider(
            (
                process(
                    username="synthetic-user",
                    exe=executable,
                    signature_matched=True,
                ),
            )
        ),
        identity_fingerprint_provider=lambda _pid, _user, _platform: "a" * 64,
        current_boot="boot-current",
        current_user="synthetic-user",
        platform_name="windows",
        captured_at=NOW,
    )

    scanned_identity = snapshot.agents[0].process.identity
    assert scanned_identity is not None
    assert (
        scanned_identity.executable_hash
        == hashlib.sha256(executable.casefold().encode("utf-8")).hexdigest()
    )
    assert scanned_identity.user_hash == "a" * 64


def test_identity_fingerprint_denial_is_explicit_incomplete_and_nonactionable(
    tmp_path: Path,
) -> None:
    lease_dir = tmp_path / "leases"
    write_lease(
        lease_dir,
        pid=4242,
        user="synthetic-user",
        executable="C:/synthetic/agent.exe",
    )

    def denied(_pid: int, _user: str, _platform_name: str) -> str:
        raise OSError("Bearer synthetic-scanner-fixture")

    result = scan_agents(
        lease_dir,
        process_provider=SnapshotProcessProvider(
            (
                process(
                    pid=4242,
                    username="synthetic-user",
                    exe="C:/synthetic/agent.exe",
                ),
            )
        ),
        identity_fingerprint_provider=denied,
        current_boot="boot-current",
        current_user="synthetic-user",
        platform_name="windows",
        captured_at=NOW,
    )

    assert result.coverage.identity_denied_count == 1
    assert result.coverage.complete is False
    assert result.agents[0].actionable is False
    assert result.agents[0].process is not None
    assert result.agents[0].process.identity is not None
    assert (
        result.agents[0].process.identity.executable_hash
        == hashlib.sha256(b"c:/synthetic/agent.exe").hexdigest()
    )
    assert result.agents[0].process.identity.user_hash is None
    assert result.agents[0].process.identity_authorization_complete is False
    assert result.coverage.warnings[0].code == "PROCESS_IDENTITY_DENIED"
    assert "must-not-appear" not in result.model_dump_json()
