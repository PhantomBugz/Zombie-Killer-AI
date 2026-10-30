from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from contextlib import closing, suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path

import psutil
import pytest
from typer.testing import CliRunner

from zombie_killer_engine import cli
from zombie_killer_engine import service as service_module
from zombie_killer_engine.paths import AppPaths
from zombie_killer_engine.service import (
    Capability,
    ClientKind,
    EngineService,
    ErrorCode,
    Method,
    RequestContext,
    ServiceFault,
)

runner = CliRunner()


def test_help_lists_safe_public_commands_and_hides_protocol_commands() -> None:
    result = runner.invoke(cli.app, ["--help"])

    assert result.exit_code == 0
    assert "scan" in result.stdout
    assert "doctor" in result.stdout
    assert "vault" in result.stdout
    assert "demo" in result.stdout
    assert "protocol-once" not in result.stdout
    assert "stdio" not in result.stdout


_NAMED_SECRET_PREFIX = "".join(("to", "ken="))


def _isolate_internal_cli_service(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Keep protocol entry-point tests out of the operator's app state."""
    paths = cli._internal_app_paths((tmp_path / "protocol-state").absolute())
    monkeypatch.setattr(cli, "build_service", lambda: EngineService(paths=paths))
    monkeypatch.setattr(
        cli.AppPaths,
        "for_current_user",
        lambda: pytest.fail("protocol test must not resolve the operator's app state"),
    )


def _action_receipt_fixture(
    *,
    outcome: str,
    certainty: str,
    action_issued: bool | None,
    partial_failures: tuple[str, ...] = (),
) -> dict[str, object]:
    return {
        "receipt_id": "receipt-1",
        "plan_id": "plan-1",
        "outcome": outcome,
        "certainty": certainty,
        "action_issued": action_issued,
        "partial_failures": list(partial_failures),
        "created_at": "2026-08-14T12:00:00+00:00",
    }


@pytest.mark.parametrize(
    ("command", "attribute"), [("protocol-once", "serve_once"), ("stdio", "serve_stdio")]
)
def test_internal_protocol_launch_injects_trusted_controller_context(
    command: str,
    attribute: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    observed: list[object] = []
    _isolate_internal_cli_service(monkeypatch, tmp_path)

    def serve(_service: EngineService, *, context: object) -> int:
        observed.append(context)
        return 0

    monkeypatch.setattr(cli, attribute, serve)
    result = runner.invoke(cli.app, [command])

    assert result.exit_code == 0
    assert len(observed) == 1
    context = observed[0]
    assert isinstance(context, RequestContext)
    assert context.client is ClientKind.CONTROLLER
    assert context.capability is Capability.EXECUTION
    assert context.local_control is True


def test_protocol_once_starts_broker_parent_watch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    watched: list[int] = []
    _isolate_internal_cli_service(monkeypatch, tmp_path)
    monkeypatch.setattr(cli, "_start_parent_watch", watched.append)
    monkeypatch.setattr(cli, "serve_once", lambda _service, *, context: 0)

    result = runner.invoke(cli.app, ["protocol-once", "--parent-pid", "4242"])

    assert result.exit_code == 0
    assert watched == [4242]


def test_protocol_once_internal_state_root_uses_only_fixed_subdirectories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = (tmp_path / "packaging-smoke").absolute()
    observed: list[AppPaths] = []

    def build(*, paths: AppPaths) -> EngineService:
        observed.append(paths)
        return EngineService(paths=paths)

    def serve(service: EngineService, *, context: object) -> int:
        service.close()
        return 0

    monkeypatch.setattr(cli, "build_service", build)
    monkeypatch.setattr(cli, "serve_once", serve)
    monkeypatch.setattr(
        cli.AppPaths,
        "for_current_user",
        lambda: pytest.fail("default user paths must not be resolved for packaging smoke"),
    )

    result = runner.invoke(
        cli.app,
        ["protocol-once", "--internal-state-root", str(root)],
    )

    assert result.exit_code == 0
    assert observed == [
        AppPaths(
            data_dir=root / "data",
            state_dir=root / "state",
            runtime_dir=root / "runtime",
            backups_dir=root / "data" / "backups",
            graveyard_dir=root / "data" / "graveyard",
        )
    ]


def test_protocol_once_internal_state_root_rejects_relative_path_before_build(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    built = False

    def build() -> EngineService:
        nonlocal built
        built = True
        return EngineService()

    monkeypatch.setattr(cli, "build_service", build)

    result = runner.invoke(
        cli.app,
        ["protocol-once", "--internal-state-root", "relative-smoke-state"],
    )

    assert result.exit_code != 0
    assert "absolute" in result.output.casefold()
    assert built is False


def test_parent_watch_rejects_a_pid_that_is_not_the_direct_parent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli.os, "getppid", lambda: 111)

    with pytest.raises(cli.CliFailure, match="parent identity"):
        cli._capture_parent_identity(222)


def test_protocol_sidecar_does_not_survive_its_broker_parent() -> None:
    helper_code = """
import json, os, subprocess, sys
child = subprocess.Popen(
    [
        sys.executable,
        '-I',
        '-m',
        'zombie_killer_engine',
        'protocol-once',
        f'--parent-pid={os.getpid()}',
    ],
    stdin=subprocess.PIPE,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    text=True,
)
assert child.stdin is not None
request = {
    'protocol_version': '1.0',
    'request_id': '11111111-1111-4111-8111-111111111111',
    'method': 'scan.list',
    'payload': {'include_unmanaged': False, 'limit': 1},
}
child.stdin.write(json.dumps(request, separators=(',', ':')) + '\\n')
child.stdin.close()
print(child.pid, flush=True)
"""
    helper = subprocess.run(
        [sys.executable, "-I", "-c", helper_code],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    child_pid = int(helper.stdout.strip())
    deadline = time.monotonic() + 5
    try:
        while time.monotonic() < deadline:
            if not psutil.pid_exists(child_pid):
                break
            try:
                process = psutil.Process(child_pid)
                stopped = not process.is_running() or process.status() == psutil.STATUS_ZOMBIE
            except psutil.NoSuchProcess:
                stopped = True
            if stopped:
                break
            time.sleep(0.05)
        else:
            pytest.fail("protocol sidecar survived its broker parent")
    finally:
        if psutil.pid_exists(child_pid):
            with suppress(psutil.NoSuchProcess):
                psutil.Process(child_pid).kill()


def test_scan_json_is_valid_and_preserves_candidate_language(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def call(method: Method, _payload: dict[str, object], **_kwargs: object) -> object:
        assert method is Method.SCAN_LIST
        return {
            "agents": [
                {
                    "agent_id": None,
                    "state": "unmanaged",
                    "evidence_grade": "signature_only",
                    "pid": 123,
                    "process_name": "fixture",
                    "actionable": False,
                }
            ],
            "coverage": {"complete": False, "warnings": []},
            "returned": 1,
            "total": 1,
        }

    monkeypatch.setattr(cli, "call_service", call)

    json_result = runner.invoke(cli.app, ["scan", "--json"])
    human_result = runner.invoke(cli.app, ["scan"])

    assert json_result.exit_code == 0
    assert json.loads(json_result.stdout)["agents"][0]["state"] == "unmanaged"
    assert human_result.exit_code == 0
    assert "candidate" in human_result.stdout.casefold()
    assert "confirmed" not in human_result.stdout.casefold()
    assert human_result.stderr == ""


def test_doctor_json_is_valid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli,
        "call_service",
        lambda method, _payload, **_kwargs: {
            "healthy": method is Method.DOCTOR,
            "checks": [],
            "warnings": [],
        },
    )

    result = runner.invoke(cli.app, ["doctor", "--json"])

    assert result.exit_code == 0
    assert json.loads(result.stdout) == {"checks": [], "healthy": True, "warnings": []}


def test_action_plan_sends_exact_reviewed_process_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[tuple[Method, dict[str, object], object]] = []
    instance_id = "a" * 64

    def call(
        method: Method,
        payload: dict[str, object],
        **kwargs: object,
    ) -> object:
        observed.append((method, payload, kwargs.get("capability")))
        return {
            "plan_id": "plan-1",
            "digest": "b" * 64,
            "expires_at": "2026-08-13T12:00:30+00:00",
            "consequences": ["The exact reviewed process will be terminated."],
            "warnings": [],
            "target": {
                "pid": 4242,
                "process_instance_id": instance_id,
                "state": "stale",
            },
        }

    monkeypatch.setattr(cli, "call_service", call)

    result = runner.invoke(
        cli.app,
        [
            "action",
            "plan",
            "agent-1",
            "--pid",
            "4242",
            "--process-instance-id",
            instance_id,
            "--mode",
            "terminate",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.stderr
    assert observed == [
        (
            Method.ACTION_PLAN,
            {
                "agent_id": "agent-1",
                "mode": "terminate",
                "target": {"pid": 4242, "process_instance_id": instance_id},
            },
            Capability.PLANNING,
        )
    ]
    assert json.loads(result.stdout)["target"]["process_instance_id"] == instance_id


@pytest.mark.parametrize(
    ("pid", "instance_id"),
    [
        ("0", "a" * 64),
        ("-1", "a" * 64),
        ("4294967296", "a" * 64),
        (f"{_NAMED_SECRET_PREFIX}private-malformed-pid", "a" * 64),
        ("4242", f"{_NAMED_SECRET_PREFIX}private-malformed-instance"),
        ("4242", "A" * 64),
        ("4242", "g" * 64),
    ],
)
def test_action_plan_rejects_malformed_identity_without_echoing_it(
    pid: str,
    instance_id: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def call(*_args: object, **_kwargs: object) -> object:
        nonlocal calls
        calls += 1
        raise AssertionError("invalid identities must not reach the service")

    monkeypatch.setattr(cli, "call_service", call)

    result = runner.invoke(
        cli.app,
        [
            "action",
            "plan",
            "agent-1",
            "--pid",
            pid,
            "--process-instance-id",
            instance_id,
        ],
    )

    assert result.exit_code == 2
    assert calls == 0
    assert "reviewed process identity is invalid" in result.stderr.casefold()
    assert pid not in result.stderr
    assert instance_id not in result.stderr


def test_action_target_accepts_the_maximum_unsigned_32_bit_pid() -> None:
    instance_id = "a" * 64

    assert cli._validated_action_target("4294967295", instance_id) == {
        "pid": 4_294_967_295,
        "process_instance_id": instance_id,
    }


@pytest.mark.parametrize(
    ("arguments", "missing_option"),
    [
        (["agent-1"], "--pid"),
        (["agent-1", "--pid", "4242"], "--process-instance-id"),
    ],
)
def test_action_plan_requires_both_reviewed_identity_fields_before_dispatch(
    arguments: list[str],
    missing_option: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def call(*_args: object, **_kwargs: object) -> object:
        nonlocal calls
        calls += 1
        raise AssertionError("incomplete identities must not reach the service")

    monkeypatch.setattr(cli, "call_service", call)

    result = runner.invoke(cli.app, ["action", "plan", *arguments])

    assert result.exit_code == 2
    assert calls == 0
    assert missing_option in result.stderr


@pytest.mark.parametrize(
    ("current_pid", "current_instance_id"),
    [
        (4243, "b" * 64),
        (4242, "b" * 64),
    ],
)
def test_action_plan_cli_rejects_restarted_or_reused_process_identity(
    current_pid: int,
    current_instance_id: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reviewed_pid = 4242
    reviewed_instance_id = "a" * 64

    def plan(
        payload: service_module.StrictModel,
        _context: RequestContext,
    ) -> object:
        body = payload.model_dump(mode="json")
        if body["target"] != {
            "pid": current_pid,
            "process_instance_id": current_instance_id,
        }:
            raise ServiceFault(
                ErrorCode.TARGET_CHANGED,
                "The reviewed process instance at C:/private/action.db is no longer "
                "the current target; --token=synthetic-secret.",
                details={"reason": "process_instance_changed"},
            )
        raise AssertionError("a stale reviewed identity must not produce a plan")

    paths = AppPaths(
        data_dir=tmp_path / "data",
        state_dir=tmp_path / "state",
        runtime_dir=tmp_path / "runtime",
        backups_dir=tmp_path / "backups",
        graveyard_dir=tmp_path / "graveyard",
    )
    service = EngineService(handlers={Method.ACTION_PLAN: plan}, paths=paths)
    monkeypatch.setattr(cli, "build_service", lambda: service)

    result = runner.invoke(
        cli.app,
        [
            "action",
            "plan",
            "agent-1",
            "--pid",
            str(reviewed_pid),
            "--process-instance-id",
            reviewed_instance_id,
            "--mode",
            "terminate",
        ],
    )

    assert result.exit_code == 4
    assert result.stderr == "Error: [LOCAL PATH]\n"
    assert "C:/private/action.db" not in result.stderr
    assert "synthetic-secret" not in result.stderr
    assert reviewed_instance_id not in result.stderr
    assert current_instance_id not in result.stderr


def test_repeated_call_service_calls_leave_no_memory_sessions_or_database_handles(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = AppPaths(
        data_dir=tmp_path / "data",
        state_dir=tmp_path / "state",
        runtime_dir=tmp_path / "runtime",
        backups_dir=tmp_path / "backups",
        graveyard_dir=tmp_path / "graveyard",
    )
    monkeypatch.setattr(cli.AppPaths, "for_current_user", lambda: paths)

    for _index in range(25):
        result = cli.call_service(Method.SYSTEM_INFO, {})
        assert isinstance(result, dict)

    database = paths.state_dir / "zombie-killer.sqlite3"
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT COUNT(*) FROM memory_sessions").fetchone()[0] == 0
    open_files = {Path(item.path) for item in psutil.Process().open_files()}
    assert database not in open_files


def test_call_service_redacts_dispatch_error_when_close_also_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    close_attempts: list[bool] = []

    def fail_close() -> None:
        close_attempts.append(True)
        raise RuntimeError("synthetic close failure")

    service = EngineService(close_callback=fail_close)

    def fail_dispatch(_envelope: object, *, context: object) -> object:
        del context
        raise RuntimeError("synthetic dispatch failure")

    monkeypatch.setattr(service, "dispatch", fail_dispatch)
    monkeypatch.setattr(cli, "build_service", lambda: service)

    with pytest.raises(cli.CliFailure) as captured:
        cli.call_service(Method.SYSTEM_INFO, {})

    assert close_attempts == [True]
    assert captured.value.exit_code == 4
    assert captured.value.message == "The local engine request failed safely."
    assert "synthetic dispatch failure" not in str(captured.value)
    assert "synthetic close failure" not in str(captured.value)


@pytest.mark.parametrize(
    "surface",
    ["scan", "doctor", "action-plan", "action-execute", "vault"],
)
@pytest.mark.parametrize("failure_type", [RuntimeError, cli.CliFailure, cli._ResponseFailure])
def test_public_service_commands_redact_unexpected_build_errors(
    surface: str,
    failure_type: type[Exception],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = "fixture-build-value"
    note_marker = "fixture-build-note-value"
    private_path = "C:/private/build-service.db"

    def fail_build() -> EngineService:
        error = failure_type(f"{private_path} {_NAMED_SECRET_PREFIX}{marker}")
        error.add_note(f"C:/private/build-note.db {_NAMED_SECRET_PREFIX}{note_marker}")
        raise error

    monkeypatch.setattr(cli, "build_service", fail_build)
    arguments = _public_service_arguments(surface, tmp_path)

    result = runner.invoke(cli.app, arguments)

    assert result.exit_code == 4
    assert result.stdout == ""
    assert result.stderr == "Error: The local engine request failed safely.\n"
    assert private_path not in result.output
    assert marker not in result.output
    assert note_marker not in result.output
    assert "traceback" not in result.output.casefold()


@pytest.mark.parametrize(
    "surface",
    ["scan", "doctor", "action-plan", "action-execute", "vault"],
)
@pytest.mark.parametrize("failure_type", [RuntimeError, cli.CliFailure, cli._ResponseFailure])
def test_public_service_commands_redact_unexpected_dispatch_errors_and_close(
    surface: str,
    failure_type: type[Exception],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    close_attempts: list[bool] = []
    marker = "fixture-dispatch-value"
    note_marker = "fixture-dispatch-note-value"
    close_marker = "fixture-close-value"
    private_path = "C:/private/dispatch.db"

    def fail_close() -> None:
        close_attempts.append(True)
        raise RuntimeError(f"C:/private/close.db {_NAMED_SECRET_PREFIX}{close_marker}")

    service = EngineService(close_callback=fail_close)

    def fail_dispatch(_envelope: object, *, context: object) -> object:
        del context
        error = failure_type(f"{private_path} {_NAMED_SECRET_PREFIX}{marker}")
        error.add_note(f"C:/private/dispatch-note.db {_NAMED_SECRET_PREFIX}{note_marker}")
        raise error

    monkeypatch.setattr(service, "dispatch", fail_dispatch)
    monkeypatch.setattr(cli, "build_service", lambda: service)
    arguments = _public_service_arguments(surface, tmp_path)

    result = runner.invoke(cli.app, arguments)

    assert result.exit_code == 4
    assert close_attempts == [True]
    assert result.stdout == ""
    assert result.stderr == "Error: The local engine request failed safely.\n"
    assert private_path not in result.output
    assert marker not in result.output
    assert note_marker not in result.output
    assert close_marker not in result.output
    assert "traceback" not in result.output.casefold()


def test_call_service_does_not_trust_a_response_failure_raised_by_returned_object(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_path = "C:/private/returned-object.db"

    class SpoofedResponse:
        @property
        def ok(self) -> bool:
            raise cli._ResponseFailure(private_path)

    service = EngineService()

    def return_spoofed_response(_envelope: object, *, context: object) -> object:
        del context
        return SpoofedResponse()

    monkeypatch.setattr(service, "dispatch", return_spoofed_response)
    monkeypatch.setattr(cli, "build_service", lambda: service)

    with pytest.raises(cli.CliFailure) as raised:
        cli.call_service(Method.SYSTEM_INFO, {})

    assert raised.value.exit_code == 4
    assert raised.value.message == "The local engine request failed safely."
    assert private_path not in raised.value.message


def test_call_service_does_not_trust_a_non_envelope_response_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_path = "C:/private/fake-response.db"

    class SpoofedError:
        message = private_path

    class SpoofedResponse:
        ok = False
        error = SpoofedError()

    service = EngineService()

    def return_spoofed_response(_envelope: object, *, context: object) -> object:
        del context
        return SpoofedResponse()

    monkeypatch.setattr(service, "dispatch", return_spoofed_response)
    monkeypatch.setattr(cli, "build_service", lambda: service)

    with pytest.raises(cli.CliFailure) as raised:
        cli.call_service(Method.SYSTEM_INFO, {})

    assert raised.value.exit_code == 4
    assert raised.value.message == "The local engine request failed safely."
    assert private_path not in raised.value.message


def test_call_service_does_not_invoke_untrusted_exception_add_note(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    close_attempts: list[bool] = []
    private_path = "C:/private/add-note.db"

    class AddNoteTrap(RuntimeError):
        def add_note(self, note: str) -> None:
            del note
            raise cli._ResponseFailure(private_path)

    def fail_close() -> None:
        close_attempts.append(True)
        raise RuntimeError("synthetic close failure")

    service = EngineService(close_callback=fail_close)

    def fail_dispatch(_envelope: object, *, context: object) -> object:
        del context
        raise AddNoteTrap("synthetic dispatch failure")

    monkeypatch.setattr(service, "dispatch", fail_dispatch)
    monkeypatch.setattr(cli, "build_service", lambda: service)

    with pytest.raises(cli.CliFailure) as raised:
        cli.call_service(Method.SYSTEM_INFO, {})

    assert close_attempts == [True]
    assert raised.value.exit_code == 4
    assert raised.value.message == "The local engine request failed safely."
    assert private_path not in raised.value.message


def _public_service_arguments(surface: str, tmp_path: Path) -> list[str]:
    if surface == "scan":
        return ["scan"]
    if surface == "doctor":
        return ["doctor"]
    if surface == "action-plan":
        return [
            "action",
            "plan",
            "agent-1",
            "--pid",
            "4242",
            "--process-instance-id",
            "a" * 64,
        ]
    if surface == "action-execute":
        return ["action", "execute", "plan-1", "a" * 64, "--confirm"]
    vault_path = tmp_path / "vault.json"
    vault_path.write_text("{}", encoding="utf-8")
    return ["vault", "inspect", str(vault_path)]


def test_call_service_preserves_non_ok_response_when_close_also_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    close_attempts: list[bool] = []

    def fail_close() -> None:
        close_attempts.append(True)
        raise RuntimeError("synthetic close failure")

    service = EngineService(close_callback=fail_close)
    monkeypatch.setattr(cli, "build_service", lambda: service)

    with pytest.raises(cli.CliFailure) as captured:
        cli.call_service(Method.SYSTEM_INFO, {"unexpected": True})

    assert captured.value.exit_code == 4
    assert close_attempts == [True]
    assert captured.value.__notes__ == ["Engine service cleanup also failed."]


def test_call_service_redacts_close_error_when_it_is_the_only_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    close_attempts: list[bool] = []

    def fail_close() -> None:
        close_attempts.append(True)
        raise RuntimeError("C:/private/token=synthetic-secret")

    service = EngineService(close_callback=fail_close)
    monkeypatch.setattr(cli, "build_service", lambda: service)

    with pytest.raises(cli.CliFailure) as captured:
        cli.call_service(Method.SYSTEM_INFO, {})

    assert close_attempts == [True]
    assert captured.value.exit_code == 4
    assert captured.value.message == "The local engine could not release its resources safely."
    assert "private" not in str(captured.value).casefold()
    assert "synthetic-secret" not in str(captured.value)


@pytest.mark.parametrize("control_flow", [KeyboardInterrupt, SystemExit])
def test_call_service_propagates_control_flow_from_close(
    control_flow: type[BaseException],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    close_attempts: list[bool] = []

    def interrupt_close() -> None:
        close_attempts.append(True)
        raise control_flow()

    service = EngineService(close_callback=interrupt_close)
    monkeypatch.setattr(cli, "build_service", lambda: service)

    with pytest.raises(control_flow):
        cli.call_service(Method.SYSTEM_INFO, {})

    assert close_attempts == [True]


class _SyntheticBaseException(BaseException):
    pass


@pytest.mark.parametrize(
    "control_flow",
    [KeyboardInterrupt, SystemExit, _SyntheticBaseException],
)
def test_call_service_propagates_control_flow_from_build(
    control_flow: type[BaseException],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def interrupt_build() -> EngineService:
        raise control_flow()

    monkeypatch.setattr(cli, "build_service", interrupt_build)

    with pytest.raises(control_flow):
        cli.call_service(Method.SYSTEM_INFO, {})


@pytest.mark.parametrize(
    "control_flow",
    [KeyboardInterrupt, SystemExit, _SyntheticBaseException],
)
def test_call_service_propagates_control_flow_from_dispatch_and_closes(
    control_flow: type[BaseException],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    close_attempts: list[bool] = []
    service = EngineService(close_callback=lambda: close_attempts.append(True))

    def interrupt_dispatch(_envelope: object, *, context: object) -> object:
        del context
        raise control_flow()

    monkeypatch.setattr(service, "dispatch", interrupt_dispatch)
    monkeypatch.setattr(cli, "build_service", lambda: service)

    with pytest.raises(control_flow):
        cli.call_service(Method.SYSTEM_INFO, {})

    assert close_attempts == [True]


@pytest.mark.parametrize(
    "control_flow",
    [KeyboardInterrupt, SystemExit, _SyntheticBaseException],
)
def test_call_service_cleanup_control_flow_takes_precedence_over_dispatch_exception(
    control_flow: type[BaseException],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    close_attempts: list[bool] = []

    def interrupt_close() -> None:
        close_attempts.append(True)
        raise control_flow()

    service = EngineService(close_callback=interrupt_close)

    def fail_dispatch(_envelope: object, *, context: object) -> object:
        del context
        raise RuntimeError("C:/private/dispatch.db")

    monkeypatch.setattr(service, "dispatch", fail_dispatch)
    monkeypatch.setattr(cli, "build_service", lambda: service)

    with pytest.raises(control_flow):
        cli.call_service(Method.SYSTEM_INFO, {})

    assert close_attempts == [True]


def test_internal_stdio_preserves_build_exception_semantics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_build() -> EngineService:
        raise RuntimeError("synthetic internal launcher failure")

    monkeypatch.setattr(cli, "build_service", fail_build)

    with pytest.raises(RuntimeError, match="synthetic internal launcher failure"):
        runner.invoke(cli.app, ["stdio"], catch_exceptions=False)


def test_build_service_preserves_initialization_error_when_store_close_also_raises(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailingStore:
        def __init__(self) -> None:
            self.close_attempts = 0

        def initialize(self) -> None:
            raise RuntimeError("synthetic initialization failure")

        def close(self) -> None:
            self.close_attempts += 1
            raise OSError("sensitive cleanup detail")

    paths = AppPaths(
        data_dir=tmp_path / "data",
        state_dir=tmp_path / "state",
        runtime_dir=tmp_path / "runtime",
        backups_dir=tmp_path / "backups",
        graveyard_dir=tmp_path / "graveyard",
    )
    store = FailingStore()
    monkeypatch.setattr(service_module, "SQLiteStateStore", lambda _paths: store)

    with pytest.raises(RuntimeError, match="synthetic initialization failure") as captured:
        cli.build_service(paths=paths)

    assert store.close_attempts == 1
    assert captured.value.__notes__ == ["Engine service cleanup also failed (OSError)."]
    assert "sensitive cleanup detail" not in " ".join(captured.value.__notes__)


def test_build_service_closes_initialized_store_if_service_constructor_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class InitializedStore:
        session_id = "constructor-failure-session"

        def __init__(self) -> None:
            self.initialize_attempts = 0
            self.close_attempts = 0

        def initialize(self) -> None:
            self.initialize_attempts += 1

        def close(self) -> None:
            self.close_attempts += 1
            raise OSError("sensitive constructor cleanup detail")

    def fail_service_constructor(**_kwargs: object) -> object:
        raise RuntimeError("synthetic service constructor failure")

    paths = AppPaths(
        data_dir=tmp_path / "data",
        state_dir=tmp_path / "state",
        runtime_dir=tmp_path / "runtime",
        backups_dir=tmp_path / "backups",
        graveyard_dir=tmp_path / "graveyard",
    )
    store = InitializedStore()
    monkeypatch.setattr(service_module, "SQLiteStateStore", lambda _paths: store)
    monkeypatch.setattr(service_module, "EngineService", fail_service_constructor)

    with pytest.raises(RuntimeError, match="synthetic service constructor failure") as captured:
        cli.build_service(paths=paths)

    assert store.initialize_attempts == 1
    assert store.close_attempts == 1
    assert captured.value.__notes__ == ["Engine service cleanup also failed (OSError)."]
    assert "sensitive constructor cleanup detail" not in " ".join(captured.value.__notes__)


def test_default_composition_is_real_and_reports_supported_local_workflows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = AppPaths(
        data_dir=tmp_path / "data",
        state_dir=tmp_path / "state",
        runtime_dir=tmp_path / "runtime",
        backups_dir=tmp_path / "backups",
        graveyard_dir=tmp_path / "graveyard",
    )
    monkeypatch.setattr(cli.AppPaths, "for_current_user", lambda: paths)
    service = cli.build_service()
    context = cli.RequestContext(
        client=cli.ClientKind.CONTROLLER,
        capability=cli.Capability.PLANNING,
        local_control=True,
    )

    doctor_response = service.dispatch(
        cli.RequestEnvelope(
            protocol_version=cli.PROTOCOL_VERSION,
            request_id=cli.uuid4(),
            method=Method.DOCTOR.value,
            payload={},
        ),
        context=context,
    )
    missing_agent = service.dispatch(
        cli.RequestEnvelope(
            protocol_version=cli.PROTOCOL_VERSION,
            request_id=cli.uuid4(),
            method=Method.ACTION_PLAN.value,
            payload={
                "agent_id": "missing-agent",
                "mode": "terminate",
                "target": {
                    "pid": 999,
                    "process_instance_id": "a" * 64,
                },
            },
        ),
        context=context,
    )
    quarantine_response = service.dispatch(
        cli.RequestEnvelope(
            protocol_version=cli.PROTOCOL_VERSION,
            request_id=cli.uuid4(),
            method=Method.QUARANTINE_LIST.value,
            payload={"limit": 25},
        ),
        context=context,
    )
    quarantine_cursor = service.dispatch(
        cli.RequestEnvelope(
            protocol_version=cli.PROTOCOL_VERSION,
            request_id=cli.uuid4(),
            method=Method.QUARANTINE_LIST.value,
            payload={"cursor": "next-page", "limit": 25},
        ),
        context=context,
    )
    missing_restore_entry = service.dispatch(
        cli.RequestEnvelope(
            protocol_version=cli.PROTOCOL_VERSION,
            request_id=cli.uuid4(),
            method=Method.QUARANTINE_RESTORE_PLAN.value,
            payload={"entry_id": "missing-graveyard-entry"},
        ),
        context=context,
    )
    service.close()

    assert doctor_response.ok is True
    doctor_result = doctor_response.result.model_dump(mode="json")
    checks = {check["name"]: check["ok"] for check in doctor_result["checks"]}
    assert len(checks) == len(Method)
    for method in Method:
        if method not in {Method.ACTION_PLAN, Method.ACTION_EXECUTE}:
            assert checks[f"method:{method.value}"] is True
    actions_available = checks["method:action.plan"]
    assert checks["method:action.execute"] is actions_available
    if sys.platform == "win32":
        assert actions_available is True
    if sys.platform == "darwin":
        assert actions_available is False
    assert doctor_result["healthy"] is actions_available
    expected_warnings = (
        set()
        if actions_available
        else {"Unavailable capability: action.plan.", "Unavailable capability: action.execute."}
    )
    assert set(doctor_result["warnings"]) == expected_warnings
    assert quarantine_response.ok is True
    assert quarantine_response.result.model_dump(mode="json") == {
        "entries": [],
        "next_cursor": None,
    }
    assert quarantine_cursor.error is not None
    assert quarantine_cursor.error.code.value == "invalid_request"
    assert missing_restore_entry.error is not None
    assert missing_restore_entry.error.code.value == "invalid_request"
    assert missing_agent.error is not None
    assert missing_agent.error.code.value == (
        "target_changed" if actions_available else "unsupported"
    )


def test_vault_inspect_is_read_only_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    vault = tmp_path / "memory.json"
    original = b'[{"id":"one","content":"local"}]\n'
    vault.write_bytes(original)
    service = EngineService(
        paths=AppPaths(
            data_dir=tmp_path / "data",
            state_dir=tmp_path / "state",
            runtime_dir=tmp_path / "runtime",
            backups_dir=tmp_path / "backups",
            graveyard_dir=tmp_path / "graveyard",
        )
    )
    monkeypatch.setattr(cli, "build_service", lambda: service)

    result = runner.invoke(cli.app, ["vault", "inspect", str(vault), "--json"])
    human = runner.invoke(cli.app, ["vault", "inspect", str(vault)])

    assert result.exit_code == 0
    body = json.loads(result.stdout)
    assert body["read_only"] is True
    assert body["recognized"] is True
    assert "path" not in body
    assert vault.read_bytes() == original
    assert human.exit_code == 0
    assert "provider safety" in human.stdout.casefold()


@pytest.mark.parametrize(
    "raw_path",
    [
        "relative/vault.json",
        "C:/vault/../vault.json",
        "//server/share/vault.json",
        "//?/C:/vault.json",
        "C:/vault.json:stream",
        " C:/vault.json",
        "C:/vault.json ",
        "C:/NUL.txt",
        "C:/safe/NUL .txt",
        "C:/safe/CoM1.log",
        "C:/CLOCK$/vault.json",
        "C:/conin$.txt",
        "C:/safe/ConOut$ .log",
        "C:/CONOUT$...",
        "C:/safe./vault.json",
        "C:/safe /vault.json",
    ],
)
def test_vault_path_lexical_rejection_precedes_any_os_probe(raw_path: str) -> None:
    probed: list[Path] = []

    def probe(path: Path) -> Path:
        probed.append(path)
        raise AssertionError("rejected paths must not reach the OS probe")

    with pytest.raises(cli.CliFailure):
        cli._select_local_vault_path(Path(raw_path), probe=probe)

    assert probed == []


def test_demo_reservation_records_exact_live_owner_and_blocks_reentry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_path = tmp_path / "demo-state.json"
    monkeypatch.setattr(cli, "demo_state_path", lambda: state_path)

    lease = cli._reserve_demo_state()
    try:
        reservation_path = state_path.with_name(state_path.name + ".reservation")
        body = json.loads(reservation_path.read_text(encoding="utf-8"))

        assert body["owner_pid"] == cli.os.getpid()
        assert abs(body["owner_create_time"] - psutil.Process().create_time()) <= 0.02
        assert len(body["nonce"]) >= 32
        assert datetime.fromisoformat(body["expires_at"]) > datetime.now(UTC)
        with pytest.raises(cli.CliFailure, match="already in progress"):
            cli._reserve_demo_state()
    finally:
        cli._release_demo_reservation(lease)
    assert list(tmp_path.glob("*.reservation.quarantine.*")) == []


def test_demo_reservation_reclaims_only_verified_dead_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_path = tmp_path / "demo-state.json"
    reservation_path = state_path.with_name(state_path.name + ".reservation")
    monkeypatch.setattr(cli, "demo_state_path", lambda: state_path)
    reservation_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "owner_pid": 999_999_999,
                "owner_create_time": 1.0,
                "nonce": "a" * 43,
                "created_at": (datetime.now(UTC) - timedelta(minutes=2)).isoformat(),
                "expires_at": (datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
            }
        ),
        encoding="utf-8",
    )

    current_create_time = psutil.Process().create_time()
    lease = cli._reserve_demo_state(
        owner_probe=lambda pid: current_create_time if pid == cli.os.getpid() else None
    )
    try:
        body = json.loads(reservation_path.read_text(encoding="utf-8"))
        assert body["owner_pid"] == cli.os.getpid()
        assert body["nonce"] != "a" * 43
    finally:
        cli._release_demo_reservation(lease)


def test_demo_reservation_guard_allows_only_one_simultaneous_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_path = tmp_path / "demo-state.json"
    monkeypatch.setattr(cli, "demo_state_path", lambda: state_path)
    start = threading.Barrier(2)
    acquired = threading.Event()
    release = threading.Event()

    def contender() -> str:
        start.wait(timeout=5)
        try:
            lease = cli._reserve_demo_state()
        except cli.CliFailure:
            return "blocked"
        acquired.set()
        assert release.wait(timeout=5)
        cli._release_demo_reservation(lease)
        return "acquired"

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(contender) for _ in range(2)]
        assert acquired.wait(timeout=5)
        done, _pending = wait(futures, timeout=5, return_when=FIRST_COMPLETED)
        assert len(done) == 1
        assert next(iter(done)).result() == "blocked"
        release.set()
        assert sorted(future.result(timeout=5) for future in futures) == ["acquired", "blocked"]
    assert state_path.with_name(state_path.name + ".reservation.lock").exists()


def test_demo_reservation_guard_is_held_across_processes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_path = tmp_path / "demo-state.json"
    monkeypatch.setattr(cli, "demo_state_path", lambda: state_path)
    lease = cli._reserve_demo_state()
    script = """
import sys
from pathlib import Path
from zombie_killer_engine import cli
cli.demo_state_path = lambda: Path(sys.argv[1])
try:
    lease = cli._reserve_demo_state()
except cli.CliFailure:
    raise SystemExit(7)
cli._release_demo_reservation(lease)
"""
    try:
        blocked = subprocess.run(
            [sys.executable, "-c", script, str(state_path)],
            check=False,
            capture_output=True,
            timeout=10,
        )
        assert blocked.returncode == 7
    finally:
        cli._release_demo_reservation(lease)

    acquired = subprocess.run(
        [sys.executable, "-c", script, str(state_path)],
        check=False,
        capture_output=True,
        timeout=10,
    )
    assert acquired.returncode == 0


@pytest.mark.parametrize("malformed", [b"", b"{"])
def test_demo_reservation_fresh_malformed_marker_blocks_but_stale_is_reclaimed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, malformed: bytes
) -> None:
    state_path = tmp_path / "demo-state.json"
    reservation_path = state_path.with_name(state_path.name + ".reservation")
    monkeypatch.setattr(cli, "demo_state_path", lambda: state_path)
    reservation_path.write_bytes(malformed)

    with pytest.raises(cli.CliFailure, match="already in progress"):
        cli._reserve_demo_state()
    assert reservation_path.read_bytes() == malformed

    stale_at = datetime.now(UTC) - cli._MALFORMED_RESERVATION_GRACE - timedelta(seconds=1)
    cli.os.utime(reservation_path, (stale_at.timestamp(), stale_at.timestamp()))
    lease = cli._reserve_demo_state()
    try:
        marker = json.loads(reservation_path.read_text(encoding="utf-8"))
        assert marker["nonce"] == lease.owner.nonce
    finally:
        cli._release_demo_reservation(lease)


def test_demo_reservation_reclaim_refuses_marker_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_path = tmp_path / "demo-state.json"
    reservation_path = state_path.with_name(state_path.name + ".reservation")
    replacement_path = state_path.with_name(state_path.name + ".replacement")
    monkeypatch.setattr(cli, "demo_state_path", lambda: state_path)
    reservation_path.write_bytes(b"{")
    stale_at = datetime.now(UTC) - cli._MALFORMED_RESERVATION_GRACE - timedelta(seconds=1)
    cli.os.utime(reservation_path, (stale_at.timestamp(), stale_at.timestamp()))

    def replace_marker() -> None:
        replacement_path.write_bytes(b"fresh replacement")
        cli.os.replace(replacement_path, reservation_path)

    with pytest.raises(cli.CliFailure, match="changed|conflict"):
        cli._reserve_demo_state(revalidation_hook=replace_marker)

    assert reservation_path.read_bytes() == b"fresh replacement"
    assert list(tmp_path.glob("*.reservation.quarantine.*")) == []


def test_demo_reservation_reclaim_retains_quarantine_when_original_reappears(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_path = tmp_path / "demo-state.json"
    reservation_path = state_path.with_name(state_path.name + ".reservation")
    replacement_path = state_path.with_name(state_path.name + ".replacement")
    monkeypatch.setattr(cli, "demo_state_path", lambda: state_path)
    reservation_path.write_bytes(b"{")
    stale_at = datetime.now(UTC) - cli._MALFORMED_RESERVATION_GRACE - timedelta(seconds=1)
    cli.os.utime(reservation_path, (stale_at.timestamp(), stale_at.timestamp()))

    def replace_before_rename() -> None:
        replacement_path.write_bytes(b"moved replacement")
        cli.os.replace(replacement_path, reservation_path)

    def occupy_original(_quarantine: Path) -> None:
        reservation_path.write_bytes(b"new original occupant")

    with pytest.raises(cli.CliFailure, match="conflict"):
        cli._reserve_demo_state(
            revalidation_hook=replace_before_rename,
            post_rename_hook=occupy_original,
        )

    quarantines = list(tmp_path.glob("*.reservation.quarantine.*"))
    assert reservation_path.read_bytes() == b"new original occupant"
    assert len(quarantines) == 1
    assert quarantines[0].read_bytes() == b"moved replacement"


def test_demo_reservation_release_does_not_unlink_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_path = tmp_path / "demo-state.json"
    reservation_path = state_path.with_name(state_path.name + ".reservation")
    replacement_path = state_path.with_name(state_path.name + ".replacement")
    monkeypatch.setattr(cli, "demo_state_path", lambda: state_path)
    lease = cli._reserve_demo_state()
    replacement_path.write_text(cli._json(lease.owner.model_dump(mode="json")), encoding="utf-8")
    cli.os.replace(replacement_path, reservation_path)

    with pytest.raises(cli.CliFailure, match="changed|conflict"):
        cli._release_demo_reservation(lease)

    assert reservation_path.exists()
    reservation_path.unlink()
    next_lease = cli._reserve_demo_state()
    cli._release_demo_reservation(next_lease)


def test_demo_reservation_release_restores_swap_after_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_path = tmp_path / "demo-state.json"
    reservation_path = state_path.with_name(state_path.name + ".reservation")
    replacement_path = state_path.with_name(state_path.name + ".replacement")
    monkeypatch.setattr(cli, "demo_state_path", lambda: state_path)
    lease = cli._reserve_demo_state()

    def replace_before_rename() -> None:
        replacement_path.write_text(
            cli._json(lease.owner.model_dump(mode="json")), encoding="utf-8"
        )
        cli.os.replace(replacement_path, reservation_path)

    with pytest.raises(cli.CliFailure, match="changed|conflict"):
        cli._release_demo_reservation(lease, revalidation_hook=replace_before_rename)

    assert reservation_path.exists()
    assert list(tmp_path.glob("*.reservation.quarantine.*")) == []


def test_demo_reservation_release_retains_verified_quarantine_on_new_occupant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_path = tmp_path / "demo-state.json"
    reservation_path = state_path.with_name(state_path.name + ".reservation")
    monkeypatch.setattr(cli, "demo_state_path", lambda: state_path)
    lease = cli._reserve_demo_state()

    def occupy_original(_quarantine: Path) -> None:
        reservation_path.write_bytes(b"new original occupant")

    with pytest.raises(cli.CliFailure, match="conflict"):
        cli._release_demo_reservation(lease, post_rename_hook=occupy_original)

    quarantines = list(tmp_path.glob("*.reservation.quarantine.*"))
    assert reservation_path.read_bytes() == b"new original occupant"
    assert len(quarantines) == 1
    assert json.loads(quarantines[0].read_text(encoding="utf-8"))["nonce"] == lease.owner.nonce


def test_destructive_execute_requires_confirmation_without_prompt() -> None:
    result = runner.invoke(
        cli.app,
        ["action", "execute", "plan-1", "a" * 64, "--json"],
        input="yes\n",
    )

    assert result.exit_code == 2
    assert result.stdout == ""
    assert "--confirm" in result.stderr
    assert "yes" not in result.stdout.casefold()


@pytest.mark.parametrize(
    ("receipt", "expected_output", "completed_claim_allowed"),
    [
        (
            _action_receipt_fixture(outcome="completed", certainty="verified", action_issued=True),
            "Action completed and was verified. Use --json to inspect the local receipt.\n",
            True,
        ),
        (
            _action_receipt_fixture(
                outcome="completed",
                certainty="verified",
                action_issued=True,
                partial_failures=("Reference cleanup could not be verified.",),
            ),
            (
                "Action was issued, but the receipt reports 1 partial failure. "
                "Use --json to inspect it.\n"
            ),
            False,
        ),
        (
            _action_receipt_fixture(
                outcome="completed",
                certainty="verified",
                action_issued=True,
                partial_failures=(
                    "Reference cleanup could not be verified.",
                    "The final state needs review.",
                ),
            ),
            (
                "Action was issued, but the receipt reports 2 partial failures. "
                "Use --json to inspect it.\n"
            ),
            False,
        ),
        (
            _action_receipt_fixture(outcome="requested", certainty="verified", action_issued=True),
            (
                "Action was issued; completion is not verified. "
                "Use --json to inspect the local receipt.\n"
            ),
            False,
        ),
        (
            _action_receipt_fixture(
                outcome="failed",
                certainty="failed_before_issue",
                action_issued=False,
                partial_failures=("The action was rejected before issuance.",),
            ),
            "Action was not issued. Use --json to inspect the local receipt.\n",
            False,
        ),
        (
            _action_receipt_fixture(
                outcome="interrupted",
                certainty="uncertain",
                action_issued=None,
                partial_failures=("The final effect could not be verified.",),
            ),
            "Action outcome is uncertain. Use --json to inspect the local receipt.\n",
            False,
        ),
        (
            _action_receipt_fixture(outcome="completed", certainty="uncertain", action_issued=None),
            "Action outcome is uncertain. Use --json to inspect the local receipt.\n",
            False,
        ),
        (
            _action_receipt_fixture(
                outcome="completed", certainty="failed_before_issue", action_issued=False
            ),
            "Action was not issued. Use --json to inspect the local receipt.\n",
            False,
        ),
    ],
)
def test_action_execute_human_output_uses_truthful_receipt_matrix(
    receipt: dict[str, object],
    expected_output: str,
    completed_claim_allowed: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli, "call_service", lambda *_args, **_kwargs: receipt)

    result = runner.invoke(
        cli.app,
        ["action", "execute", "plan-1", "a" * 64, "--confirm"],
    )

    assert result.exit_code == 0
    assert result.stdout == expected_output
    assert len(result.stdout) <= 160
    for failure in receipt["partial_failures"]:
        assert failure not in result.stdout
    if not completed_claim_allowed:
        assert "completed" not in result.stdout.casefold()


def test_action_receipt_message_is_idempotent_and_ignores_unknown_fields() -> None:
    receipt = _action_receipt_fixture(
        outcome="future_outcome",
        certainty="verified",
        action_issued=True,
    )
    receipt["future_field"] = f"C:/private/future.db {_NAMED_SECRET_PREFIX}fixture-future-value"
    original = json.loads(json.dumps(receipt))

    first = cli._action_receipt_message(receipt)
    second = cli._action_receipt_message(receipt)

    assert first == second
    assert receipt == original
    assert first == (
        "Action was issued; completion is not verified. Use --json to inspect the local receipt."
    )
    assert "private" not in first.casefold()
    assert "fixture-future-value" not in first


@pytest.mark.parametrize(
    "contradiction",
    [
        {"certainty": "future_certainty"},
        {"action_issued": "true"},
        {"partial_failures": "fixture-marker"},
        {"partial_failures": ["fixture-marker"] * 65},
    ],
)
def test_action_receipt_message_fails_closed_on_unknown_or_malformed_fields(
    contradiction: dict[str, object],
) -> None:
    receipt = _action_receipt_fixture(
        outcome="completed",
        certainty="verified",
        action_issued=True,
    )
    receipt.update(contradiction)

    message = cli._action_receipt_message(receipt)

    assert message == ("Action outcome is uncertain. Use --json to inspect the local receipt.")
    assert "completed" not in message.casefold()
    assert "fixture-marker" not in message
    assert len(message) <= 160


@pytest.mark.parametrize(
    ("action_issued", "certainty"),
    [(True, "failed_before_issue"), (False, "verified")],
)
def test_action_receipt_message_fails_closed_on_contradictory_certainty_pairs(
    action_issued: bool,
    certainty: str,
) -> None:
    receipt = _action_receipt_fixture(
        outcome="failed",
        certainty=certainty,
        action_issued=action_issued,
    )

    message = cli._action_receipt_message(receipt)

    assert message == "Action outcome is uncertain. Use --json to inspect the local receipt."


def test_action_execute_json_preserves_the_bounded_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = _action_receipt_fixture(outcome="pending", certainty="verified", action_issued=True)
    monkeypatch.setattr(cli, "call_service", lambda *_args, **_kwargs: receipt)

    result = runner.invoke(
        cli.app,
        ["action", "execute", "plan-1", "a" * 64, "--confirm", "--json"],
    )

    assert result.exit_code == 0
    assert json.loads(result.stdout) == receipt
    assert "completed" not in result.stdout.casefold()


def test_demo_simulated_lifecycle_uses_no_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_path = tmp_path / "demo-state.json"
    monkeypatch.setattr(cli, "demo_state_path", lambda: state_path)

    spawned = runner.invoke(cli.app, ["demo", "spawn", "--json"])
    status = runner.invoke(cli.app, ["demo", "status", "--json"])
    stopped = runner.invoke(cli.app, ["demo", "stop", "--confirm", "--json"])
    reset = runner.invoke(cli.app, ["demo", "reset", "--confirm", "--json"])

    assert spawned.exit_code == status.exit_code == stopped.exit_code == reset.exit_code == 0
    assert json.loads(spawned.stdout)["mode"] == "simulated"
    assert json.loads(status.stdout)["state"] == "orphaned_fixture"
    assert json.loads(stopped.stdout)["state"] == "stopped"
    assert json.loads(reset.stdout)["reset"] is True
    assert not state_path.exists()


def test_demo_real_cleanup_is_exact_and_does_not_touch_sibling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_path = tmp_path / "demo-state.json"
    monkeypatch.setattr(cli, "demo_state_path", lambda: state_path)
    sibling = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    demo_pid: int | None = None
    try:
        spawned = runner.invoke(cli.app, ["demo", "spawn", "--real", "--json"])
        assert spawned.exit_code == 0, spawned.stderr
        demo_pid = int(json.loads(spawned.stdout)["pid"])
        assert psutil.pid_exists(demo_pid)

        stopped = runner.invoke(cli.app, ["demo", "stop", "--confirm", "--json"])
        reset = runner.invoke(cli.app, ["demo", "reset", "--confirm", "--json"])

        assert stopped.exit_code == 0, stopped.stderr
        assert reset.exit_code == 0, reset.stderr
        assert sibling.poll() is None
        assert not psutil.pid_exists(demo_pid)
        assert not state_path.exists()
    finally:
        if demo_pid is not None and psutil.pid_exists(demo_pid):
            psutil.Process(demo_pid).kill()
        sibling.kill()
        sibling.wait(timeout=5)


def test_demo_refuses_pid_create_time_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_path = tmp_path / "demo-state.json"
    monkeypatch.setattr(cli, "demo_state_path", lambda: state_path)
    spawned = runner.invoke(cli.app, ["demo", "spawn", "--real", "--json"])
    body = json.loads(spawned.stdout)
    process = psutil.Process(int(body["pid"]))
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["create_time"] = float(state["create_time"]) + 100
        state_path.write_text(json.dumps(state), encoding="utf-8")

        stopped = runner.invoke(cli.app, ["demo", "stop", "--confirm", "--json"])

        assert stopped.exit_code == 3
        assert "identity" in stopped.stderr.casefold()
        assert process.is_running()
        assert state_path.exists()
    finally:
        process.kill()
        process.wait(timeout=5)


def test_demo_spawn_state_write_failure_reaps_exact_child_and_reservation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_path = tmp_path / "demo-state.json"
    spawned: list[subprocess.Popen[bytes]] = []
    original_popen = subprocess.Popen

    def tracked_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        process = original_popen(*args, **kwargs)
        spawned.append(process)
        return process

    monkeypatch.setattr(cli, "demo_state_path", lambda: state_path)
    monkeypatch.setattr(cli.subprocess, "Popen", tracked_popen)

    def fail_state_write(_state: cli.DemoState) -> None:
        temporary = state_path.with_name(state_path.name + f".{cli.os.getpid()}.tmp")
        temporary.write_text("partial", encoding="utf-8")
        raise OSError("synthetic state failure")

    monkeypatch.setattr(cli, "_write_demo_state", fail_state_write)

    result = runner.invoke(cli.app, ["demo", "spawn", "--real", "--json"])

    try:
        assert result.exit_code == 3
        assert len(spawned) == 1
        spawned[0].wait(timeout=5)
        assert spawned[0].poll() is not None
        assert not state_path.exists()
        assert list(tmp_path.glob("*.reservation")) == []
        assert list(tmp_path.glob("*.reservation.quarantine.*")) == []
        assert list(tmp_path.glob("*.tmp")) == []
    finally:
        for process in spawned:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)


def test_concurrent_demo_spawn_loser_never_starts_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_path = tmp_path / "demo-state.json"
    entered_popen = threading.Event()
    allow_popen = threading.Event()
    calls = 0
    calls_lock = threading.Lock()
    original_popen = subprocess.Popen

    def blocked_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        nonlocal calls
        with calls_lock:
            calls += 1
        entered_popen.set()
        assert allow_popen.wait(timeout=5)
        return original_popen(*args, **kwargs)

    monkeypatch.setattr(cli, "demo_state_path", lambda: state_path)
    monkeypatch.setattr(cli.subprocess, "Popen", blocked_popen)

    with ThreadPoolExecutor(max_workers=2) as pool:
        winner = pool.submit(cli.demo_spawn, real=True, stale_after=None, json_output=True)
        assert entered_popen.wait(timeout=5)
        loser = pool.submit(cli.demo_spawn, real=True, stale_after=None, json_output=True)
        with pytest.raises(cli.typer.Exit):
            loser.result(timeout=5)
        allow_popen.set()
        winner.result(timeout=5)

    assert calls == 1
    state = cli._read_demo_state()
    try:
        cli._stop_demo(state)
    finally:
        if state_path.exists():
            state_path.unlink()
