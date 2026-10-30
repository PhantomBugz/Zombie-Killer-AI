"""Headless Typer CLI for the finite Zombie Killer application service."""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Literal
from uuid import uuid4

import psutil  # type: ignore[import-untyped]
import typer
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from zombie_killer_engine.local_cli import install_local_workflows
from zombie_killer_engine.memory.base import MemoryError, validate_local_path_lexical
from zombie_killer_engine.paths import AppPaths
from zombie_killer_engine.protocol import protocol_once as serve_once
from zombie_killer_engine.protocol import stdio as serve_stdio
from zombie_killer_engine.service import (
    MAX_PROCESS_ID,
    PROTOCOL_VERSION,
    Capability,
    ClientKind,
    EngineService,
    Method,
    RequestContext,
    RequestEnvelope,
    ResponseEnvelope,
    build_default_service,
)

app = typer.Typer(
    help="Inspect and safely recover local agent workloads.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)
vault_app = typer.Typer(help="Inspect user-selected local Memory Vault files.")
demo_app = typer.Typer(help="Run a harmless local Zombie Lab fixture.")
action_app = typer.Typer(help="Preview and execute identity-bound process actions.")
app.add_typer(vault_app, name="vault")
app.add_typer(demo_app, name="demo")
app.add_typer(action_app, name="action")


class CliFailure(RuntimeError):
    def __init__(self, message: str, *, exit_code: int = 2) -> None:
        super().__init__(message)
        self.message = message
        self.exit_code = exit_code


class _ResponseFailure(CliFailure):
    """A bounded fault taken from a validated service response."""


_SERVICE_REQUEST_FAILURE = "The local engine request failed safely."


@dataclass(frozen=True)
class _ParentIdentity:
    pid: int
    create_time: float


def _capture_parent_identity(parent_pid: int) -> _ParentIdentity:
    if parent_pid != os.getppid():
        raise CliFailure("Broker parent identity validation failed.")
    try:
        parent = psutil.Process(parent_pid)
        if not parent.is_running() or parent.status() == psutil.STATUS_ZOMBIE:
            raise CliFailure("Broker parent identity validation failed.")
        return _ParentIdentity(pid=parent_pid, create_time=parent.create_time())
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess) as error:
        raise CliFailure("Broker parent identity validation failed.") from error


def _parent_identity_matches(identity: _ParentIdentity) -> bool:
    try:
        parent = psutil.Process(identity.pid)
        return bool(
            parent.is_running()
            and parent.status() != psutil.STATUS_ZOMBIE
            and parent.create_time() == identity.create_time
        )
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
        return False


def _watch_parent(identity: _ParentIdentity) -> None:
    while True:
        time.sleep(0.25)
        if not _parent_identity_matches(identity):
            # The native broker disappeared or its PID was reused. Exit without cleanup code that
            # could block a hung engine; the broker will reconcile any dispatched action later.
            os._exit(70)


def _start_parent_watch(parent_pid: int) -> None:
    identity = _capture_parent_identity(parent_pid)
    threading.Thread(
        target=_watch_parent,
        args=(identity,),
        name="zombie-killer-parent-watch",
        daemon=True,
    ).start()


def _json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def build_service(*, paths: AppPaths | None = None) -> EngineService:
    """Build a caller-owned service that must be closed exactly once."""
    return build_default_service(paths=paths)


def _internal_app_paths(root: Path) -> AppPaths:
    if not root.is_absolute() or any(part in {".", ".."} for part in root.parts):
        raise CliFailure("Internal state root must be a lexical absolute path.")
    data = root / "data"
    return AppPaths(
        data_dir=data,
        state_dir=root / "state",
        runtime_dir=root / "runtime",
        backups_dir=data / "backups",
        graveyard_dir=data / "graveyard",
    )


def call_service(
    method: Method,
    payload: dict[str, object],
    *,
    capability: Capability = Capability.READ,
    local_control: bool = True,
) -> object:
    envelope = RequestEnvelope(
        protocol_version=PROTOCOL_VERSION,
        request_id=uuid4(),
        method=method.value,
        payload=payload,
    )
    context = RequestContext(
        client=ClientKind.CONTROLLER,
        capability=capability,
        local_control=local_control,
    )
    try:
        service = build_service()
    except Exception:
        raise CliFailure(_SERVICE_REQUEST_FAILURE, exit_code=4) from None
    response_failure: _ResponseFailure | None = None
    try:
        response = service.dispatch(envelope, context=context)
        if type(response) is not ResponseEnvelope:
            raise TypeError("Engine service returned an invalid response type")
        if not response.ok:
            assert response.error is not None
            response_failure = _ResponseFailure(response.error.message, exit_code=4)
            raise response_failure
        if isinstance(response.result, BaseModel):
            result: object = response.result.model_dump(mode="json")
        else:
            result = response.result
    except BaseException as primary_error:
        try:
            service.close()
        except BaseException as close_error:
            if isinstance(primary_error, Exception) and not isinstance(close_error, Exception):
                raise
            if primary_error is response_failure:
                BaseException.add_note(primary_error, "Engine service cleanup also failed.")
        if isinstance(primary_error, Exception) and primary_error is not response_failure:
            raise CliFailure(_SERVICE_REQUEST_FAILURE, exit_code=4) from None
        raise
    else:
        try:
            service.close()
        except Exception:
            raise CliFailure(
                "The local engine could not release its resources safely.",
                exit_code=4,
            ) from None
    return result


def _fail(error: CliFailure) -> None:
    typer.echo(f"Error: {error.message}", err=True)
    raise typer.Exit(error.exit_code)


def _action_receipt_message(result: object) -> str:
    inspect_receipt = "Use --json to inspect the local receipt."
    if not isinstance(result, dict):
        return f"Action outcome is uncertain. {inspect_receipt}"

    outcome = result.get("outcome")
    certainty = result.get("certainty")
    action_issued = result.get("action_issued")
    partial_failures = result.get("partial_failures")

    valid_certainty_pair = (
        (action_issued is True and certainty == "verified")
        or (action_issued is False and certainty == "failed_before_issue")
        or (action_issued is None and certainty == "uncertain")
    )
    if not valid_certainty_pair or action_issued is None:
        return f"Action outcome is uncertain. {inspect_receipt}"
    if action_issued is False:
        return f"Action was not issued. {inspect_receipt}"
    if not isinstance(partial_failures, (list, tuple)) or len(partial_failures) > 64:
        return f"Action outcome is uncertain. {inspect_receipt}"
    if partial_failures:
        failure_count = len(partial_failures)
        failure_label = "failure" if failure_count == 1 else "failures"
        return (
            f"Action was issued, but the receipt reports {failure_count} partial {failure_label}. "
            "Use --json to inspect it."
        )
    if outcome == "completed":
        return f"Action completed and was verified. {inspect_receipt}"
    return f"Action was issued; completion is not verified. {inspect_receipt}"


@app.command()
def scan(
    json_output: Annotated[bool, typer.Option("--json", help="Emit one JSON value.")] = False,
) -> None:
    """Scan local process evidence; signature matches remain candidates."""
    try:
        result = call_service(Method.SCAN_LIST, {})
    except CliFailure as error:
        _fail(error)
    if json_output:
        typer.echo(_json(result))
        return
    assert isinstance(result, dict)
    agents = result.get("agents", [])
    coverage = result.get("coverage", {})
    typer.echo("STATE                 EVIDENCE        PID      NAME")
    if not agents:
        typer.echo("No local agent evidence found.")
    for raw_agent in agents if isinstance(agents, list) else []:
        if not isinstance(raw_agent, dict):
            continue
        state = str(raw_agent.get("state", "unknown"))
        display_state = "candidate" if state == "unmanaged" else state
        evidence = str(raw_agent.get("evidence_grade", "insufficient"))
        pid = str(raw_agent.get("pid") or "-")
        name = str(raw_agent.get("process_name") or raw_agent.get("agent_id") or "-")
        typer.echo(f"{display_state:<21} {evidence:<15} {pid:<8} {name[:40]}")
    if isinstance(coverage, dict) and not coverage.get("complete", False):
        typer.echo("Coverage is partial; absence of evidence is not proof of absence.")


@app.command()
def doctor(
    json_output: Annotated[bool, typer.Option("--json", help="Emit one JSON value.")] = False,
) -> None:
    """Check the local engine boundary and report bounded warnings."""
    try:
        result = call_service(Method.DOCTOR, {})
    except CliFailure as error:
        _fail(error)
    if json_output:
        typer.echo(_json(result))
        return
    assert isinstance(result, dict)
    typer.echo(
        "Zombie Killer doctor: healthy"
        if result.get("healthy")
        else "Zombie Killer doctor: attention required"
    )
    for warning in result.get("warnings", []):
        typer.echo(f"Warning: {warning}")


@vault_app.command("inspect")
def vault_inspect(
    path: Annotated[Path, typer.Argument(help="A local file selected by the operator.")],
    json_output: Annotated[bool, typer.Option("--json", help="Emit one JSON value.")] = False,
) -> None:
    """Probe a selected local vault without registering or modifying it."""
    try:
        selected = _select_local_vault_path(path)
        result = call_service(Method.VAULT_PROBE, {"path": str(selected)})
    except (OSError, CliFailure) as error:
        _fail(
            error
            if isinstance(error, CliFailure)
            else CliFailure("The selected vault could not be read.")
        )
    if json_output:
        typer.echo(_json(result))
        return
    assert isinstance(result, dict)
    recognized = "recognized" if result.get("recognized") else "not recognized"
    typer.echo(
        f"Format: {result.get('format', 'unsupported')} ({recognized}, read-only inspection)"
    )
    if result.get("reason"):
        typer.echo(f"Reason: {result['reason']}")
    typer.echo(str(result["local_only_warning"]))


def _probe_local_vault_file(path: Path) -> Path:
    selected = path.resolve(strict=True)
    if not selected.is_file():
        raise CliFailure("The selected vault is not a regular local file.")
    return selected


def _select_local_vault_path(
    path: Path,
    *,
    probe: Callable[[Path], Path] = _probe_local_vault_file,
) -> Path:
    try:
        validate_local_path_lexical(path)
    except MemoryError as error:
        raise CliFailure("The selected vault path is not an approved local file.") from error
    return probe(path)


def _validated_action_target(pid: str, process_instance_id: str) -> dict[str, object]:
    invalid = (
        not pid.isascii()
        or not pid.isdecimal()
        or len(pid) > 10
        or not process_instance_id.isascii()
        or len(process_instance_id) != 64
        or any(character not in "0123456789abcdef" for character in process_instance_id)
    )
    if invalid:
        raise CliFailure("The reviewed process identity is invalid.")
    numeric_pid = int(pid)
    if numeric_pid <= 0 or numeric_pid > MAX_PROCESS_ID:
        raise CliFailure("The reviewed process identity is invalid.")
    return {"pid": numeric_pid, "process_instance_id": process_instance_id}


@action_app.command("plan")
def action_plan(
    agent_id: Annotated[str, typer.Argument(help="Exact agent identifier from a scan.")],
    pid: Annotated[
        str,
        typer.Option("--pid", help="Exact reviewed PID from `zk scan --json`."),
    ],
    process_instance_id: Annotated[
        str,
        typer.Option(
            "--process-instance-id",
            help="Exact reviewed process-instance ID from `zk scan --json`.",
        ),
    ],
    mode: Annotated[
        Literal["request_stop", "terminate", "kill"],
        typer.Option("--mode", help="Action to preview."),
    ] = "request_stop",
    json_output: Annotated[bool, typer.Option("--json", help="Emit one JSON value.")] = False,
) -> None:
    """Create a short-lived action preview with a plan ID and digest."""
    try:
        target = _validated_action_target(pid, process_instance_id)
        result = call_service(
            Method.ACTION_PLAN,
            {
                "agent_id": agent_id,
                "mode": mode,
                "target": target,
            },
            capability=Capability.PLANNING,
        )
    except CliFailure as error:
        _fail(error)
    if json_output:
        typer.echo(_json(result))
    else:
        assert isinstance(result, dict)
        typer.echo(f"Plan: {result.get('plan_id')}")
        typer.echo(f"Digest: {result.get('digest')}")
        for consequence in result.get("consequences", []):
            typer.echo(f"Consequence: {consequence}")


@action_app.command("execute")
def action_execute(
    plan_id: Annotated[str, typer.Argument(help="Exact plan ID returned by action plan.")],
    digest: Annotated[str, typer.Argument(help="Exact 64-character plan digest.")],
    confirm: Annotated[
        bool,
        typer.Option("--confirm", help="Explicitly authorize this exact plan; never prompts."),
    ] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Emit one JSON value.")] = False,
) -> None:
    """Execute one stored action plan; requires --confirm, plan ID, and digest."""
    if not confirm:
        _fail(CliFailure("Execution requires the explicit --confirm flag."))
    try:
        result = call_service(
            Method.ACTION_EXECUTE,
            {"plan_id": plan_id, "digest": digest},
            capability=Capability.EXECUTION,
        )
    except CliFailure as error:
        _fail(error)
    typer.echo(_json(result) if json_output else _action_receipt_message(result))


class DemoState(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    schema_version: Literal[1] = 1
    demo_id: str = Field(pattern=r"^demo-[0-9a-f]{32}$")
    mode: Literal["simulated", "process"]
    state: Literal["orphaned_fixture", "running", "stale_fixture", "stopped"]
    token: str = Field(min_length=32, max_length=128)
    pid: int | None = Field(default=None, gt=0)
    create_time: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    heartbeat_path: str | None = Field(default=None, min_length=1, max_length=4096)
    started_at: str = Field(min_length=20, max_length=64)

    @model_validator(mode="after")
    def process_fields_match_mode(self) -> DemoState:
        fields = (self.pid, self.create_time, self.heartbeat_path)
        if self.mode == "process" and any(item is None for item in fields):
            raise ValueError("process fixture identity is incomplete")
        if self.mode == "simulated" and any(item is not None for item in fields):
            raise ValueError("simulated fixture cannot own process resources")
        return self


class DemoReservation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    schema_version: Literal[1] = 1
    owner_pid: int = Field(gt=0)
    owner_create_time: float = Field(ge=0, allow_inf_nan=False)
    nonce: str = Field(min_length=32, max_length=128)
    created_at: datetime
    expires_at: datetime

    @model_validator(mode="after")
    def expiry_follows_creation(self) -> DemoReservation:
        if self.created_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("reservation timestamps must include a timezone")
        if self.expires_at <= self.created_at:
            raise ValueError("reservation expiry must follow creation")
        return self


@dataclass(slots=True)
class DemoReservationLease:
    path: Path
    owner: DemoReservation
    marker_identity: tuple[int, int, int, int]
    guard_descriptor: int
    released: bool = False


@dataclass(frozen=True, slots=True)
class _DemoReservationSnapshot:
    data: bytes
    identity: tuple[int, int, int, int]
    modified_at: datetime
    oversized: bool


_DEMO_RESERVATION_TTL = timedelta(minutes=2)
_MALFORMED_RESERVATION_GRACE = timedelta(seconds=30)
_MAX_DEMO_RESERVATION_BYTES = 4_096


def demo_state_path() -> Path:
    return AppPaths.for_current_user().state_dir / "zombie-lab-state.json"


def _write_demo_state(state: DemoState) -> None:
    destination = demo_state_path()
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + f".{os.getpid()}.tmp")
    temporary.write_text(_json(state.model_dump(mode="json")), encoding="utf-8")
    os.replace(temporary, destination)


def _reservation_owner_create_time(pid: int) -> float | None:
    try:
        return float(psutil.Process(pid).create_time())
    except psutil.NoSuchProcess:
        return None
    except (psutil.AccessDenied, OSError) as error:
        raise CliFailure(
            "A Zombie Lab reservation owner could not be verified; spawn was refused."
        ) from error


def _file_identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def _read_demo_reservation_snapshot(path: Path) -> _DemoReservationSnapshot | None:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    except FileNotFoundError:
        return None
    except OSError as error:
        raise CliFailure("The Zombie Lab reservation could not be verified.") from error
    try:
        before = os.fstat(descriptor)
        chunks: list[bytes] = []
        remaining = _MAX_DEMO_RESERVATION_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
    except OSError as error:
        raise CliFailure("The Zombie Lab reservation could not be verified.") from error
    finally:
        os.close(descriptor)
    if _file_identity(before) != _file_identity(after):
        raise CliFailure("The Zombie Lab reservation changed while it was inspected.")
    data = b"".join(chunks)
    return _DemoReservationSnapshot(
        data=data,
        identity=_file_identity(after),
        modified_at=datetime.fromtimestamp(after.st_mtime, tz=UTC),
        oversized=(
            after.st_size > _MAX_DEMO_RESERVATION_BYTES or len(data) > _MAX_DEMO_RESERVATION_BYTES
        ),
    )


def _parse_demo_reservation(snapshot: _DemoReservationSnapshot) -> DemoReservation | None:
    if snapshot.oversized:
        return None
    try:
        return DemoReservation.model_validate_json(snapshot.data)
    except ValidationError:
        return None


def _lock_demo_guard(descriptor: int) -> bool:
    os.lseek(descriptor, 0, os.SEEK_SET)
    if os.name == "nt":
        import msvcrt

        try:
            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
        except OSError:
            return False
        return True
    import fcntl

    try:
        fcntl.flock(  # type: ignore[attr-defined]
            descriptor,
            fcntl.LOCK_EX | fcntl.LOCK_NB,  # type: ignore[attr-defined]
        )
    except OSError:
        return False
    return True


def _unlock_demo_guard(descriptor: int) -> None:
    try:
        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(  # type: ignore[attr-defined]
                    descriptor,
                    fcntl.LOCK_UN,  # type: ignore[attr-defined]
                )
        except OSError:
            pass
    finally:
        with suppress(OSError):
            os.close(descriptor)


def _acquire_demo_guard(path: Path) -> int:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0),
            0o600,
        )
        if os.fstat(descriptor).st_size == 0:
            os.write(descriptor, b"\0")
            os.fsync(descriptor)
        if not _lock_demo_guard(descriptor):
            raise CliFailure("A Zombie Lab spawn is already in progress; no fixture was started.")
        locked_descriptor = descriptor
        descriptor = None
        return locked_descriptor
    except CliFailure:
        raise
    except OSError as error:
        raise CliFailure("The Zombie Lab spawn guard could not be acquired.") from error
    finally:
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)


def _same_reservation_snapshot(
    observed: _DemoReservationSnapshot | None,
    expected: _DemoReservationSnapshot,
) -> bool:
    return (
        observed is not None
        and observed.identity == expected.identity
        and observed.data == expected.data
        and observed.oversized == expected.oversized
    )


def _atomic_rename_no_replace(source: Path, destination: Path) -> None:
    if os.path.lexists(destination):
        raise FileExistsError(str(destination))
    if os.name == "nt":
        os.rename(source, destination)
        return
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform.startswith("linux"):
        rename_no_replace = getattr(libc, "renameat2", None)
        flag = 1
        arguments = (-100, os.fsencode(source), -100, os.fsencode(destination), flag)
    elif sys.platform == "darwin":
        rename_no_replace = getattr(libc, "renamex_np", None)
        flag = 0x00000004
        arguments = (os.fsencode(source), os.fsencode(destination), flag)
    else:
        rename_no_replace = None
        arguments = ()
    if rename_no_replace is None:
        raise OSError("atomic no-replace rename is unavailable")
    result = rename_no_replace(*arguments)
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number), str(destination))


def _new_reservation_quarantine_path(path: Path) -> Path:
    for _attempt in range(8):
        candidate = path.with_name(path.name + ".quarantine." + secrets.token_hex(16))
        if not os.path.lexists(candidate):
            return candidate
    raise CliFailure("A unique Zombie Lab reservation quarantine could not be allocated.")


def _quarantine_delete_expected_reservation(
    path: Path,
    expected: _DemoReservationSnapshot,
    *,
    revalidation_hook: Callable[[], None] | None = None,
    post_rename_hook: Callable[[Path], None] | None = None,
) -> bool:
    if not _same_reservation_snapshot(_read_demo_reservation_snapshot(path), expected):
        return False
    if revalidation_hook is not None:
        revalidation_hook()
    quarantine = _new_reservation_quarantine_path(path)
    try:
        _atomic_rename_no_replace(path, quarantine)
    except OSError as error:
        raise CliFailure("The Zombie Lab reservation changed before quarantine.") from error
    if post_rename_hook is not None:
        post_rename_hook(quarantine)
    moved = _read_demo_reservation_snapshot(quarantine)
    if _same_reservation_snapshot(moved, expected):
        if os.path.lexists(path):
            raise CliFailure(
                "Zombie Lab reservation conflict; the verified object was retained in quarantine."
            )
        try:
            quarantine.unlink()
        except OSError as error:
            raise CliFailure(
                "The verified Zombie Lab reservation quarantine could not be removed."
            ) from error
        return True
    try:
        _atomic_rename_no_replace(quarantine, path)
    except OSError as error:
        raise CliFailure(
            "Zombie Lab reservation conflict; the unexpected object was retained in quarantine."
        ) from error
    raise CliFailure("The Zombie Lab reservation changed; the unexpected object was restored.")


def _release_demo_reservation(
    lease: DemoReservationLease,
    *,
    revalidation_hook: Callable[[], None] | None = None,
    post_rename_hook: Callable[[Path], None] | None = None,
) -> None:
    if lease.released:
        return
    try:
        expected = _DemoReservationSnapshot(
            data=_json(lease.owner.model_dump(mode="json")).encode("utf-8"),
            identity=lease.marker_identity,
            modified_at=lease.owner.created_at,
            oversized=False,
        )
        removed = _quarantine_delete_expected_reservation(
            lease.path,
            expected,
            revalidation_hook=revalidation_hook,
            post_rename_hook=post_rename_hook,
        )
        if not removed:
            raise CliFailure("The Zombie Lab reservation changed; release was refused.")
    finally:
        lease.released = True
        _unlock_demo_guard(lease.guard_descriptor)


def _reclaim_stale_demo_reservation(
    path: Path,
    snapshot: _DemoReservationSnapshot,
    *,
    owner_probe: Callable[[int], float | None],
    revalidation_hook: Callable[[], None] | None = None,
    post_rename_hook: Callable[[Path], None] | None = None,
) -> bool:
    owner = _parse_demo_reservation(snapshot)
    if owner is None:
        if datetime.now(UTC) - snapshot.modified_at < _MALFORMED_RESERVATION_GRACE:
            return False
        return _quarantine_delete_expected_reservation(
            path,
            snapshot,
            revalidation_hook=revalidation_hook,
            post_rename_hook=post_rename_hook,
        )
    observed_create_time = owner_probe(owner.owner_pid)
    exact_owner_is_live = (
        observed_create_time is not None
        and abs(observed_create_time - owner.owner_create_time) <= 0.02
    )
    if exact_owner_is_live or datetime.now(UTC) < owner.expires_at:
        return False
    return _quarantine_delete_expected_reservation(
        path,
        snapshot,
        revalidation_hook=revalidation_hook,
        post_rename_hook=post_rename_hook,
    )


def _reserve_demo_state(
    *,
    owner_probe: Callable[[int], float | None] = _reservation_owner_create_time,
    revalidation_hook: Callable[[], None] | None = None,
    post_rename_hook: Callable[[Path], None] | None = None,
) -> DemoReservationLease:
    destination = demo_state_path()
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    reservation = destination.with_name(destination.name + ".reservation")
    guard_path = destination.with_name(destination.name + ".reservation.lock")
    guard_descriptor = _acquire_demo_guard(guard_path)
    guard_transferred = False
    descriptor: int | None = None
    created_identity: tuple[int, int, int, int] | None = None
    try:
        existing = _read_demo_reservation_snapshot(reservation)
        if existing is not None and not _reclaim_stale_demo_reservation(
            reservation,
            existing,
            owner_probe=owner_probe,
            revalidation_hook=revalidation_hook,
            post_rename_hook=post_rename_hook,
        ):
            raise CliFailure("A Zombie Lab spawn is already in progress; no fixture was started.")
        if destination.exists():
            raise CliFailure("A Zombie Lab fixture is already registered; stop or reset it first.")
        owner_create_time = owner_probe(os.getpid())
        if owner_create_time is None:
            raise CliFailure("The Zombie Lab reservation owner could not be verified.")
        created_at = datetime.now(UTC)
        owner = DemoReservation(
            owner_pid=os.getpid(),
            owner_create_time=owner_create_time,
            nonce=secrets.token_urlsafe(32),
            created_at=created_at,
            expires_at=created_at + _DEMO_RESERVATION_TTL,
        )
        encoded = _json(owner.model_dump(mode="json")).encode("utf-8")
        try:
            descriptor = os.open(
                reservation,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
        except FileExistsError as error:
            raise CliFailure(
                "A Zombie Lab spawn is already in progress; no fixture was started."
            ) from error
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            if written <= 0:
                raise OSError("reservation write made no progress")
            offset += written
        os.fsync(descriptor)
        created_identity = _file_identity(os.fstat(descriptor))
        os.close(descriptor)
        descriptor = None
        created = _read_demo_reservation_snapshot(reservation)
        if (
            created is None
            or created.identity != created_identity
            or created.data != encoded
            or created.oversized
        ):
            raise CliFailure("The Zombie Lab reservation changed while it was created.")
        lease = DemoReservationLease(
            path=reservation,
            owner=owner,
            marker_identity=created_identity,
            guard_descriptor=guard_descriptor,
        )
        guard_transferred = True
        return lease
    except BaseException:
        if descriptor is not None:
            try:
                created_identity = _file_identity(os.fstat(descriptor))
            except OSError:
                created_identity = None
            os.close(descriptor)
        if created_identity is not None:
            try:
                current = _read_demo_reservation_snapshot(reservation)
                if current is not None and current.identity == created_identity:
                    _quarantine_delete_expected_reservation(reservation, current)
            except (CliFailure, OSError) as cleanup_error:
                raise cleanup_error
        raise
    finally:
        if not guard_transferred:
            _unlock_demo_guard(guard_descriptor)


def _reap_failed_fixture(process: subprocess.Popen[bytes] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def _remove_owned_demo_resources(state: DemoState | None) -> None:
    destination = demo_state_path()
    temporary = destination.with_name(destination.name + f".{os.getpid()}.tmp")
    temporary.unlink(missing_ok=True)
    if state is None:
        return
    with suppress(CliFailure):
        _remove_heartbeat(state)
    try:
        current = DemoState.model_validate_json(destination.read_bytes())
    except (FileNotFoundError, OSError, ValidationError):
        return
    if current.demo_id == state.demo_id and current.token == state.token:
        destination.unlink(missing_ok=True)


def _remove_failed_heartbeat(path: Path | None, token: str | None) -> None:
    if path is None or token is None:
        return
    try:
        data = path.read_bytes()
        payload = json.loads(data)
    except (FileNotFoundError, OSError, UnicodeDecodeError, json.JSONDecodeError):
        return
    if isinstance(payload, dict) and payload.get("token") == token:
        path.unlink(missing_ok=True)


def _read_demo_state() -> DemoState:
    try:
        data = demo_state_path().read_bytes()
        if len(data) > 16_384:
            raise CliFailure("Zombie Lab state exceeds its safety bound.", exit_code=3)
        return DemoState.model_validate_json(data)
    except FileNotFoundError as error:
        raise CliFailure("No Zombie Lab fixture is registered.", exit_code=3) from error
    except (OSError, ValidationError) as error:
        raise CliFailure(
            "Zombie Lab state is invalid; refusing process control.", exit_code=3
        ) from error


def _process_identity(
    state: DemoState,
) -> tuple[Literal["exact", "absent", "mismatch"], psutil.Process | None]:
    if state.mode != "process" or state.pid is None or state.create_time is None:
        return "absent", None
    try:
        process = psutil.Process(state.pid)
        create_time = process.create_time()
        cmdline = process.cmdline()
    except psutil.NoSuchProcess:
        return "absent", None
    except (psutil.AccessDenied, OSError):
        return "mismatch", None
    exact = (
        abs(create_time - state.create_time) <= 0.02
        and state.token in cmdline
        and "zombie_killer_engine.demo_fixture" in cmdline
    )
    return ("exact", process) if exact else ("mismatch", process)


def _demo_public(state: DemoState) -> dict[str, object]:
    identity, _process = _process_identity(state)
    display_state: str = state.state
    if state.mode == "process":
        if identity == "absent":
            display_state = "stopped"
        elif identity == "mismatch":
            display_state = "target_changed"
        else:
            display_state = "orphaned_fixture" if state.state == "running" else state.state
    return {
        "demo_id": state.demo_id,
        "mode": state.mode,
        "state": display_state,
        "pid": state.pid,
        "local_only": True,
        "network_used": False,
    }


@demo_app.command("spawn")
def demo_spawn(
    real: Annotated[
        bool,
        typer.Option("--real", help="Opt in to a harmless identity-tracked local process."),
    ] = False,
    stale_after: Annotated[
        float | None,
        typer.Option("--stale-after", min=1, max=3_600, help="Stop heartbeats after N seconds."),
    ] = None,
    json_output: Annotated[bool, typer.Option("--json", help="Emit one JSON value.")] = False,
) -> None:
    """Create simulated demo data by default, or an opted-in local fixture process."""
    reservation: DemoReservationLease | None = None
    process: subprocess.Popen[bytes] | None = None
    state: DemoState | None = None
    token: str | None = None
    heartbeat: Path | None = None
    try:
        reservation = _reserve_demo_state()
        destination = demo_state_path()
        token = secrets.token_urlsafe(32)
        demo_id = "demo-" + uuid4().hex
        started_at = datetime.now(UTC).isoformat()
        if not real:
            state = DemoState(
                demo_id=demo_id,
                mode="simulated",
                state="orphaned_fixture",
                token=token,
                started_at=started_at,
            )
        else:
            heartbeat = destination.with_name("zombie-lab-heartbeat.json")
            command = [
                sys.executable,
                "-m",
                "zombie_killer_engine.demo_fixture",
                "--token",
                token,
                "--heartbeat",
                str(heartbeat),
            ]
            if stale_after is not None:
                command.extend(("--stale-after", str(stale_after)))
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                creationflags=creationflags,
                start_new_session=os.name != "nt",
            )
            create_time = psutil.Process(process.pid).create_time()
            state = DemoState(
                demo_id=demo_id,
                mode="process",
                state="running",
                token=token,
                pid=process.pid,
                create_time=create_time,
                heartbeat_path=str(heartbeat),
                started_at=started_at,
            )
        _write_demo_state(state)
    except BaseException as error:
        _reap_failed_fixture(process)
        _remove_failed_heartbeat(heartbeat, token)
        _remove_owned_demo_resources(state)
        if isinstance(error, CliFailure):
            _fail(error)
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        _fail(CliFailure("The fixture could not be started safely.", exit_code=3))
    finally:
        if reservation is not None:
            _release_demo_reservation(reservation)
    assert state is not None
    public = _demo_public(state)
    if json_output:
        typer.echo(_json(public))
    else:
        typer.echo(f"Zombie Lab fixture {public['demo_id']} spawned in {state.mode} mode.")


@demo_app.command("status")
def demo_status(
    json_output: Annotated[bool, typer.Option("--json", help="Emit one JSON value.")] = False,
) -> None:
    """Report only the registered fixture's bounded local state."""
    try:
        state = _read_demo_state()
    except CliFailure as error:
        _fail(error)
    public = _demo_public(state)
    typer.echo(_json(public) if json_output else f"Zombie Lab: {public['state']}")


def _stop_demo(state: DemoState) -> DemoState:
    if state.mode == "simulated":
        stopped = state.model_copy(update={"state": "stopped"})
        _write_demo_state(stopped)
        return stopped
    identity, process = _process_identity(state)
    if identity == "mismatch":
        raise CliFailure("Fixture process identity changed; refusing to signal it.", exit_code=3)
    if identity == "exact" and process is not None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except psutil.TimeoutExpired as error:
            raise CliFailure(
                "Fixture did not stop; no unrelated process was signaled.", exit_code=3
            ) from error
    stopped = state.model_copy(update={"state": "stopped"})
    _write_demo_state(stopped)
    return stopped


@demo_app.command("stop")
def demo_stop(
    confirm: Annotated[
        bool, typer.Option("--confirm", help="Authorize the exact fixture stop.")
    ] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Emit one JSON value.")] = False,
) -> None:
    """Stop only the PID/create-time/token-bound fixture process."""
    if not confirm:
        _fail(CliFailure("Stopping a real fixture requires the explicit --confirm flag."))
    try:
        stopped = _stop_demo(_read_demo_state())
    except CliFailure as error:
        _fail(error)
    public = _demo_public(stopped)
    typer.echo(_json(public) if json_output else "Zombie Lab fixture stopped.")


def _remove_heartbeat(state: DemoState) -> None:
    if state.heartbeat_path is None:
        return
    heartbeat = Path(state.heartbeat_path)
    try:
        data = heartbeat.read_bytes()
    except FileNotFoundError:
        return
    except OSError as error:
        raise CliFailure(
            "Fixture heartbeat could not be verified; reset refused.", exit_code=3
        ) from error
    try:
        payload = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CliFailure("Fixture heartbeat is invalid; reset refused.", exit_code=3) from error
    if not isinstance(payload, dict) or payload.get("token") != state.token:
        raise CliFailure("Fixture resource identity changed; reset refused.", exit_code=3)
    heartbeat.unlink()


@demo_app.command("reset")
def demo_reset(
    confirm: Annotated[
        bool, typer.Option("--confirm", help="Authorize exact fixture cleanup.")
    ] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Emit one JSON value.")] = False,
) -> None:
    """Remove only resources recorded for the exact Zombie Lab fixture."""
    if not confirm:
        _fail(CliFailure("Reset requires the explicit --confirm flag."))
    try:
        state = _read_demo_state()
        identity, _process = _process_identity(state)
        if identity == "mismatch":
            raise CliFailure("Fixture process identity changed; reset refused.", exit_code=3)
        if identity == "exact":
            state = _stop_demo(state)
        _remove_heartbeat(state)
        demo_state_path().unlink()
    except (OSError, CliFailure) as error:
        _fail(
            error
            if isinstance(error, CliFailure)
            else CliFailure("Fixture reset failed safely.", exit_code=3)
        )
    result = {"reset": True, "demo_id": state.demo_id}
    typer.echo(_json(result) if json_output else "Zombie Lab fixture reset.")


@app.command("protocol-once", hidden=True)
def protocol_once_command(
    parent_pid: Annotated[
        int | None,
        typer.Option("--parent-pid", min=1, hidden=True),
    ] = None,
    internal_state_root: Annotated[
        Path | None,
        typer.Option("--internal-state-root", hidden=True, resolve_path=False),
    ] = None,
) -> None:
    """Internal: serve one bounded protocol request through EOF."""
    if parent_pid is not None:
        try:
            _start_parent_watch(parent_pid)
        except CliFailure as error:
            _fail(error)
    context = RequestContext(
        client=ClientKind.CONTROLLER,
        capability=Capability.EXECUTION,
        local_control=True,
    )
    try:
        service = (
            build_service(paths=_internal_app_paths(internal_state_root))
            if internal_state_root is not None
            else build_service()
        )
    except CliFailure as error:
        _fail(error)
    raise typer.Exit(serve_once(service, context=context))


@app.command("stdio", hidden=True)
def stdio_command() -> None:
    """Internal: serve persistent bounded NDJSON over inherited stdio."""
    context = RequestContext(
        client=ClientKind.CONTROLLER,
        capability=Capability.EXECUTION,
        local_control=True,
    )
    raise typer.Exit(serve_stdio(build_service(), context=context))


install_local_workflows(app, vault_app, call_service, _json, _fail, CliFailure)


def main() -> None:
    app()


__all__ = ["app", "build_service", "call_service", "demo_state_path", "main"]
