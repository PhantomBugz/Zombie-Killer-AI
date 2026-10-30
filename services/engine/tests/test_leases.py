from __future__ import annotations

import ctypes
import hashlib
import importlib
import json
import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

import zombie_killer_engine.leases as leases_module
from zombie_killer_engine.leases import (
    CANCELLATION_PROTOCOL_VERSION,
    LEASE_PROTOCOL_VERSION,
    MAX_AGGREGATE_LEASE_BYTES,
    MAX_LEASE_BYTES,
    MAX_LEASE_FILES,
    MAX_LEASE_WARNINGS,
    LeaseEnvelope,
    clear_cancellation_request,
    discover_leases,
    observe_cancellation_request,
    read_cancellation_request,
    write_cancellation_request,
)
from zombie_killer_engine.models import ProcessIdentity
from zombie_killer_engine.paths import (
    AppPaths,
    PathWarning,
    PosixPermissionBackend,
    WindowsPermissionBackend,
)

NOW = datetime(2026, 8, 12, 12, 0, tzinfo=UTC)
REGISTRATION_NONCE = "registration-generation-1"


def cancellation_identity(*, create_time: float | None = None) -> ProcessIdentity:
    executable = "/synthetic/bin/agent"
    user = "synthetic-user"
    return ProcessIdentity(
        boot_id="boot-current",
        pid=4242,
        create_time=NOW.timestamp() - 60 if create_time is None else create_time,
        executable=executable,
        user=user,
        executable_hash=hashlib.sha256(executable.encode()).hexdigest(),
        user_hash=hashlib.sha256(user.encode()).hexdigest(),
    )


def lease_payload(
    *,
    agent_id: str = "agent-1",
    boot_id: str = "boot-current",
    pid: int = 4242,
    create_time: float = NOW.timestamp() - 60,
    heartbeat_at: datetime = NOW,
    detached: bool = False,
    lifecycle: str = "running",
    terminal_at: datetime | None = None,
    status: str = "Processing local fixtures",
) -> dict[str, object]:
    return {
        "protocol_version": LEASE_PROTOCOL_VERSION,
        "agent_id": agent_id,
        "registration_nonce": REGISTRATION_NONCE,
        "identity": {
            "boot_id": boot_id,
            "pid": pid,
            "create_time": create_time,
            "executable": "/synthetic/bin/agent",
            "user": "synthetic-user",
        },
        "heartbeat_at": heartbeat_at.isoformat().replace("+00:00", "Z"),
        "heartbeat_timeout_seconds": 30.0,
        "provider": "synthetic-provider",
        "project": "Synthetic Project",
        "role": "worker",
        "status": status,
        "detached": detached,
        "expected_parent_pid": 4000,
        "expected_owner": "synthetic-owner",
        "run_id": "run-1",
        "lifecycle": lifecycle,
        "terminal_at": (
            terminal_at.isoformat().replace("+00:00", "Z") if terminal_at is not None else None
        ),
        "resources": [{"kind": "temporary", "path": "/synthetic/output/result.json"}],
        "counters": {"input_tokens": 12.0},
    }


def write_payload(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_declared_cleanup_authority_is_complete_or_legacy() -> None:
    payload = lease_payload()
    resource = {
        "kind": "temporary",
        "path": "/synthetic/output/result.json",
        "approved_root": "/synthetic/output",
        "resource_type": "file",
        "cleanup_policy": "quarantine",
        "creation_fingerprint": {
            "device": 1,
            "inode": 2,
            "mode": 33152,
            "size": 3,
            "mtime_ns": 4,
            "ctime_ns": 5,
            "content_digest": "a" * 64,
        },
    }
    payload["resources"] = [resource]
    parsed = LeaseEnvelope.model_validate(payload)
    assert parsed.resources[0].approved_root == "/synthetic/output"
    assert parsed.resources[0].creation_fingerprint is not None
    for key in ("approved_root", "resource_type", "cleanup_policy", "creation_fingerprint"):
        payload["resources"] = [{name: value for name, value in resource.items() if name != key}]
        with pytest.raises(ValueError):
            LeaseEnvelope.model_validate(payload)
    payload["resources"] = [{"kind": "temporary", "path": "/synthetic/legacy"}]
    assert LeaseEnvelope.model_validate(payload).resources[0].approved_root is None


def test_exact_registration_reader_preserves_private_resource_authority(tmp_path: Path) -> None:
    paths = AppPaths(
        data_dir=tmp_path / "data",
        state_dir=tmp_path / "state",
        runtime_dir=tmp_path / "runtime",
        backups_dir=tmp_path / "backups",
        graveyard_dir=tmp_path / "graveyard",
    )
    assert not paths.ensure()
    payload = lease_payload()
    target = str(tmp_path / ("sk-" + "fixture" + "A" * 20))
    payload["resources"] = [{"kind": "temporary", "path": target}]
    write_payload(paths.leases_dir / "agent-1.json", payload)

    document = leases_module.read_resource_registration(paths.leases_dir, "agent-1")

    assert document.resources[0].path == target
    assert document.lease.registration_nonce == REGISTRATION_NONCE
    assert discover_leases(paths.leases_dir, now=NOW).leases[0].resources[0].path != target


def test_app_paths_can_be_injected_and_created_under_a_temp_root(tmp_path: Path) -> None:
    paths = AppPaths(
        data_dir=tmp_path / "data",
        state_dir=tmp_path / "state",
        runtime_dir=tmp_path / "runtime",
        backups_dir=tmp_path / "backups",
        graveyard_dir=tmp_path / "graveyard",
    )

    warnings = paths.ensure()

    assert warnings == ()
    assert paths.leases_dir == tmp_path / "runtime" / "leases"
    assert paths.cancellations_dir == tmp_path / "runtime" / "cancellations"
    assert all(
        path.is_dir()
        for path in (
            paths.data_dir,
            paths.state_dir,
            paths.runtime_dir,
            paths.backups_dir,
            paths.graveyard_dir,
            paths.leases_dir,
            paths.cancellations_dir,
        )
    )


def test_windows_paths_apply_injected_restrictive_permissions(tmp_path: Path) -> None:
    paths = AppPaths(
        data_dir=tmp_path / "data",
        state_dir=tmp_path / "state",
        runtime_dir=tmp_path / "runtime",
        backups_dir=tmp_path / "backups",
        graveyard_dir=tmp_path / "graveyard",
    )
    restricted: list[Path] = []

    class RecordingBackend:
        def restrict(self, path: Path) -> None:
            restricted.append(path)

    warnings = paths.ensure(
        platform_name="windows",
        permission_backend=RecordingBackend(),
    )

    assert warnings == ()
    assert set(restricted) == {
        paths.data_dir,
        paths.state_dir,
        paths.runtime_dir,
        paths.backups_dir,
        paths.graveyard_dir,
        paths.leases_dir,
        paths.cancellations_dir,
    }


def test_permission_restriction_failure_is_structured(tmp_path: Path) -> None:
    paths = AppPaths(
        data_dir=tmp_path / "data",
        state_dir=tmp_path / "state",
        runtime_dir=tmp_path / "runtime",
        backups_dir=tmp_path / "backups",
        graveyard_dir=tmp_path / "graveyard",
    )

    class FailingBackend:
        def restrict(self, path: Path) -> None:
            raise OSError(f"sensitive path: {path}")

    warnings = paths.ensure(
        platform_name="windows",
        permission_backend=FailingBackend(),
    )

    assert len(warnings) == 7
    assert all(isinstance(warning, PathWarning) for warning in warnings)
    assert all(warning.code == "DIRECTORY_PERMISSION_RESTRICTION_FAILED" for warning in warnings)
    assert all("sensitive path" not in warning.message for warning in warnings)


def test_windows_permissions_are_inheritable_to_child_files() -> None:
    assert "(A;OICI;FA;;;OW)" in WindowsPermissionBackend.SECURITY_DESCRIPTOR
    assert "(A;OICI;FA;;;SY)" in WindowsPermissionBackend.SECURITY_DESCRIPTOR


@pytest.mark.skipif(os.name == "nt", reason="POSIX ownership semantics only")
def test_posix_permissions_reject_directory_owned_by_another_user(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import zombie_killer_engine.paths as paths_module

    actual_owner = os.stat(tmp_path).st_uid
    monkeypatch.setattr(paths_module, "_effective_user_id", lambda: actual_owner + 1)

    with pytest.raises(OSError, match="not owned by the current user"):
        PosixPermissionBackend().restrict(tmp_path)


def test_app_paths_reject_redirected_existing_directory(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    redirected = tmp_path / "redirected"
    try:
        redirected.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink creation is unavailable on this host")
    paths = AppPaths(
        data_dir=redirected,
        state_dir=tmp_path / "state",
        runtime_dir=tmp_path / "runtime",
        backups_dir=redirected / "backups",
        graveyard_dir=tmp_path / "graveyard",
    )
    restricted: list[Path] = []

    class RecordingBackend:
        def restrict(self, path: Path) -> None:
            restricted.append(path)

    warnings = paths.ensure(permission_backend=RecordingBackend())

    assert redirected not in restricted
    assert paths.backups_dir not in restricted
    assert not (outside / "backups").exists()
    assert any(warning.code == "DIRECTORY_REDIRECTED" for warning in warnings)


def test_valid_lease_parses_exact_process_identity_and_metadata(tmp_path: Path) -> None:
    payload = lease_payload()
    assert LeaseEnvelope.model_validate(payload).protocol_version == LEASE_PROTOCOL_VERSION
    write_payload(tmp_path / "agent-1.json", payload)

    result = discover_leases(tmp_path, now=NOW)

    assert result.warnings == ()
    assert result.malformed_count == 0
    assert len(result.leases) == 1
    document = result.leases[0]
    assert document.lease.agent_id == "agent-1"
    assert document.lease.identity.pid == 4242
    assert document.lease.identity.create_time == NOW.timestamp() - 60
    assert document.provider == "synthetic-provider"
    assert document.project == "Synthetic Project"
    assert document.role == "worker"
    assert document.status == "Processing local fixtures"
    assert document.resources[0].path == "/synthetic/output/result.json"


def test_json_integer_numbers_are_accepted_without_string_coercion(tmp_path: Path) -> None:
    payload = lease_payload()
    identity = payload["identity"]
    assert isinstance(identity, dict)
    identity["create_time"] = int(NOW.timestamp() - 60)
    payload["heartbeat_timeout_seconds"] = 30
    write_payload(tmp_path / "integer-numbers.json", payload)

    result = discover_leases(tmp_path, now=NOW)

    assert result.malformed_count == 0
    assert result.leases[0].lease.identity.create_time == NOW.timestamp() - 60
    assert result.leases[0].lease.heartbeat_timeout_seconds == 30.0


@pytest.mark.parametrize(
    ("name", "content", "expected_code"),
    [
        ("broken.json", "{not-json", "LEASE_MALFORMED_JSON"),
        (
            "extra.json",
            json.dumps({**lease_payload(), "api_key": "top-secret"}),
            "LEASE_SCHEMA_INVALID",
        ),
    ],
)
def test_malformed_or_schema_invalid_lease_warns_without_crashing(
    tmp_path: Path,
    name: str,
    content: str,
    expected_code: str,
) -> None:
    (tmp_path / name).write_text(content, encoding="utf-8")

    result = discover_leases(tmp_path, now=NOW)

    assert result.leases == ()
    assert result.malformed_count == 1
    assert result.warnings[0].code == expected_code
    assert len(result.warnings[0].message) <= 512
    assert "top-secret" not in result.warnings[0].message


def test_oversized_lease_is_rejected_before_json_parsing(tmp_path: Path) -> None:
    (tmp_path / "huge.json").write_bytes(b"{" + b"x" * MAX_LEASE_BYTES)

    result = discover_leases(tmp_path, now=NOW)

    assert result.leases == ()
    assert result.malformed_count == 1
    assert result.warnings[0].code == "LEASE_TOO_LARGE"


def test_lease_file_budget_tracks_total_and_skipped_candidates(tmp_path: Path) -> None:
    for index in range(5):
        (tmp_path / f"bad-{index}.json").write_text("{", encoding="utf-8")

    result = discover_leases(tmp_path, now=NOW, max_files=2)

    assert result.total_count == 5
    assert result.malformed_count == 2
    assert result.skipped_count == 3
    assert any(warning.code == "LEASE_FILE_BUDGET_EXCEEDED" for warning in result.warnings)
    assert MAX_LEASE_FILES > 2


def test_aggregate_byte_budget_bounds_parsing(tmp_path: Path) -> None:
    for index in range(3):
        write_payload(
            tmp_path / f"agent-{index}.json",
            lease_payload(agent_id=f"agent-{index}", pid=5000 + index),
        )
    first_size = (tmp_path / "agent-0.json").stat().st_size

    result = discover_leases(
        tmp_path,
        now=NOW,
        max_aggregate_bytes=first_size,
    )

    assert result.total_count == 3
    assert len(result.leases) == 1
    assert result.skipped_count == 2
    assert first_size < MAX_AGGREGATE_LEASE_BYTES


def test_repeated_lease_warnings_are_aggregated_and_bounded(tmp_path: Path) -> None:
    for index in range(10):
        (tmp_path / f"bad-{index}.json").write_text("{", encoding="utf-8")

    result = discover_leases(tmp_path, now=NOW, max_warnings=2)

    assert result.total_count == 10
    assert result.malformed_count == 10
    assert len(result.warnings) <= 2
    assert any(warning.code == "LEASE_WARNING_SUMMARY" for warning in result.warnings)
    assert MAX_LEASE_WARNINGS > 2


def test_deeply_nested_json_is_rejected_without_recursion_crash(tmp_path: Path) -> None:
    (tmp_path / "deep.json").write_text("[" * 5000 + "]" * 5000, encoding="utf-8")

    result = discover_leases(tmp_path, now=NOW)

    assert result.leases == ()
    assert result.malformed_count == 1
    assert result.warnings[0].code == "LEASE_MALFORMED_JSON"


def test_missing_directory_and_disappearing_file_are_bounded_warnings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    missing = discover_leases(tmp_path / "missing", now=NOW)
    assert missing.leases == ()
    assert missing.malformed_count == 0

    target = tmp_path / "race.json"
    write_payload(target, lease_payload())
    real_open = os.open

    def racing_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        *args: object,
        **kwargs: object,
    ) -> int:
        if Path(path).name == target.name:
            target.unlink(missing_ok=True)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", racing_open)
    raced = discover_leases(tmp_path, now=NOW)

    assert raced.leases == ()
    assert raced.malformed_count == 1
    assert raced.warnings[0].code == "LEASE_READ_FAILED"
    assert len(raced.warnings[0].message) <= 512


def test_stat_race_does_not_hide_other_valid_leases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    race = tmp_path / "a-race.json"
    valid = tmp_path / "b-valid.json"
    write_payload(race, lease_payload(agent_id="race"))
    write_payload(valid, lease_payload(agent_id="valid"))
    real_lstat = os.lstat
    real_stat = os.stat

    def racing_lstat(path: object, *args: object, **kwargs: object) -> os.stat_result:
        if Path(path).name == race.name:
            race.unlink(missing_ok=True)
            raise FileNotFoundError(path)
        return real_lstat(path, *args, **kwargs)

    def racing_stat(path: object, *args: object, **kwargs: object) -> os.stat_result:
        if Path(path).name == race.name:
            race.unlink(missing_ok=True)
            raise FileNotFoundError(path)
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", racing_lstat)
    monkeypatch.setattr(os, "stat", racing_stat)

    result = discover_leases(tmp_path, now=NOW)

    assert [document.lease.agent_id for document in result.leases] == ["valid"]
    assert result.malformed_count == 1
    assert result.warnings[0].code == "LEASE_READ_FAILED"


def test_discovery_ignores_non_json_nested_and_symlink_entries(tmp_path: Path) -> None:
    write_payload(tmp_path / "valid.json", lease_payload())
    write_payload(tmp_path / "ignored.txt", lease_payload(agent_id="text"))
    nested = tmp_path / "nested"
    nested.mkdir()
    write_payload(nested / "nested.json", lease_payload(agent_id="nested"))
    symlink = tmp_path / "link.json"
    try:
        symlink.symlink_to(tmp_path / "valid.json")
    except OSError:
        pytest.skip("symlink creation is unavailable on this host")

    result = discover_leases(tmp_path, now=NOW)

    assert [document.lease.agent_id for document in result.leases] == ["agent-1"]
    assert result.malformed_count == 1
    assert result.warnings[0].code == "LEASE_REDIRECTED"


def test_discovery_rejects_symlinked_lease_directory(tmp_path: Path) -> None:
    actual = tmp_path / "actual"
    actual.mkdir()
    write_payload(actual / "valid.json", lease_payload())
    linked = tmp_path / "linked"
    try:
        linked.symlink_to(actual, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink creation is unavailable on this host")

    result = discover_leases(linked, now=NOW)

    assert result.leases == ()
    assert result.warnings[0].code == "LEASE_DIRECTORY_REDIRECTED"


@pytest.mark.skipif(os.name == "nt", reason="POSIX ancestor symlink semantics only")
def test_discovery_rejects_symlinked_lease_directory_ancestor(tmp_path: Path) -> None:
    actual = tmp_path / "actual"
    leases = actual / "leases"
    leases.mkdir(parents=True)
    write_payload(leases / "valid.json", lease_payload())
    linked = tmp_path / "linked"
    linked.symlink_to(actual, target_is_directory=True)

    result = discover_leases(linked / "leases", now=NOW)

    assert result.leases == ()
    assert result.warnings[0].code == "LEASE_DIRECTORY_REDIRECTED"


@pytest.mark.skipif(os.name != "nt", reason="Windows junction semantics only")
def test_discovery_rejects_junction_lease_directory_ancestor(tmp_path: Path) -> None:
    actual = tmp_path / "actual"
    leases = actual / "leases"
    leases.mkdir(parents=True)
    write_payload(leases / "valid.json", lease_payload())
    junction = tmp_path / "junction"
    create_junction = importlib.import_module("_winapi").CreateJunction
    try:
        create_junction(str(actual), str(junction))
    except OSError:
        pytest.skip("junction creation is unavailable on this host")

    result = discover_leases(junction / "leases", now=NOW)

    assert result.leases == ()
    assert result.warnings[0].code == "LEASE_DIRECTORY_REDIRECTED"


def test_discovery_fails_closed_when_directory_chain_cannot_be_verified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import zombie_killer_engine.leases as leases_module

    write_payload(tmp_path / "valid.json", lease_payload())

    def unavailable(path: Path) -> object:
        raise NotImplementedError(path)

    monkeypatch.setattr(
        leases_module,
        "_open_verified_lease_directory",
        unavailable,
        raising=False,
    )
    result = discover_leases(tmp_path, now=NOW)

    assert result.leases == ()
    assert result.warnings[0].code == "LEASE_DIRECTORY_UNVERIFIABLE"


def test_posix_component_identity_swap_fails_closed_without_fd_leak(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import zombie_killer_engine.leases as leases_module

    opened = iter((10, 11, 12, 13, 14, 15))
    closed: list[int] = []

    def fake_open(*args: object, **kwargs: object) -> int:
        return next(opened)

    def fake_stat(*args: object, **kwargs: object) -> object:
        return SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o700,
            st_dev=7,
            st_ino=100,
        )

    def fake_fstat(descriptor: int) -> object:
        return SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o700,
            st_dev=7,
            st_ino=101 if descriptor == 11 else 100,
        )

    monkeypatch.setattr(os, "O_DIRECTORY", 0x10000, raising=False)
    monkeypatch.setattr(os, "O_NOFOLLOW", 0x20000, raising=False)
    monkeypatch.setattr(os, "open", fake_open)
    monkeypatch.setattr(os, "stat", fake_stat)
    monkeypatch.setattr(os, "fstat", fake_fstat)
    monkeypatch.setattr(os, "close", closed.append)
    monkeypatch.setattr(os, "supports_dir_fd", {fake_open, fake_stat})
    monkeypatch.setattr(os, "supports_follow_symlinks", {fake_stat})
    monkeypatch.setattr(os, "supports_fd", {os.scandir})

    with pytest.raises(OSError, match="changed while opening"):
        leases_module._open_verified_posix_directory(Path("/synthetic/leases"))

    assert closed == [11, 10]


@pytest.mark.skipif(os.name != "nt", reason="Windows handle accounting only")
def test_windows_component_lstat_failure_does_not_leak_handle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import zombie_killer_engine.leases as leases_module

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    kernel32.GetProcessHandleCount.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_ulong),
    )
    before = ctypes.c_ulong()
    assert kernel32.GetProcessHandleCount(kernel32.GetCurrentProcess(), ctypes.byref(before))
    real_lstat = os.lstat

    def failing_lstat(path: object, *args: object, **kwargs: object) -> os.stat_result:
        if Path(path) == tmp_path:
            raise PermissionError(path)
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", failing_lstat)
    for _ in range(10):
        result = leases_module.discover_leases(tmp_path, now=NOW)
        assert result.leases == ()
    after = ctypes.c_ulong()
    assert kernel32.GetProcessHandleCount(kernel32.GetCurrentProcess(), ctypes.byref(after))

    assert after.value <= before.value


def test_unexpected_enumeration_failure_closes_verified_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import zombie_killer_engine.leases as leases_module

    closed = False

    class InjectedDirectory:
        directory_fd = None
        directory_stat = os.stat(tmp_path)

        def verify(self) -> None:
            return None

        def close(self) -> None:
            nonlocal closed
            closed = True

    monkeypatch.setattr(
        leases_module,
        "_open_verified_lease_directory",
        lambda path: InjectedDirectory(),
    )

    def fail_scandir(path: object) -> object:
        raise RuntimeError(path)

    monkeypatch.setattr(os, "scandir", fail_scandir)
    with pytest.raises(RuntimeError):
        discover_leases(tmp_path, now=NOW)

    assert closed is True


def test_child_swapped_to_same_inode_symlink_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "agent-1.json"
    write_payload(target, lease_payload())
    backing = tmp_path / "backing"
    real_open = os.open
    raced = False

    def racing_open(
        path: object,
        flags: int,
        *args: object,
        **kwargs: object,
    ) -> int:
        nonlocal raced
        if not raced and Path(path).name == target.name:
            raced = True
            target.replace(backing)
            try:
                target.symlink_to(backing)
            except OSError:
                backing.replace(target)
                pytest.skip("symlink creation is unavailable on this host")
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", racing_open)
    result = discover_leases(tmp_path, now=NOW)

    assert result.leases == ()
    assert result.malformed_count == 1
    assert result.warnings[0].code == "LEASE_READ_FAILED"


@pytest.mark.skipif(os.name != "nt", reason="Windows path revalidation only")
def test_windows_root_change_after_enumeration_rejects_candidates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_payload(tmp_path / "agent-1.json", lease_payload())
    real_lstat = os.lstat
    root_checks = 0

    def changing_lstat(path: object, *args: object, **kwargs: object) -> os.stat_result:
        nonlocal root_checks
        if Path(path) == tmp_path:
            root_checks += 1
            if root_checks >= 3:
                raise OSError("simulated root replacement")
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", changing_lstat)
    result = discover_leases(tmp_path, now=NOW)

    assert result.leases == ()
    assert result.warnings[0].code == "LEASE_DIRECTORY_READ_FAILED"


def test_previous_boot_lease_is_retained_for_scanner_classification(tmp_path: Path) -> None:
    write_payload(
        tmp_path / "previous.json",
        lease_payload(agent_id="previous", boot_id="boot-previous"),
    )

    result = discover_leases(tmp_path, now=NOW)

    assert result.leases[0].lease.identity.boot_id == "boot-previous"


def test_expired_terminal_lease_is_removed_and_not_returned(tmp_path: Path) -> None:
    target = tmp_path / "completed.json"
    write_payload(
        target,
        lease_payload(
            lifecycle="completed",
            terminal_at=NOW - timedelta(hours=25),
            heartbeat_at=NOW - timedelta(hours=25),
        ),
    )

    result = discover_leases(
        tmp_path,
        now=NOW,
        terminal_retention_seconds=24 * 60 * 60,
    )

    assert result.leases == ()
    assert result.malformed_count == 0
    assert not target.exists()


def test_duplicate_agent_ids_are_rejected_deterministically(tmp_path: Path) -> None:
    write_payload(tmp_path / "a.json", lease_payload(agent_id="duplicate"))
    write_payload(tmp_path / "b.json", lease_payload(agent_id="duplicate", pid=5252))

    result = discover_leases(tmp_path, now=NOW)

    assert len(result.leases) == 1
    assert result.leases[0].source_name == "a.json"
    assert result.malformed_count == 1
    assert result.warnings[0].code == "LEASE_DUPLICATE_AGENT_ID"


def test_expired_terminal_lease_does_not_reserve_agent_id(tmp_path: Path) -> None:
    write_payload(
        tmp_path / "a-expired.json",
        lease_payload(
            agent_id="same-agent",
            lifecycle="completed",
            terminal_at=NOW - timedelta(hours=25),
            heartbeat_at=NOW - timedelta(hours=25),
        ),
    )
    write_payload(
        tmp_path / "b-active.json",
        lease_payload(agent_id="same-agent"),
    )

    result = discover_leases(tmp_path, now=NOW)

    assert [document.source_name for document in result.leases] == ["b-active.json"]
    assert result.malformed_count == 0


@pytest.mark.parametrize("agent_id", ["a/b", "a\\b", "CON", "con.worker", "agent."])
def test_lease_agent_ids_use_portable_cancellation_namespace(tmp_path: Path, agent_id: str) -> None:
    write_payload(tmp_path / "invalid-agent.json", lease_payload(agent_id=agent_id))

    result = discover_leases(tmp_path, now=NOW)

    assert result.leases == ()
    assert result.warnings[0].code == "LEASE_SCHEMA_INVALID"


def test_terminal_cleanup_does_not_delete_concurrently_replaced_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "agent-1.json"
    write_payload(
        target,
        lease_payload(
            lifecycle="completed",
            terminal_at=NOW - timedelta(hours=25),
            heartbeat_at=NOW - timedelta(hours=25),
        ),
    )
    replacement_payload = lease_payload(status="New active lease")
    real_replace = os.replace
    raced = False

    def racing_replace(
        source: object,
        destination: object,
        *args: object,
        **kwargs: object,
    ) -> None:
        nonlocal raced
        if ".terminal-quarantine-" in Path(destination).name and not raced:
            raced = True
            replacement = tmp_path / ".replacement.tmp"
            write_payload(replacement, replacement_payload)
            real_replace(replacement, target)
        real_replace(source, destination, *args, **kwargs)

    monkeypatch.setattr(os, "replace", racing_replace)
    result = discover_leases(tmp_path, now=NOW)

    assert result.leases == ()
    assert target.exists()
    assert json.loads(target.read_text(encoding="utf-8"))["status"] == "New active lease"
    assert list(tmp_path.glob(".terminal-quarantine-*.tmp")) == []
    refreshed = discover_leases(tmp_path, now=NOW)
    assert refreshed.leases[0].status == "New active lease"


def test_terminal_cleanup_restores_replacement_when_hard_link_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "agent-1.json"
    write_payload(
        target,
        lease_payload(
            lifecycle="completed",
            terminal_at=NOW - timedelta(hours=25),
            heartbeat_at=NOW - timedelta(hours=25),
        ),
    )
    replacement_payload = lease_payload(status="Replacement survives")
    real_replace = os.replace
    raced = False

    def racing_replace(
        source: object,
        destination: object,
        *args: object,
        **kwargs: object,
    ) -> None:
        nonlocal raced
        if ".terminal-quarantine-" in Path(destination).name and not raced:
            raced = True
            replacement = tmp_path / ".replacement.tmp"
            write_payload(replacement, replacement_payload)
            real_replace(replacement, target)
        real_replace(source, destination, *args, **kwargs)

    def failing_link(*args: object, **kwargs: object) -> None:
        raise OSError("hard links unavailable")

    monkeypatch.setattr(os, "replace", racing_replace)
    monkeypatch.setattr(os, "link", failing_link)
    result = discover_leases(tmp_path, now=NOW)

    assert result.leases == ()
    assert target.is_file()
    assert json.loads(target.read_text(encoding="utf-8"))["status"] == ("Replacement survives")


@pytest.mark.parametrize(
    "update",
    [
        {"protocol_version": 999},
        {"heartbeat_at": "2026-08-12T12:00:00"},
        {"resources": [{"kind": "temporary", "path": f"/tmp/{index}"} for index in range(65)]},
        {"counters": {f"counter-{index}": 1.0 for index in range(65)}},
    ],
)
def test_protocol_timestamp_and_collection_bounds_are_strict(
    tmp_path: Path, update: dict[str, object]
) -> None:
    write_payload(tmp_path / "invalid.json", {**lease_payload(), **update})

    result = discover_leases(tmp_path, now=NOW)

    assert result.leases == ()
    assert result.malformed_count == 1
    assert result.warnings[0].code == "LEASE_SCHEMA_INVALID"


def test_cancellation_request_write_observe_and_clear_is_atomic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    replacements: list[tuple[Path, Path]] = []
    real_replace = os.replace

    def recording_replace(source: str | os.PathLike[str], target: str | os.PathLike[str]) -> None:
        replacements.append((Path(source), Path(target)))
        real_replace(source, target)

    monkeypatch.setattr(os, "replace", recording_replace)

    target_identity = cancellation_identity()
    request_path = write_cancellation_request(
        tmp_path,
        "agent-1",
        target_identity=target_identity,
        registration_nonce=REGISTRATION_NONCE,
        plan_id="plan-1",
        requested_at=NOW,
        expires_at=NOW + timedelta(seconds=30),
    )

    assert request_path == tmp_path / "agent-1.json"
    assert replacements and replacements[0][1] == request_path
    assert replacements[0][0] != request_path
    assert not replacements[0][0].exists()
    observed = observe_cancellation_request(
        tmp_path,
        "agent-1",
        observer_identity=target_identity,
        registration_nonce=REGISTRATION_NONCE,
        now=NOW,
    )
    assert observed is not None
    assert observed.agent_id == "agent-1"
    assert observed.requested_at == NOW
    assert observed.expires_at == NOW + timedelta(seconds=30)
    assert observed.plan_id == "plan-1"
    assert observed.registration_nonce == REGISTRATION_NONCE
    assert observed.target.pid == target_identity.pid
    assert len(observed.request_id) == 32
    assert (
        read_cancellation_request(
            tmp_path,
            "agent-1",
            observer_identity=target_identity,
            registration_nonce=REGISTRATION_NONCE,
            now=NOW,
        )
        == observed
    )
    assert (
        clear_cancellation_request(
            tmp_path,
            "agent-1",
            observer_identity=target_identity,
            registration_nonce=REGISTRATION_NONCE,
            now=NOW,
        )
        is True
    )
    assert (
        observe_cancellation_request(
            tmp_path,
            "agent-1",
            observer_identity=target_identity,
            registration_nonce=REGISTRATION_NONCE,
            now=NOW,
        )
        is None
    )


def test_invalid_cancellation_content_is_observed_fail_closed(tmp_path: Path) -> None:
    (tmp_path / "agent-1.json").write_text(
        "[" * 5000 + "]" * 5000,
        encoding="utf-8",
    )

    assert (
        observe_cancellation_request(
            tmp_path,
            "agent-1",
            observer_identity=cancellation_identity(),
            registration_nonce=REGISTRATION_NONCE,
            now=NOW,
        )
        is None
    )


def test_legacy_unbound_cancellation_request_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "agent-1.json").write_text(
        json.dumps(
            {
                "protocol_version": 1,
                "agent_id": "agent-1",
                "request_id": "legacy-request",
                "requested_at": NOW.isoformat().replace("+00:00", "Z"),
            }
        ),
        encoding="utf-8",
    )

    assert CANCELLATION_PROTOCOL_VERSION > 1
    assert (
        observe_cancellation_request(
            tmp_path,
            "agent-1",
            observer_identity=cancellation_identity(),
            registration_nonce=REGISTRATION_NONCE,
            now=NOW,
        )
        is None
    )


def test_cancellation_request_lifetime_is_bounded(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="lifetime"):
        write_cancellation_request(
            tmp_path,
            "agent-1",
            target_identity=cancellation_identity(),
            registration_nonce=REGISTRATION_NONCE,
            plan_id="plan-1",
            requested_at=NOW,
            expires_at=NOW + timedelta(seconds=31),
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows SID cancellation fingerprint")
def test_windows_raw_sdk_identity_observes_sid_authorized_request(
    tmp_path: Path,
) -> None:
    from zombie_killer_engine.actions import PsutilProcessController

    controller = PsutilProcessController()
    authorized = controller.read_identity(os.getpid())
    raw_observer = authorized.model_copy(update={"user_hash": None})
    write_cancellation_request(
        tmp_path,
        "agent-1",
        target_identity=authorized,
        registration_nonce=REGISTRATION_NONCE,
        plan_id="plan-1",
        requested_at=NOW,
        expires_at=NOW + timedelta(seconds=30),
    )

    observed = observe_cancellation_request(
        tmp_path,
        "agent-1",
        observer_identity=raw_observer,
        registration_nonce=REGISTRATION_NONCE,
        now=NOW,
    )

    assert observed is not None
    assert (
        observe_cancellation_request(
            tmp_path,
            "agent-1",
            observer_identity=raw_observer.model_copy(update={"user_hash": "0" * 64}),
            registration_nonce=REGISTRATION_NONCE,
            now=NOW,
        )
        is None
    )


def test_cancellation_publish_rejects_redirected_runtime_ancestor(
    tmp_path: Path,
) -> None:
    actual_runtime = tmp_path / "actual-runtime"
    actual_cancellations = actual_runtime / "cancellations"
    actual_cancellations.mkdir(parents=True)
    redirected_runtime = tmp_path / "runtime"
    if os.name == "nt":
        create_junction = importlib.import_module("_winapi").CreateJunction
        try:
            create_junction(str(actual_runtime), str(redirected_runtime))
        except OSError:
            pytest.skip("junction creation is unavailable on this host")
    else:
        redirected_runtime.symlink_to(actual_runtime, target_is_directory=True)
    target_identity = cancellation_identity()
    if os.name == "nt":
        from zombie_killer_engine.actions import PsutilProcessController

        target_identity = PsutilProcessController().read_identity(os.getpid())

    with pytest.raises(OSError, match="redirect|reparse|link"):
        write_cancellation_request(
            redirected_runtime / "cancellations",
            "agent-1",
            target_identity=target_identity,
            registration_nonce=REGISTRATION_NONCE,
            plan_id="plan-1",
            requested_at=NOW,
            expires_at=NOW + timedelta(seconds=30),
        )

    assert not (actual_cancellations / "agent-1.json").exists()
    assert not tuple(actual_cancellations.glob("*.tmp"))


def test_cancellation_observer_rejects_redirected_runtime_ancestor(
    tmp_path: Path,
) -> None:
    actual_runtime = tmp_path / "actual-runtime"
    actual_cancellations = actual_runtime / "cancellations"
    actual_cancellations.mkdir(parents=True)
    target_identity = cancellation_identity()
    write_cancellation_request(
        actual_cancellations,
        "agent-1",
        target_identity=target_identity,
        registration_nonce=REGISTRATION_NONCE,
        plan_id="plan-1",
        requested_at=NOW,
        expires_at=NOW + timedelta(seconds=30),
    )
    redirected_runtime = tmp_path / "runtime"
    if os.name == "nt":
        create_junction = importlib.import_module("_winapi").CreateJunction
        try:
            create_junction(str(actual_runtime), str(redirected_runtime))
        except OSError:
            pytest.skip("junction creation is unavailable on this host")
    else:
        redirected_runtime.symlink_to(actual_runtime, target_is_directory=True)

    assert (
        observe_cancellation_request(
            redirected_runtime / "cancellations",
            "agent-1",
            observer_identity=target_identity,
            registration_nonce=REGISTRATION_NONCE,
            now=NOW,
        )
        is None
    )


@pytest.mark.parametrize("mismatch", ["identity", "nonce", "expired"])
def test_cancellation_observation_requires_exact_live_registration(
    tmp_path: Path,
    mismatch: str,
) -> None:
    target_identity = cancellation_identity()
    write_cancellation_request(
        tmp_path,
        "agent-1",
        target_identity=target_identity,
        registration_nonce=REGISTRATION_NONCE,
        plan_id="plan-1",
        requested_at=NOW,
        expires_at=NOW + timedelta(seconds=30),
    )
    observer = (
        cancellation_identity(create_time=target_identity.create_time + 1)
        if mismatch == "identity"
        else target_identity
    )

    assert (
        observe_cancellation_request(
            tmp_path,
            "agent-1",
            observer_identity=observer,
            registration_nonce=(
                "replacement-registration" if mismatch == "nonce" else REGISTRATION_NONCE
            ),
            now=NOW + (timedelta(seconds=31) if mismatch == "expired" else timedelta()),
        )
        is None
    )


def test_clear_acknowledges_only_the_observed_cancellation_generation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target_identity = cancellation_identity()
    write_cancellation_request(
        tmp_path,
        "agent-1",
        target_identity=target_identity,
        registration_nonce=REGISTRATION_NONCE,
        plan_id="plan-1",
        requested_at=NOW,
        expires_at=NOW + timedelta(seconds=30),
    )
    target = tmp_path / "agent-1.json"
    acknowledgement = tmp_path / "agent-1.cleared"
    replacement_time = NOW + timedelta(seconds=1)
    replacement_id = "replacement-request-1"
    replacement_payload = json.loads(target.read_text(encoding="utf-8"))
    replacement_payload.update(
        {
            "request_id": replacement_id,
            "requested_at": replacement_time.isoformat().replace("+00:00", "Z"),
            "expires_at": (replacement_time + timedelta(seconds=30))
            .isoformat()
            .replace("+00:00", "Z"),
        }
    )
    real_replace = os.replace
    raced = False

    def racing_replace(source: object, destination: object) -> None:
        nonlocal raced
        if Path(destination) == acknowledgement and not raced:
            raced = True
            replacement = tmp_path / ".replacement.tmp"
            replacement.write_text(
                json.dumps(replacement_payload),
                encoding="utf-8",
            )
            real_replace(replacement, target)
        real_replace(source, destination)

    monkeypatch.setattr(os, "replace", racing_replace)

    assert (
        clear_cancellation_request(
            tmp_path,
            "agent-1",
            observer_identity=target_identity,
            registration_nonce=REGISTRATION_NONCE,
            now=NOW,
        )
        is True
    )
    observed = read_cancellation_request(
        tmp_path,
        "agent-1",
        observer_identity=target_identity,
        registration_nonce=REGISTRATION_NONCE,
        now=replacement_time,
    )
    assert observed is not None
    assert observed.request_id == replacement_id
    assert observed.requested_at == replacement_time


@pytest.mark.parametrize(
    "agent_id",
    ["../escape", "a/b", "a\\b", "", ".", "CON", "con.worker", "agent."],
)
def test_cancellation_agent_id_cannot_escape_directory(tmp_path: Path, agent_id: str) -> None:
    with pytest.raises(ValueError):
        write_cancellation_request(
            tmp_path,
            agent_id,
            target_identity=cancellation_identity(),
            registration_nonce=REGISTRATION_NONCE,
            plan_id="plan-1",
            requested_at=NOW,
            expires_at=NOW + timedelta(seconds=30),
        )


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode probe")
def test_cancellation_observer_rejects_broadly_writable_directory(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "cancellations"
    identity = cancellation_identity()
    write_cancellation_request(
        directory,
        "agent-1",
        target_identity=identity,
        registration_nonce=REGISTRATION_NONCE,
        plan_id="plan-1",
        requested_at=NOW,
        expires_at=NOW + timedelta(seconds=30),
    )
    directory.chmod(0o777)

    observed = observe_cancellation_request(
        directory,
        "agent-1",
        process_identity=identity,
        registration_nonce=REGISTRATION_NONCE,
        now=NOW + timedelta(seconds=1),
    )

    assert observed is None


def test_cancellation_observation_never_follows_permission_check_path_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "cancellations"
    replacement = tmp_path / "replacement"
    displaced = tmp_path / "displaced"
    identity = cancellation_identity()
    for target, plan_id in ((directory, "plan-a"), (replacement, "plan-b")):
        write_cancellation_request(
            target,
            "agent-1",
            target_identity=identity,
            registration_nonce=REGISTRATION_NONCE,
            plan_id=plan_id,
            requested_at=NOW,
            expires_at=NOW + timedelta(seconds=30),
        )
    real_verify = leases_module._verify_cancellation_directory_permissions

    def swapping_verify(verified: object, path: Path) -> None:
        os.replace(directory, displaced)
        os.replace(replacement, directory)
        real_verify(verified, path)  # type: ignore[arg-type]

    monkeypatch.setattr(
        leases_module,
        "_verify_cancellation_directory_permissions",
        swapping_verify,
    )

    observed = read_cancellation_request(
        directory,
        "agent-1",
        observer_identity=identity,
        registration_nonce=REGISTRATION_NONCE,
        now=NOW + timedelta(seconds=1),
    )

    assert observed is None or observed.plan_id == "plan-a"


def test_cancellation_publication_is_relative_to_permission_checked_handle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "cancellations"
    replacement = tmp_path / "replacement"
    displaced = tmp_path / "displaced"
    directory.mkdir(mode=0o700)
    replacement.mkdir(mode=0o700)
    real_restrict = leases_module._restrict_verified_cancellation_directory

    def swapping_restrict(verified: object, path: Path) -> None:
        os.replace(directory, displaced)
        os.replace(replacement, directory)
        real_restrict(verified, path)  # type: ignore[arg-type]

    monkeypatch.setattr(
        leases_module,
        "_restrict_verified_cancellation_directory",
        swapping_restrict,
    )

    try:
        write_cancellation_request(
            directory,
            "agent-1",
            target_identity=cancellation_identity(),
            registration_nonce=REGISTRATION_NONCE,
            plan_id="plan-a",
            requested_at=NOW,
            expires_at=NOW + timedelta(seconds=30),
        )
    except OSError:
        assert os.name == "nt"
        return

    assert os.name != "nt"
    assert (displaced / "agent-1.cancel.json").is_file()
    assert not (directory / "agent-1.cancel.json").exists()
