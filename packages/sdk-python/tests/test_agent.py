from __future__ import annotations

import asyncio
import gc
import json
import signal
import threading
import uuid
import weakref
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from zombie_killer import Agent, BudgetExceeded, BudgetReservation, SDKError, register
from zombie_killer.lease import ProcessIdentity


def synthetic_identity(pid: int = 4242) -> ProcessIdentity:
    return ProcessIdentity(
        boot_id="00000000-0000-0000-0000-000000000001",
        pid=pid,
        create_time=float(pid),
        executable="/synthetic/python",
        user="1000",
        user_hash="0" * 64,
    )


def agent(tmp_path: Path, **kwargs: object) -> Agent:
    options: dict[str, object] = dict(
        provider="google-gemini",
        project="MTGA Cardbot",
        role="Search Bot",
        state_dir=tmp_path,
        heartbeat_interval=1,
        _identity_provider=synthetic_identity,
    )
    options.update(kwargs)
    return Agent(**options)  # type: ignore[arg-type]


def payload(instance: Agent) -> dict[str, object]:
    return json.loads(instance.lease_path.read_text(encoding="utf-8"))


@pytest.fixture
def memory_agent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[tuple[Agent, list[dict[str, object]]]]:
    instance = agent(tmp_path)
    leases: list[dict[str, object]] = []

    def publish(agent_id: str, candidate: dict[str, object]) -> bool:
        leases.append(json.loads(json.dumps(candidate)))
        return True

    monkeypatch.setattr(instance._store, "write_lease", publish)
    monkeypatch.setattr(instance, "_start_thread_locked", lambda: None)
    try:
        yield instance, leases
    finally:
        instance.close()


def test_agent_module_star_import_matches_public_api() -> None:
    import zombie_killer.agent as agent_module

    expected = {"Agent", "BudgetExceeded", "BudgetReservation", "SDKError", "register"}
    namespace: dict[str, object] = {}
    exec("from zombie_killer.agent import *", {}, namespace)

    assert set(agent_module.__all__) == expected
    assert set(namespace) == expected


def test_context_registration_status_usage_and_terminal_lease(tmp_path: Path) -> None:
    handlers = {name: signal.getsignal(name) for name in (signal.SIGINT, signal.SIGTERM)}

    with agent(tmp_path) as instance:
        assert instance.started
        assert instance.lease_path.exists()
        instance.status("Searching --api-key synthetic-value")
        instance.record_usage(requests=1, input_tokens=10, output_tokens=2, cost_usd=None)
        running = payload(instance)
        assert running["status"] == "Searching --api-key [REDACTED]"
        assert running["counters"]["requests"] == 1
        assert "cost_usd" not in running["counters"]
        assert running["lifecycle"] == "running"

    terminal = payload(instance)
    assert terminal["lifecycle"] == "completed"
    assert terminal["terminal_at"].endswith("Z")
    assert not instance.started
    assert handlers == {name: signal.getsignal(name) for name in handlers}


def test_status_persistence_redacts_multiline_and_unkeyed_credentials(tmp_path: Path) -> None:
    token = "xoxb-" + "fixture" + "A" * 20
    raw = f'password="fixture first\nfixture second" {token}'

    with agent(tmp_path) as instance:
        instance.status(raw)
        stored = str(payload(instance)["status"])

    assert stored == 'password="[REDACTED]" [REDACTED]'
    assert "fixture first" not in stored
    assert "fixture second" not in stored
    assert token not in stored


def test_register_starts_agent_and_close_is_idempotent(tmp_path: Path) -> None:
    instance = register(
        provider="custom",
        project="Synthetic",
        role="Worker",
        state_dir=tmp_path,
        _identity_provider=synthetic_identity,
    )

    assert instance.started
    instance.close(result="failed")
    instance.close(result="completed")
    instance.start()
    assert not instance.started
    assert payload(instance)["lifecycle"] == "failed"


def test_async_context_marks_exception_failed(tmp_path: Path) -> None:
    instance = agent(tmp_path)

    async def run() -> None:
        with pytest.raises(RuntimeError, match="synthetic"):
            async with instance:
                raise RuntimeError("synthetic application failure")

    asyncio.run(run())

    terminal = payload(instance)
    assert terminal["lifecycle"] == "failed"
    assert "synthetic application failure" not in instance.lease_path.read_text()


def test_async_context_offloads_blocking_start_and_close(tmp_path: Path) -> None:
    instance = agent(tmp_path)
    entered = threading.Event()
    release = threading.Event()
    original_start = instance.start

    def delayed_start() -> Agent:
        entered.set()
        assert release.wait(timeout=2)
        return original_start()

    instance.start = delayed_start  # type: ignore[method-assign]

    async def run() -> None:
        task = asyncio.create_task(instance.__aenter__())
        assert await asyncio.to_thread(entered.wait, 1)
        await asyncio.sleep(0)
        assert not task.done()
        release.set()
        assert await task is instance
        await instance.__aexit__(None, None, None)

    asyncio.run(run())


def test_cancelled_async_entry_closes_registration_before_propagating(
    memory_agent: tuple[Agent, list[dict[str, object]]], monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, leases = memory_agent
    entered = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    original_start = instance.start

    def delayed_start() -> Agent:
        entered.set()
        try:
            assert release.wait(timeout=2)
            return original_start()
        finally:
            finished.set()

    monkeypatch.setattr(instance, "start", delayed_start)

    async def run() -> None:
        task = asyncio.create_task(instance.__aenter__())
        try:
            assert await asyncio.to_thread(entered.wait, 1)
            task.cancel()
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert await asyncio.to_thread(finished.wait, 1)
            assert not instance.started
            assert leases[-1]["lifecycle"] == "cancelled"
            assert leases[-1]["terminal_at"] is not None
        finally:
            release.set()

    asyncio.run(run())


def test_repeated_cancellation_waits_for_async_entry_cleanup(
    memory_agent: tuple[Agent, list[dict[str, object]]], monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, leases = memory_agent
    entered = threading.Event()
    release_start = threading.Event()
    closing = threading.Event()
    release_close = threading.Event()
    original_start = instance.start
    original_close = instance.close

    def delayed_start() -> Agent:
        entered.set()
        assert release_start.wait(timeout=2)
        return original_start()

    def delayed_close(result: str = "completed") -> None:
        closing.set()
        assert release_close.wait(timeout=2)
        original_close(result=result)  # type: ignore[arg-type]

    monkeypatch.setattr(instance, "start", delayed_start)
    monkeypatch.setattr(instance, "close", delayed_close)

    async def run() -> None:
        task = asyncio.create_task(instance.__aenter__())
        try:
            assert await asyncio.to_thread(entered.wait, 1)
            task.cancel()
            release_start.set()
            assert await asyncio.to_thread(closing.wait, 1)
            task.cancel()
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            assert not task.done()
            assert not release_close.is_set()
            release_close.set()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert not instance.started
            assert leases[-1]["lifecycle"] == "cancelled"
        finally:
            release_start.set()
            release_close.set()

    asyncio.run(run())


def test_async_context_marks_task_cancellation_cancelled(
    memory_agent: tuple[Agent, list[dict[str, object]]],
) -> None:
    instance, leases = memory_agent

    async def run() -> None:
        with pytest.raises(asyncio.CancelledError):
            async with instance:
                raise asyncio.CancelledError()

    asyncio.run(run())

    assert not instance.started
    assert leases[-1]["lifecycle"] == "cancelled"


def test_heartbeat_advances_and_cancellation_callback_isolated(tmp_path: Path) -> None:
    calls: list[str] = []
    called = threading.Event()

    def callback() -> None:
        calls.append(threading.current_thread().name)
        called.set()
        raise RuntimeError("callback detail must remain local")

    instance = agent(tmp_path, on_cancel=callback).start()
    first = payload(instance)["heartbeat_at"]
    now = datetime.now(UTC)
    cancellation = {
        "protocol_version": 2,
        "agent_id": instance.agent_id,
        "registration_nonce": instance.registration_nonce,
        "plan_id": "plan-1",
        "request_id": "request-1",
        "target": instance.cancellation_target,
        "requested_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(seconds=30)).isoformat().replace("+00:00", "Z"),
    }
    instance._store.write_cancellation_for_test(instance.agent_id, cancellation)

    assert called.wait(timeout=3)
    assert payload(instance)["heartbeat_at"] != first
    assert instance.cancelled
    assert calls and calls[0].startswith("zombie-killer-")
    assert "callback detail" not in instance.lease_path.read_text()
    instance.close(result="cancelled")


def test_fork_detection_rolls_registration_without_overwriting_parent(tmp_path: Path) -> None:
    identities = [synthetic_identity(4242)]
    instance = agent(tmp_path, _identity_provider=lambda: identities[-1]).start()
    approved = tmp_path / "approved"
    approved.mkdir()
    temporary = approved / "parent.tmp"
    temporary.write_text("synthetic", encoding="utf-8")
    instance.status("parent status")
    instance.record_usage(requests=3, input_tokens=5)
    instance.track_temp(temporary, root=approved)
    parent_id = instance.agent_id
    parent_nonce = instance.registration_nonce
    parent_path = instance.lease_path
    parent_contents = parent_path.read_bytes()

    identities.append(synthetic_identity(4243))
    instance.status("child work")

    assert instance.agent_id != parent_id
    assert instance.registration_nonce != parent_nonce
    assert instance.identity.pid == 4243
    assert parent_path.read_bytes() == parent_contents
    assert instance.lease_path.exists()
    child = payload(instance)
    assert child["resources"] == []
    assert child["counters"]["requests"] == 0
    assert child["counters"]["input_tokens"] == 0
    assert child["status"] == "child work"
    instance.close()


def test_concurrent_status_and_counters_are_atomic(tmp_path: Path) -> None:
    instance = agent(tmp_path).start()

    def update(index: int) -> None:
        instance.status(f"worker {index}")
        instance.record_usage(requests=1, input_tokens=2, output_tokens=1)

    workers = [threading.Thread(target=update, args=(index,)) for index in range(12)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()

    current = payload(instance)
    assert current["counters"]["requests"] == 12
    assert current["counters"]["input_tokens"] == 24
    assert current["counters"]["output_tokens"] == 12
    assert str(current["status"]).startswith("worker ")
    instance.close()


def test_resources_ports_and_bounds(tmp_path: Path) -> None:
    approved = tmp_path / "approved"
    approved.mkdir()
    target = approved / "result.tmp"
    target.write_text("synthetic", encoding="utf-8")
    instance = agent(tmp_path).start()

    instance.track_temp(target, root=approved)
    instance.expect_listening_port(8123)

    current = payload(instance)
    assert len(current["resources"]) == 1
    assert current["resources"][0]["path"] == str(target.resolve())
    assert current["resources"][0]["approved_root"] == str(approved.resolve())
    assert current["resources"][0]["resource_type"] == "file"
    assert current["resources"][0]["creation_fingerprint"]["inode"] == target.stat().st_ino
    assert current["counters"]["expected_loopback_port"] == 8123
    with pytest.raises(ValueError):
        instance.expect_listening_port(0)
    with pytest.raises(ValueError):
        instance.track_temp(Path("relative"), root=approved)
    prior_resources = payload(instance)["resources"]
    overbound = Path("C:\\" + "x" * 4096)
    with pytest.raises(ValueError, match="4096"):
        instance.track_temp(overbound, root=approved)
    with pytest.raises(ValueError, match="4096"):
        instance.track_temp(target, root=overbound)
    assert payload(instance)["resources"] == prior_resources
    instance.close()


def test_parent_and_detached_intent_are_explicit(tmp_path: Path) -> None:
    owner_id = "00000000-0000-4000-8000-000000000099"
    attached = agent(tmp_path / "attached", parent_pid=4000, parent_agent_id=owner_id).start()
    detached = agent(tmp_path / "detached", survive_parent=True).start()
    try:
        attached_payload = payload(attached)
        assert attached_payload["expected_parent_pid"] == 4000
        assert attached_payload["expected_owner"] == owner_id
        assert not attached_payload["detached"]
        detached_payload = payload(detached)
        assert detached_payload["expected_parent_pid"] is None
        assert detached_payload["expected_owner"] is None
        assert detached_payload["detached"]
    finally:
        attached.close()
        detached.close()


def test_budget_blocks_n_plus_one_before_callback(tmp_path: Path) -> None:
    instance = agent(tmp_path, max_requests=2, max_tokens=10).start()
    calls: list[str] = []

    for _ in range(2):
        instance.before_request(lambda: calls.append("network"))

    with pytest.raises(BudgetExceeded) as raised:
        instance.before_request(lambda: calls.append("must-not-run"))

    assert calls == ["network", "network"]
    assert instance.budget_exceeded
    assert "max_requests" in raised.value.reasons
    assert payload(instance)["counters"]["budget_max_requests"] == 1
    instance.close()


def test_budget_reservation_is_atomic_across_concurrent_callbacks(tmp_path: Path) -> None:
    instance = agent(tmp_path, max_requests=1).start()
    entered = threading.Event()
    release = threading.Event()
    calls: list[str] = []

    def network() -> None:
        calls.append("network")
        entered.set()
        assert release.wait(timeout=2)

    worker = threading.Thread(target=lambda: instance.before_request(network))
    worker.start()
    assert entered.wait(timeout=1)
    with pytest.raises(BudgetExceeded):
        instance.before_request(lambda: calls.append("must-not-run"))
    release.set()
    worker.join(timeout=2)

    assert calls == ["network"]
    assert payload(instance)["counters"]["requests"] == 1
    instance.close()


def test_failed_callback_releases_budget_reservation(tmp_path: Path) -> None:
    instance = agent(tmp_path, max_requests=1, max_tokens=4).start()
    reservation = BudgetReservation(requests=1, input_tokens=4)

    def fail() -> None:
        raise RuntimeError("synthetic")

    with pytest.raises(RuntimeError, match="synthetic"):
        instance.before_request(fail, reservation=reservation)
    instance.before_request(lambda: "ok", reservation=reservation)

    counters = payload(instance)["counters"]
    assert counters["requests"] == 1
    assert counters["input_tokens"] == 4
    instance.close()


def test_runtime_reservation_blocks_before_callback(tmp_path: Path) -> None:
    instance = agent(tmp_path, max_runtime_seconds=5).start()
    calls: list[str] = []

    with pytest.raises(BudgetExceeded) as raised:
        instance.before_request(
            lambda: calls.append("network"),
            reservation=BudgetReservation(runtime_seconds=6),
        )

    assert calls == []
    assert "max_runtime_seconds" in raised.value.reasons
    instance.close()


def test_oversized_resource_candidate_is_transactional(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import zombie_killer.agent as agent_module

    instance = agent(tmp_path).start()
    sequence = iter(range(100))

    def synthetic_resource(path: object, *, root: object) -> dict[str, str]:
        index = next(sequence)
        return {"kind": "temporary", "path": f"/{index:02d}-" + "x" * 4080}

    monkeypatch.setattr(agent_module, "validate_temp_resource", synthetic_resource)
    while instance.track_temp("ignored", root="ignored"):
        pass
    prior = payload(instance)

    assert len(prior["resources"]) < 64
    assert instance.track_temp("ignored", root="ignored") is False
    assert payload(instance)["resources"] == prior["resources"]
    assert instance.warning == "LEASE_PAYLOAD_TOO_LARGE"
    instance.close()


def test_strict_oversized_resource_candidate_raises_without_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import zombie_killer.agent as agent_module

    instance = agent(tmp_path, strict=True).start()
    instance._resources = [
        {"kind": "temporary", "path": f"/{index:02d}-" + "x" * 4080} for index in range(31)
    ]
    monkeypatch.setattr(
        agent_module,
        "validate_temp_resource",
        lambda path, *, root: {"kind": "temporary", "path": "/next-" + "x" * 4080},
    )

    before = list(instance._resources)
    with pytest.raises(SDKError):
        instance.track_temp("ignored", root="ignored")
    assert instance._resources == before
    instance._resources.clear()
    instance.close()


def test_unavailable_state_is_quiet_noop_unless_strict(tmp_path: Path) -> None:
    unavailable = tmp_path / "not-a-directory"
    unavailable.write_text("occupied", encoding="utf-8")

    instance = agent(unavailable).start()
    instance.status("local status")
    instance.record_usage(requests=1)
    instance.close()
    assert instance.status_text == "local status"
    assert not instance.available

    with pytest.raises(SDKError):
        agent(unavailable, strict=True).start()


def test_unavailable_process_identity_is_quiet_noop_unless_strict(tmp_path: Path) -> None:
    def denied() -> ProcessIdentity:
        raise OSError("synthetic identity denial")

    instance = agent(tmp_path, _identity_provider=denied).start()
    instance.status("local status")
    instance.close()
    assert instance.status_text == "local status"
    assert not instance.available

    with pytest.raises(SDKError):
        agent(tmp_path / "strict", strict=True, _identity_provider=denied).start()


def test_non_strict_publication_failures_never_escape(tmp_path: Path) -> None:
    instance = agent(tmp_path).start()

    def serialization_failure(agent_id: str, candidate: dict[str, object]) -> bool:
        raise ValueError("synthetic serialization failure")

    instance._store.write_lease = serialization_failure  # type: ignore[method-assign]
    instance.status("still local")
    assert not instance._heartbeat_once()
    instance.close()
    assert instance.status_text == "still local"
    assert instance.warning == "ValueError"


def test_strict_publication_failure_is_safe_sdk_error(tmp_path: Path) -> None:
    instance = agent(tmp_path, strict=True).start()
    original = instance._store.write_lease

    def serialization_failure(agent_id: str, candidate: dict[str, object]) -> bool:
        raise ValueError("synthetic serialization failure")

    instance._store.write_lease = serialization_failure  # type: ignore[method-assign]
    with pytest.raises(SDKError, match="publication failed safely"):
        instance.status("local status remains bounded")
    instance._store.write_lease = original  # type: ignore[method-assign]
    instance.close()


def test_default_path_failure_is_lazy_and_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    import zombie_killer.lease as lease_module

    monkeypatch.setattr(
        lease_module,
        "default_runtime_dir",
        lambda: (_ for _ in ()).throw(OSError("synthetic native path failure")),
    )
    instance = Agent(provider="custom", project="Synthetic", role="Worker")
    instance.start()
    instance.status("local only")
    instance.close()
    assert instance.status_text == "local only"
    assert not instance.available

    strict = Agent(provider="custom", project="Synthetic", role="Worker", strict=True)
    with pytest.raises(SDKError):
        strict.start()


def test_closed_agent_is_collectible(tmp_path: Path) -> None:
    instance = agent(tmp_path).start()
    reference = weakref.ref(instance)
    instance.close()
    del instance
    gc.collect()

    assert reference() is None


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("provider", "Unknown Provider"),
        ("project", " "),
        ("role", "bad\nrole"),
        ("heartbeat_interval", 0),
        ("heartbeat_interval", 301),
        ("agent_id", "not a uuid"),
        ("run_id", "not a uuid"),
    ],
)
def test_constructor_rejects_noncanonical_identifiers(
    tmp_path: Path, field: str, value: object
) -> None:
    kwargs: dict[str, object] = {
        "provider": "custom",
        "project": "Synthetic",
        "role": "Worker",
        "state_dir": tmp_path,
        "_identity_provider": synthetic_identity,
    }
    kwargs[field] = value
    with pytest.raises((TypeError, ValueError)):
        Agent(**kwargs)


def test_repr_is_useful_and_contains_no_registration_secret(tmp_path: Path) -> None:
    instance = agent(
        tmp_path,
        agent_id=str(uuid.UUID("00000000-0000-4000-8000-000000000010")),
        _nonce_factory=lambda: "registration-secret-marker",
    )

    rendered = repr(instance)

    assert "google-gemini" in rendered
    assert "MTGA Cardbot" in rendered
    assert "registration-secret-marker" not in rendered


def test_real_process_identity_is_managed_by_engine_scanner(tmp_path: Path) -> None:
    from zombie_killer_engine.scanner import scan_agents

    instance = Agent(
        provider="custom",
        project="Compatibility",
        role="Scanner Test",
        state_dir=tmp_path,
        heartbeat_interval=1,
    ).start()
    try:
        result = scan_agents(instance._store.leases_dir)
        scanned = next(agent for agent in result.agents if agent.agent_id == instance.agent_id)
        assert scanned.lease_matched
        assert scanned.classification.state.value == "healthy"
    finally:
        instance.close()
