from __future__ import annotations

import inspect
import io
import json
import sqlite3
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote
from uuid import UUID, uuid4

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import ValidationError as PydanticValidationError

from zombie_killer_engine import protocol as protocol_module
from zombie_killer_engine import service as service_module
from zombie_killer_engine.actions import ActionReceipt
from zombie_killer_engine.memory import (
    VaultCapabilities,
    VaultFormat,
    VaultSource,
)
from zombie_killer_engine.paths import AppPaths
from zombie_killer_engine.protocol import (
    MAX_INPUT_FRAME_BYTES,
    MAX_OUTPUT_FRAME_BYTES,
    ProtocolRunner,
    RequestReplayCache,
    handle_frame,
    protocol_once,
    stdio,
)
from zombie_killer_engine.service import (
    PROTOCOL_VERSION,
    RESULT_MODELS,
    VAULT_LOCAL_ONLY_WARNING,
    Capability,
    ClientKind,
    DoctorResult,
    EngineService,
    ErrorBody,
    ErrorCode,
    Method,
    RequestContext,
    RequestEnvelope,
    ResponseEnvelope,
    ServiceFault,
    build_default_service,
)
from zombie_killer_engine.store import ExpiredPlanError, PlanClaimError, SQLiteStateStore

ROOT = Path(__file__).parents[3]


def request(
    method: str,
    payload: dict[str, Any] | None = None,
    *,
    request_id: str | None = None,
    extra: dict[str, Any] | None = None,
) -> bytes:
    envelope = {
        "protocol_version": PROTOCOL_VERSION,
        "request_id": request_id or str(uuid4()),
        "method": method,
        "payload": payload or {},
    }
    envelope.update(extra or {})
    return json.dumps(envelope, separators=(",", ":")).encode()


def decode(frame: bytes) -> dict[str, Any]:
    return json.loads(frame.decode())


def system_info_result(**extra: object) -> dict[str, object]:
    return {
        "engine_version": "0.1.0-alpha.1",
        "protocol_version": PROTOCOL_VERSION,
        "platform": "test",
        "python": "3.12",
        "local_only": True,
        "network_listener": False,
        "memory_warning": "Memory remains local.",
        **extra,
    }


def receipt_result(plan_id: str) -> dict[str, object]:
    return {
        "receipt_id": "receipt-1",
        "plan_id": plan_id,
        "outcome": "completed",
        "certainty": "verified",
        "action_issued": True,
        "partial_failures": [],
        "created_at": "2026-08-12T12:00:00Z",
    }


def partial_action_receipt() -> ActionReceipt:
    sensitive_reason = "".join(("pass", "word=", "fixture-only-value"))
    return ActionReceipt.model_validate_json(
        json.dumps(
            {
                "receipt_id": "receipt-partial",
                "correlation_id": "correlation-partial",
                "plan_id": "plan-partial",
                "actor": "local-user",
                "session_id": "local-session",
                "action": "terminate",
                "target": {
                    "boot_id": "boot-partial",
                    "pid": 4242,
                    "create_time": 1_765_000_000.25,
                    "executable": "[REDACTED]/python",
                    "user": "[CURRENT USER]",
                    "executable_hash": "a" * 64,
                    "user_hash": "b" * 64,
                },
                "before": "running",
                "after": "not_found",
                "result": "completed",
                "action_issued": True,
                "started_at": "2026-08-12T12:00:00Z",
                "finished_at": "2026-08-12T12:00:01Z",
                "partial_failures": [
                    "Cleanup verification failed.",
                    sensitive_reason,
                ],
                "restore_reference": None,
            },
            separators=(",", ":"),
        )
    )


def test_action_and_activity_project_partial_receipt_reasons_without_false_success() -> None:
    receipt = partial_action_receipt()
    projected = service_module._action_receipt_result(receipt)
    service = EngineService(
        handlers={
            Method.ACTION_EXECUTE: lambda _payload, _context: projected,
            Method.ACTIVITY_LIST: lambda _payload, _context: {
                "receipts": [projected],
                "next_cursor": None,
            },
        },
        execution_authorizer=lambda _method, _plan_id, _digest: True,
    )
    execution = RequestContext(
        client=ClientKind.CONTROLLER,
        capability=Capability.EXECUTION,
        local_control=True,
    )
    reading = RequestContext(
        client=ClientKind.CONTROLLER,
        capability=Capability.READ,
        local_control=True,
    )

    action = decode(
        handle_frame(
            request(
                "action.execute",
                {"plan_id": "plan-partial", "digest": "a" * 64},
            ),
            service,
            context=execution,
        )
    )
    activity = decode(handle_frame(request("activity.list"), service, context=reading))

    expected_keys = {
        "receipt_id",
        "plan_id",
        "outcome",
        "certainty",
        "action_issued",
        "partial_failures",
        "created_at",
        "kind",
    }
    for result in (action["result"], activity["result"]["receipts"][0]):
        assert set(result) == expected_keys
        assert result["outcome"] == "completed"
        assert result["certainty"] == "verified"
        assert result["partial_failures"][0] == "Cleanup verification failed."
        assert "fixture-only-value" not in json.dumps(result)


def test_receipt_result_requires_exact_bounded_partial_failures() -> None:
    valid = receipt_result("plan-1")
    model = RESULT_MODELS[Method.ACTION_EXECUTE].model_validate_json(json.dumps(valid))
    assert model.model_dump(mode="json")["partial_failures"] == []

    missing = dict(valid)
    missing.pop("partial_failures")
    with pytest.raises(PydanticValidationError):
        RESULT_MODELS[Method.ACTION_EXECUTE].model_validate_json(json.dumps(missing))

    for invalid_failures in (
        ["bounded"] * 65,
        ["x" * 2_049],
        [""],
    ):
        with pytest.raises(PydanticValidationError):
            RESULT_MODELS[Method.ACTION_EXECUTE].model_validate_json(
                json.dumps({**valid, "partial_failures": invalid_failures})
            )


def plan_result(plan_id: str = "plan-1") -> dict[str, object]:
    return {
        "plan_id": plan_id,
        "digest": "a" * 64,
        "expires_at": "2026-08-12T12:00:30Z",
        "consequences": ["Local change only."],
        "warnings": [],
    }


def action_target() -> dict[str, object]:
    return {"pid": 123, "process_instance_id": "c" * 64}


def action_plan_result(plan_id: str = "plan-1") -> dict[str, object]:
    return {
        **plan_result(plan_id),
        "target": {**action_target(), "state": "stale"},
    }


def vault_result(method: Method) -> dict[str, object]:
    if method in {Method.VAULT_REGISTER, Method.VAULT_PROBE}:
        return {
            "format": "json",
            "recognized": True,
            "capabilities": {
                "readable": True,
                "queryable": True,
                "editable": True,
                "snapshot": True,
                "restore": True,
                "reason": None,
            },
            "reason": None,
            "read_only": True,
            "selected_locally": True,
        }
    if method is Method.VAULT_LIST:
        return {"sources": [], "next_cursor": None}
    if method is Method.VAULT_QUERY:
        return {"records": [], "next_cursor": None, "total": 0}
    if method is Method.VAULT_GET:
        return {
            "record": {
                "record_id": "record-1",
                "namespace": "default",
                "content": "local",
                "metadata": {},
                "embedding_present": False,
                "source_revision": "b" * 64,
            }
        }
    if method in {Method.VAULT_MUTATION_PLAN, Method.VAULT_RESTORE_PLAN}:
        return plan_result()
    if method in {Method.VAULT_MUTATION_EXECUTE, Method.VAULT_RESTORE_EXECUTE}:
        return receipt_result("plan-1")
    if method is Method.VAULT_SNAPSHOT_LIST:
        return {"snapshots": []}
    raise AssertionError(f"missing vault fixture for {method}")


def agent_result() -> dict[str, object]:
    return {
        "agent_id": "agent-1",
        "provider": "local",
        "project": "fixture",
        "role": "worker",
        "state": "healthy",
        "evidence_grade": "confirmed",
        "confidence": 1.0,
        "reason_codes": ["lease_match"],
        "explanation": "The managed lease and process identity match.",
        "evidence": [
            {
                "code": "lease_match",
                "grade": "confirmed",
                "observed_at": "2026-08-12T12:00:00Z",
                "detail": "Managed fixture identity matched.",
            }
        ],
        "actionable": False,
        "managed": True,
        "pid": 123,
        "process_instance_id": "c" * 64,
        "process_name": "fixture",
        "os_status": "running",
        "usage_cost": {
            "availability": "unknown",
            "amount_usd": None,
            "note": "Provider cost is unknown.",
        },
    }


def representative_result(method: Method) -> dict[str, object]:
    if method is Method.SYSTEM_INFO:
        return system_info_result()
    if method is Method.DOCTOR:
        return {"healthy": True, "checks": [{"name": "protocol", "ok": True}], "warnings": []}
    if method is Method.SCAN_LIST:
        return {
            "agents": [],
            "coverage": {
                "inspected_count": 0,
                "denied_count": 0,
                "vanished_count": 0,
                "malformed_lease_count": 0,
                "lease_file_count": 0,
                "skipped_lease_count": 0,
                "other_user_count": 0,
                "unknown_owner_count": 0,
                "identity_denied_count": 0,
                "complete": True,
                "captured_at": "2026-08-12T12:00:00Z",
                "current_boot_id": "boot-1",
                "warnings": [],
            },
            "returned": 0,
            "total": 0,
        }
    if method is Method.AGENT_DETAIL:
        return agent_result()
    if method is Method.ACTION_PLAN:
        return action_plan_result()
    if method in {Method.QUARANTINE_RESTORE_PLAN, Method.QUARANTINE_PLAN}:
        return plan_result()
    if method in {
        Method.ACTION_EXECUTE,
        Method.RECEIPT_GET,
        Method.QUARANTINE_RESTORE_EXECUTE,
        Method.QUARANTINE_EXECUTE,
        Method.DIAGNOSTICS_EXPORT_EXECUTE,
    }:
        return receipt_result("plan-1")
    if method is Method.ACTIVITY_LIST:
        return {"receipts": [], "next_cursor": None}
    if method is Method.QUARANTINE_LIST:
        return {"entries": [], "next_cursor": None}
    if method is Method.QUARANTINE_RESOURCE_LIST:
        return {"agent_id": "fixture-agent", "resources": [], "returned": 0}
    if method.value.startswith("vault."):
        return {**vault_result(method), "local_only_warning": VAULT_LOCAL_ONLY_WARNING}
    if method in {Method.SETTINGS_GET, Method.SETTINGS_UPDATE}:
        return {
            "settings": {
                "scan_interval_seconds": 30,
                "heartbeat_grace_seconds": 120,
                "retention_days": 30,
                "include_unmanaged_candidates": True,
                "appearance": "system",
                "reduced_motion": False,
            },
            "revision": 0,
        }
    if method is Method.DIAGNOSTICS_EXPORT_PLAN:
        return {
            **plan_result(),
            "excluded_by_default": ["command_lines", "memory_contents", "paths", "secrets"],
        }
    raise AssertionError(f"missing result fixture for {method}")


def test_system_info_uses_versioned_success_envelope() -> None:
    response = decode(handle_frame(request("system.info"), EngineService()))

    UUID(response["request_id"])
    assert response["protocol_version"] == PROTOCOL_VERSION
    assert response["method"] == "system.info"
    assert response["ok"] is True
    assert response["result"]["protocol_version"] == PROTOCOL_VERSION
    assert response["error"] is None


@pytest.mark.parametrize(
    ("frame", "code"),
    [
        (b"{", "invalid_request"),
        (b"\xff", "invalid_request"),
        (
            b'{"protocol_version":"bad","request_id":"'
            + str(uuid4()).encode()
            + b'","method":"system.info","payload":{}}',
            "invalid_request",
        ),
        (request("system.info", request_id="not-a-uuid"), "invalid_request"),
        (request("missing.method"), "unsupported"),
        (request("system.info", {"extra": True}), "invalid_request"),
    ],
)
def test_invalid_frames_return_one_bounded_error(frame: bytes, code: str) -> None:
    response_frame = handle_frame(frame, EngineService())
    response = decode(response_frame)

    assert len(response_frame) <= MAX_OUTPUT_FRAME_BYTES
    assert response["ok"] is False
    assert response["error"]["code"] == code
    assert response["result"] is None


def test_duplicate_json_keys_are_rejected() -> None:
    identifier = str(uuid4())
    frame = (
        '{"protocol_version":"1.0","request_id":"'
        + identifier
        + '","method":"system.info","method":"doctor","payload":{}}'
    ).encode()

    response = decode(handle_frame(frame, EngineService()))

    assert response["ok"] is False
    assert response["error"]["code"] == "invalid_request"


def test_oversized_and_deeply_nested_frames_are_rejected() -> None:
    oversized = b"{" + (b" " * MAX_INPUT_FRAME_BYTES)
    nested: object = "leaf"
    for _ in range(40):
        nested = [nested]
    deep = request("system.info").replace(
        b'"payload":{}', b'"payload":' + json.dumps(nested).encode()
    )

    assert decode(handle_frame(oversized, EngineService()))["error"]["code"] == "invalid_request"
    assert decode(handle_frame(deep, EngineService()))["error"]["code"] == "invalid_request"


def test_parser_recursion_limit_is_classified_as_invalid_request() -> None:
    nesting = 10_000
    frame = (
        b'{"protocol_version":"1.0","request_id":"'
        + str(uuid4()).encode()
        + b'","method":"system.info","payload":'
        + (b"[" * nesting)
        + b"0"
        + (b"]" * nesting)
        + b"}"
    )
    assert len(frame) <= MAX_INPUT_FRAME_BYTES

    response = decode(handle_frame(frame, EngineService()))

    assert response["ok"] is False
    assert response["error"]["code"] == "invalid_request"


def test_deep_vault_query_error_preserves_authoritative_correlation() -> None:
    request_id = str(uuid4())
    nested: object = "leaf"
    for _ in range(40):
        nested = [nested]
    frame = request(
        Method.VAULT_QUERY.value,
        {"source_id": "source-1", "filter": nested},
        request_id=request_id,
    )

    response_frame = handle_frame(frame, EngineService())
    response = decode(response_frame)

    assert response["ok"] is False
    assert response["error"]["code"] == "invalid_request"
    assert response["request_id"] == request_id
    assert response["method"] == Method.VAULT_QUERY.value
    ResponseEnvelope.model_validate_json(response_frame)


def test_invalid_envelope_preserves_authoritative_correlation() -> None:
    request_id = str(uuid4())
    frame = request(
        Method.VAULT_QUERY.value,
        {"source_id": "source-1"},
        request_id=request_id,
        extra={"protocol_version": "unsupported"},
    )

    response_frame = handle_frame(frame, EngineService())
    response = decode(response_frame)

    assert response["ok"] is False
    assert response["error"]["code"] == "invalid_request"
    assert response["request_id"] == request_id
    assert response["method"] == Method.VAULT_QUERY.value
    ResponseEnvelope.model_validate_json(response_frame)


def test_multiline_and_trailing_json_are_rejected() -> None:
    valid = request("system.info")

    for frame in (valid + b"\n" + valid, valid + b" {}", valid + b"\r\n{}"):
        response = decode(handle_frame(frame, EngineService()))
        assert response["ok"] is False
        assert response["error"]["code"] == "invalid_request"


def test_stdio_recovers_after_invalid_frame() -> None:
    valid = request("doctor")
    input_stream = io.BytesIO(b"{\n" + valid + b"\n")
    output_stream = io.BytesIO()

    exit_code = stdio(EngineService(), stdin=input_stream, stdout=output_stream)
    responses = [json.loads(line) for line in output_stream.getvalue().splitlines()]

    assert exit_code == 0
    assert [item["ok"] for item in responses] == [False, True]


def test_stdio_handler_keyboard_interrupt_returns_130_and_closes_service() -> None:
    closed: list[bool] = []

    def interrupt(_payload: object, _context: RequestContext) -> object:
        raise KeyboardInterrupt

    service = EngineService(
        handlers={Method.SYSTEM_INFO: interrupt},
        close_callback=lambda: closed.append(True),
    )
    output = io.BytesIO()

    exit_code = stdio(
        service,
        stdin=io.BytesIO(request(Method.SYSTEM_INFO.value) + b"\n"),
        stdout=output,
    )

    assert exit_code == 130
    assert output.getvalue() == b""
    assert closed == [True]


def test_stdio_handler_system_exit_propagates_and_closes_service() -> None:
    closed: list[bool] = []

    def exit_handler(_payload: object, _context: RequestContext) -> object:
        raise SystemExit(17)

    service = EngineService(
        handlers={Method.SYSTEM_INFO: exit_handler},
        close_callback=lambda: closed.append(True),
    )
    output = io.BytesIO()

    with pytest.raises(SystemExit) as captured:
        stdio(
            service,
            stdin=io.BytesIO(request(Method.SYSTEM_INFO.value) + b"\n"),
            stdout=output,
        )

    assert captured.value.code == 17
    assert output.getvalue() == b""
    assert closed == [True]


def test_stdio_applies_frame_cap_after_lf_or_crlf_terminator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"x" * MAX_INPUT_FRAME_BYTES
    observed: list[bytes] = []
    success = handle_frame(request("system.info"), EngineService())

    def fake_handle(frame: bytes, *_args: object, **_kwargs: object) -> bytes:
        observed.append(frame)
        return success

    monkeypatch.setattr(protocol_module, "handle_frame", fake_handle)
    output = io.BytesIO()

    stdio(
        EngineService(),
        stdin=io.BytesIO(payload + b"\n" + payload + b"\r\n"),
        stdout=output,
    )

    assert observed == [payload, payload]


def test_protocol_once_applies_frame_cap_after_crlf_terminator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"x" * MAX_INPUT_FRAME_BYTES
    observed: list[bytes] = []
    success = handle_frame(request("system.info"), EngineService())

    def fake_handle(frame: bytes, *_args: object, **_kwargs: object) -> bytes:
        observed.append(frame)
        return success

    monkeypatch.setattr(protocol_module, "handle_frame", fake_handle)
    accepted_output = io.BytesIO()
    rejected_output = io.BytesIO()

    accepted = protocol_once(
        EngineService(), stdin=io.BytesIO(payload + b"\r\n"), stdout=accepted_output
    )
    rejected = protocol_once(
        EngineService(), stdin=io.BytesIO(payload + b"x\r\n"), stdout=rejected_output
    )

    assert accepted == 0
    assert rejected == 2
    assert observed == [payload]


def test_stdio_rejects_duplicate_request_id_without_reexecution() -> None:
    calls: list[str] = []
    service = EngineService(
        handlers={
            Method.ACTION_EXECUTE: lambda payload, _context: (
                calls.append(payload.plan_id) or receipt_result(payload.plan_id)
            )
        },
        execution_authorizer=lambda _method, _plan_id, _digest: True,
    )
    context = RequestContext(
        client=ClientKind.CONTROLLER,
        capability=Capability.EXECUTION,
        local_control=True,
    )
    frame = request(
        "action.execute",
        {"plan_id": "plan-1", "digest": "a" * 64},
        request_id=str(uuid4()),
    )
    output = io.BytesIO()

    exit_code = stdio(
        service,
        stdin=io.BytesIO(frame + b"\n" + frame + b"\n"),
        stdout=output,
        context=context,
    )
    responses = [json.loads(line) for line in output.getvalue().splitlines()]

    assert exit_code == 0
    assert responses[0]["ok"] is True
    assert responses[1]["error"]["code"] == "conflict"
    assert responses[1]["error"]["details"] == {"reason": "request_id_replay"}
    assert calls == ["plan-1"]


def test_stdio_replay_cache_is_lru_bounded_and_evicts_oldest() -> None:
    cache = RequestReplayCache(max_entries=2, ttl_seconds=60)
    frames = [request("doctor", request_id=str(uuid4())) for _ in range(3)]
    output = io.BytesIO()

    stdio(
        EngineService(),
        stdin=io.BytesIO(b"\n".join([*frames, frames[0]]) + b"\n"),
        stdout=output,
        replay_cache=cache,
    )
    responses = [json.loads(line) for line in output.getvalue().splitlines()]

    assert [item["ok"] for item in responses] == [True, True, True, True]
    assert len(cache) == 2


def test_stdio_replay_cache_expires_ids_after_ttl() -> None:
    now = [100.0]
    cache = RequestReplayCache(
        max_entries=8,
        ttl_seconds=10,
        clock=lambda: now[0],
    )
    frame = request("doctor", request_id=str(uuid4()))
    first_output = io.BytesIO()
    stdio(
        EngineService(),
        stdin=io.BytesIO(frame + b"\n" + frame + b"\n"),
        stdout=first_output,
        replay_cache=cache,
    )
    now[0] = 111.0
    expired_output = io.BytesIO()
    stdio(
        EngineService(),
        stdin=io.BytesIO(frame + b"\n"),
        stdout=expired_output,
        replay_cache=cache,
    )

    first = [json.loads(line) for line in first_output.getvalue().splitlines()]
    expired = json.loads(expired_output.getvalue())
    assert [item["ok"] for item in first] == [True, False]
    assert expired["ok"] is True


def test_protocol_once_does_not_share_request_id_state() -> None:
    frame = request("doctor", request_id=str(uuid4()))
    outputs = [io.BytesIO(), io.BytesIO()]

    exits = [
        protocol_once(
            EngineService(),
            stdin=io.BytesIO(frame + b"\n"),
            stdout=output,
        )
        for output in outputs
    ]

    assert exits == [0, 0]
    assert all(json.loads(output.getvalue())["ok"] for output in outputs)


def test_protocol_once_accepts_one_frame_and_rejects_smuggling() -> None:
    valid = request("doctor")
    one_output = io.BytesIO()
    extra_output = io.BytesIO()

    one_exit = protocol_once(EngineService(), stdin=io.BytesIO(valid + b"\n"), stdout=one_output)
    extra_exit = protocol_once(
        EngineService(), stdin=io.BytesIO(valid + b"\n" + valid + b"\n"), stdout=extra_output
    )

    assert one_exit == 0
    assert decode(one_output.getvalue().strip())["ok"] is True
    assert extra_exit == 2
    assert decode(extra_output.getvalue().strip())["ok"] is False


def test_output_limit_returns_error_instead_of_large_result() -> None:
    service = EngineService(
        handlers={
            Method.SYSTEM_INFO: lambda _payload, _context: {"value": "x" * MAX_OUTPUT_FRAME_BYTES}
        }
    )

    response_frame = handle_frame(request("system.info"), service)
    response = decode(response_frame)

    assert len(response_frame) <= MAX_OUTPUT_FRAME_BYTES
    assert response["ok"] is False
    assert response["error"]["code"] == "partial"


def test_oversized_valid_vault_query_result_preserves_authoritative_correlation() -> None:
    request_id = str(uuid4())
    record = {
        "record_id": "record-1",
        "namespace": "default",
        "content": "x" * 65_536,
        "metadata": {},
        "embedding_present": False,
        "source_revision": "a" * 64,
    }
    service = EngineService(
        handlers={
            Method.VAULT_QUERY: lambda _payload, _context: {
                "records": [record] * 65,
                "next_cursor": None,
                "total": 65,
            }
        }
    )

    response_frame = handle_frame(
        request(
            Method.VAULT_QUERY.value,
            {"source_id": "source-1"},
            request_id=request_id,
        ),
        service,
    )
    response = decode(response_frame)

    assert len(response_frame) <= MAX_OUTPUT_FRAME_BYTES
    assert response["ok"] is False
    assert response["error"]["code"] == "partial"
    assert response["request_id"] == request_id
    assert response["method"] == Method.VAULT_QUERY.value
    ResponseEnvelope.model_validate_json(response_frame)


def test_exact_output_cap_reserves_the_rust_wire_delimiter() -> None:
    request_id = "11111111-1111-4111-8111-111111111111"
    full_record = {
        "record_id": "record-1",
        "namespace": "default",
        "content": "x" * 65_536,
        "metadata": {},
        "embedding_present": False,
        "source_revision": "a" * 64,
    }
    # The default editable_fields array contributes 21 bytes per record.
    final_record = {**full_record, "content": "x" * 52_011}
    query_result = {
        "records": [full_record] * 63 + [final_record],
        "next_cursor": None,
        "total": 64,
    }
    validated_result = RESULT_MODELS[Method.VAULT_QUERY].model_validate_json(
        json.dumps(
            {**query_result, "local_only_warning": VAULT_LOCAL_ONLY_WARNING},
            separators=(",", ":"),
        )
    )
    exact_response = ResponseEnvelope(
        request_id=UUID(request_id),
        method=Method.VAULT_QUERY,
        ok=True,
        result=validated_result,
        error=None,
    )
    exact_body = json.dumps(
        exact_response.model_dump(mode="json"),
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    assert len(exact_body) == MAX_OUTPUT_FRAME_BYTES

    service = EngineService(handlers={Method.VAULT_QUERY: lambda _payload, _context: query_result})
    output = io.BytesIO()

    exit_code = protocol_once(
        service,
        stdin=io.BytesIO(
            request(
                Method.VAULT_QUERY.value,
                {"source_id": "source-1"},
                request_id=request_id,
            )
        ),
        stdout=output,
    )
    wire_response = output.getvalue()
    response = decode(wire_response.rstrip(b"\n"))

    assert len(wire_response) <= MAX_OUTPUT_FRAME_BYTES
    assert exit_code == 2
    assert response["error"]["code"] == "partial"
    assert response["request_id"] == request_id
    assert response["method"] == Method.VAULT_QUERY.value


def test_mutating_handler_never_outlives_its_response() -> None:
    mutations: list[str] = []

    def slow(payload: object, _context: RequestContext) -> dict[str, object]:
        time.sleep(0.05)
        mutations.append("issued")
        return receipt_result(payload.plan_id)

    service = EngineService(
        handlers={Method.ACTION_EXECUTE: slow},
        execution_authorizer=lambda _method, _plan_id, _digest: True,
    )
    context = RequestContext(
        client=ClientKind.CONTROLLER,
        capability=Capability.EXECUTION,
        local_control=True,
    )

    response = decode(
        handle_frame(
            request("action.execute", {"plan_id": "plan-1", "digest": "a" * 64}),
            service,
            context=context,
        )
    )

    assert response["ok"] is True
    assert mutations == ["issued"]
    time.sleep(0.06)
    assert mutations == ["issued"]


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (ValueError("bad secret=synthetic-fault-fixture"), "invalid_request"),
        (KeyError("private path C:/secret"), "not_found"),
        (FileNotFoundError("C:/private/vault"), "not_found"),
        (PlanClaimError("already used"), "conflict"),
        (PermissionError("username"), "permission_denied"),
        (ExpiredPlanError("expired"), "expired"),
        (NotImplementedError("provider token"), "unsupported"),
        (RuntimeError("traceback password"), "internal"),
    ],
)
def test_domain_errors_map_to_stable_redacted_codes(error: Exception, code: str) -> None:
    def failing(_payload: object, _context: RequestContext) -> dict[str, bool]:
        raise error

    service = EngineService(handlers={Method.SYSTEM_INFO: failing})

    encoded = handle_frame(request("system.info"), service).decode()
    response = json.loads(encoded)

    assert response["error"]["code"] == code
    assert "secret" not in encoded.casefold()
    assert "password" not in encoded.casefold()
    assert "traceback" not in encoded.casefold()
    assert "C:/" not in encoded


def test_explicit_service_fault_keeps_only_bounded_safe_details() -> None:
    def failing(_payload: object, _context: RequestContext) -> dict[str, bool]:
        raise ServiceFault(
            ErrorCode.TARGET_CHANGED,
            "Target identity changed.",
            details={"field": "process_identity"},
        )

    response = decode(
        handle_frame(request("system.info"), EngineService(handlers={Method.SYSTEM_INFO: failing}))
    )

    assert response["error"] == {
        "code": "target_changed",
        "message": "Target identity changed.",
        "retryable": False,
        "details": {"field": "process_identity"},
    }


def test_explicit_fault_cannot_leak_secret_path_or_internal_detail() -> None:
    def failing(_payload: object, _context: RequestContext) -> dict[str, bool]:
        raise ServiceFault(
            ErrorCode.INTERNAL,
            "password=hunter2 at C:/private/vault",
            details={"api_key": "top-secret", "path": "C:/private/vault"},
        )

    encoded = handle_frame(
        request("system.info"), EngineService(handlers={Method.SYSTEM_INFO: failing})
    ).decode()
    response = json.loads(encoded)

    assert response["error"]["code"] == "internal"
    assert set(response["error"]["details"]) == {"correlation_id"}
    assert "hunter2" not in encoded
    assert "top-secret" not in encoded
    assert "C:/" not in encoded


def test_handler_result_filters_secret_and_raw_path_fields() -> None:
    service = EngineService(
        handlers={
            Method.SYSTEM_INFO: lambda _payload, _context: {
                **system_info_result(),
                "access_token": "do-not-return",
                "executable": "C:/private/agent.exe",
            }
        }
    )

    encoded = handle_frame(request("system.info"), service).decode()
    result = json.loads(encoded)["result"]

    assert result == system_info_result()
    assert "do-not-return" not in encoded
    assert "C:/" not in encoded


def test_success_display_fields_redact_tokens_credentials_and_private_paths() -> None:
    service = EngineService(
        handlers={
            Method.SYSTEM_INFO: lambda _payload, _context: system_info_result(
                platform="Bearer synthetic-secret-value",
                memory_warning="See C:/Users/private/vault.json api_key=hidden-value",
            )
        }
    )

    encoded = handle_frame(request("system.info"), service).decode()

    assert "synthetic-secret-value" not in encoded
    assert "hidden-value" not in encoded
    assert "C:/Users/private" not in encoded
    assert "[LOCAL PATH]" in encoded


def test_error_detail_keys_and_values_are_sanitized() -> None:
    def failing(_payload: object, _context: RequestContext) -> object:
        raise ServiceFault(
            ErrorCode.CONFLICT,
            "Conflict at C:/Users/private/state.db bearer hidden-token",
            details={
                "api_key": "named-secret",
                "api_key=SUPERSECRET": "composite-secret",
                "Bearer eyJhbGciOiJIUzI1NiJ9.payload.signaturefixture": "bearer-key-secret",
                "C:/Users/private/secret.txt": "path-key-secret",
                "location": "C:/Users/private/state.db",
                "note": "Authorization: Bearer synthetic-other-secret",
            },
        )

    response = decode(
        handle_frame(
            request(
                "action.plan",
                {
                    "agent_id": "agent-1",
                    "mode": "terminate",
                    "target": action_target(),
                },
            ),
            EngineService(handlers={Method.ACTION_PLAN: failing}),
            context=RequestContext(
                client=ClientKind.CONTROLLER,
                capability=Capability.PLANNING,
                local_control=True,
            ),
        )
    )
    encoded = json.dumps(response)

    assert "api_key" not in encoded
    assert "SUPERSECRET" not in encoded
    assert "eyJhbGciOiJIUzI1NiJ9" not in encoded
    assert "composite-secret" not in encoded
    assert "bearer-key-secret" not in encoded
    assert "path-key-secret" not in encoded
    assert "named-secret" not in encoded
    assert "hidden-token" not in encoded
    assert "other-secret" not in encoded
    assert "C:/Users/private" not in encoded
    assert "[LOCAL PATH]" in encoded


def test_error_body_sanitizes_untrusted_detail_keys_directly() -> None:
    error = ErrorBody(
        code=ErrorCode.CONFLICT,
        message="Conflict",
        details={
            "api_key=SUPERSECRET": "secret-value",
            "field": "Authorization: Bearer hidden-value",
        },
    )
    encoded = error.model_dump_json()

    assert "SUPERSECRET" not in encoded
    assert "secret-value" not in encoded
    assert "hidden-value" not in encoded
    assert set(error.details) == {"redacted_detail_1", "field"}

    schema = json.loads(
        (ROOT / "packages/protocol/schema/protocol.schema.json").read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema["$defs"]["error"])
    validator.validate(error.model_dump(mode="json"))
    unsafe = error.model_dump(mode="json")
    unsafe["details"] = {"api_key=SUPERSECRET": "secret-value"}
    with pytest.raises(JsonSchemaValidationError):
        validator.validate(unsafe)


def test_explicit_vault_record_content_is_not_display_redacted() -> None:
    content = "Bearer synthetic-user-authored-text at C:/fictional/path"
    service = EngineService(
        handlers={
            Method.VAULT_GET: lambda _payload, _context: {
                "record": {
                    "record_id": "record-1",
                    "namespace": "default",
                    "content": content,
                    "metadata": {},
                    "embedding_present": False,
                    "source_revision": "b" * 64,
                }
            }
        }
    )

    response = decode(
        handle_frame(
            request("vault.get", {"source_id": "source-1", "record_id": "record-1"}),
            service,
        )
    )

    assert response["result"]["record"]["content"] == content


def test_explicit_vault_query_record_content_is_not_display_redacted() -> None:
    content = "Bearer synthetic-user-authored-text at C:/fictional/path"
    service = EngineService(
        handlers={
            Method.VAULT_QUERY: lambda _payload, _context: {
                "records": [
                    {
                        "record_id": "record-1",
                        "namespace": "default",
                        "content": content,
                        "metadata": {},
                        "embedding_present": False,
                        "source_revision": "b" * 64,
                    }
                ],
                "next_cursor": None,
                "total": 1,
            }
        }
    )

    response = decode(
        handle_frame(
            request("vault.query", {"source_id": "source-1", "text": "fixture"}),
            service,
        )
    )

    assert response["result"]["records"][0]["content"] == content


def test_vault_metadata_sanitizes_dynamic_secret_keys_without_collisions() -> None:
    token = "sk-" + "A" * 24
    encoded_token = token.replace("-", "%2D")
    overdepth_token = token.replace("-", "%25252D")
    encoded_url = quote(
        "https://fixture-user:fixture-pass@example.invalid/safe",
        safe="",
    )
    service = EngineService(
        handlers={
            Method.VAULT_GET: lambda _payload, _context: {
                "record": {
                    "record_id": "record-1",
                    "namespace": "default",
                    "content": "user-authored content remains explicit",
                    "metadata": {
                        "api_key=fixture-key-in-name": "safe-one",
                        "[REDACTED_KEY_1]": "safe-two",
                        "nested": {
                            "credential=fixture-nested-key": "safe-three",
                            "content": "credential=fixture-metadata-value",
                        },
                        f"prefix_{token}_suffix": "safe-four",
                        (
                            "prefix_https://fixture-user:fixture-pass@example.invalid_suffix"
                        ): "safe-five",
                        f"prefix_{encoded_token}_suffix": "safe-six",
                        f"prefix_{encoded_url}_suffix": "safe-seven",
                        f"prefix_{overdepth_token}_suffix": "safe-eight",
                    },
                    "embedding_present": False,
                    "source_revision": "b" * 64,
                }
            }
        }
    )

    response = decode(
        handle_frame(
            request("vault.get", {"source_id": "source-1", "record_id": "record-1"}),
            service,
        )
    )
    metadata = response["result"]["record"]["metadata"]
    encoded = json.dumps(metadata)

    assert "fixture-key-in-name" not in encoded
    assert "fixture-nested-key" not in encoded
    assert "fixture-metadata-value" not in encoded
    assert "sk-" not in encoded
    assert "fixture-user" not in encoded
    assert "%2D" not in encoded
    assert "%3A" not in encoded
    assert "%2525" not in encoded
    assert metadata["[REDACTED_KEY_1]"] == "safe-two"
    assert metadata["[REDACTED_KEY_1_1]"] == "safe-one"
    assert metadata["nested"] == {
        "[REDACTED_KEY_1]": "safe-three",
        "content": "credential=[REDACTED]",
    }
    assert metadata["[REDACTED_KEY_4]"] == "safe-four"
    assert metadata["[REDACTED_KEY_5]"] == "safe-five"
    assert metadata["[REDACTED_KEY_6]"] == "safe-six"
    assert metadata["[REDACTED_KEY_7]"] == "safe-seven"
    assert metadata["[REDACTED_KEY_8]"] == "safe-eight"


def test_safe_result_rejects_cyclic_sequences_with_bounded_work() -> None:
    cycle: list[object] = []
    cycle.extend((cycle, cycle))

    with pytest.raises(ServiceFault, match="cyclic collection"):
        service_module._safe_result(cycle, method=Method.SYSTEM_INFO)


def test_request_cannot_supply_or_promote_its_authorization_context() -> None:
    service = EngineService(
        handlers={
            Method.ACTION_PLAN: lambda _payload, _context: {"plan_id": "plan", "digest": "a" * 64},
            Method.ACTION_EXECUTE: lambda _payload, _context: {"receipt_id": "receipt"},
        },
        execution_authorizer=lambda _method, _plan_id, _digest: True,
    )
    promoted = request(
        "action.execute",
        {"plan_id": "plan", "digest": "a" * 64},
        extra={
            "context": {
                "client": "controller",
                "capability": "execution",
                "local_control": True,
            }
        },
    )
    runner = ProtocolRunner(
        service,
        context=RequestContext(
            client=ClientKind.CONTROLLER,
            capability=Capability.READ,
            local_control=False,
        ),
    )

    response = decode(runner.handle_frame(promoted))

    assert response["error"]["code"] == "invalid_request"


def test_same_request_cannot_self_promote_between_trusted_launch_modes() -> None:
    calls: list[str] = []
    service = EngineService(
        handlers={
            Method.ACTION_EXECUTE: lambda payload, _context: (
                calls.append(payload.plan_id) or {"receipt_id": "receipt"}
            )
        },
        execution_authorizer=lambda _method, _plan_id, _digest: True,
    )
    frame = request("action.execute", {"plan_id": "plan", "digest": "a" * 64})
    read_runner = ProtocolRunner(
        service,
        context=RequestContext(
            client=ClientKind.CONTROLLER,
            capability=Capability.READ,
            local_control=False,
        ),
    )
    sdk_runner = ProtocolRunner(
        service,
        context=RequestContext(
            client=ClientKind.SDK,
            capability=Capability.EXECUTION,
            local_control=True,
        ),
    )

    read_response = decode(read_runner.handle_frame(frame))
    sdk_response = decode(sdk_runner.handle_frame(frame))

    assert read_response["error"]["code"] == "permission_denied"
    assert sdk_response["error"]["code"] == "permission_denied"
    assert calls == []


@pytest.mark.parametrize(
    "frame",
    [request("system.info"), b"not-json"],
    ids=["normal", "error"],
)
def test_protocol_once_closes_service_on_every_return_path(frame: bytes) -> None:
    assert "close_callback" in inspect.signature(EngineService).parameters
    closed: list[bool] = []
    service = EngineService(close_callback=lambda: closed.append(True))

    protocol_once(service, stdin=io.BytesIO(frame), stdout=io.BytesIO())

    assert closed == [True]


def test_repeated_protocol_once_calls_leave_no_memory_sessions(tmp_path: Path) -> None:
    paths = AppPaths(
        data_dir=tmp_path / "data",
        state_dir=tmp_path / "state",
        runtime_dir=tmp_path / "runtime",
        backups_dir=tmp_path / "backups",
        graveyard_dir=tmp_path / "graveyard",
    )

    for _index in range(25):
        service = build_default_service(paths=paths)
        output = io.BytesIO()
        assert (
            protocol_once(
                service,
                stdin=io.BytesIO(request("system.info")),
                stdout=output,
            )
            == 0
        )

    with sqlite3.connect(paths.state_dir / "zombie-killer.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM memory_sessions").fetchone()[0] == 0


def test_default_service_initialization_failure_unregisters_memory_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
) -> None:
    paths = AppPaths(
        data_dir=tmp_path / "data",
        state_dir=tmp_path / "state",
        runtime_dir=tmp_path / "runtime",
        backups_dir=tmp_path / "backups",
        graveyard_dir=tmp_path / "graveyard",
    )
    store = SQLiteStateStore(paths)
    initialize = store.initialize

    def fail_after_registration() -> None:
        initialize()
        raise RuntimeError("synthetic post-registration initialization failure")

    monkeypatch.setattr(store, "initialize", fail_after_registration)
    monkeypatch.setattr(service_module, "SQLiteStateStore", lambda _paths: store)
    request.addfinalizer(store.close)

    with pytest.raises(RuntimeError, match="post-registration"):
        build_default_service(paths=paths)

    assert store._memory_session_finalizer.alive is False
    with sqlite3.connect(store.database_path) as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM memory_sessions WHERE session_nonce = ?",
                (store._memory_session_nonce,),
            ).fetchone()[0]
            == 0
        )


def test_final_database_security_failure_unregisters_committed_memory_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailFinalDatabaseSecurity:
        def __init__(self) -> None:
            self.secure_calls = 0

        def prepare_state_directory(self, path: Path) -> None:
            path.mkdir(parents=True, exist_ok=True)

        def secure_database(self, _path: Path, *, allow_missing: bool) -> None:
            self.secure_calls += 1
            if self.secure_calls == 3 and not allow_missing:
                raise PermissionError("synthetic final database security failure")

    paths = AppPaths(
        data_dir=tmp_path / "data",
        state_dir=tmp_path / "state",
        runtime_dir=tmp_path / "runtime",
        backups_dir=tmp_path / "backups",
        graveyard_dir=tmp_path / "graveyard",
    )
    backend = FailFinalDatabaseSecurity()
    store = SQLiteStateStore(paths, security_backend=backend)
    monkeypatch.setattr(service_module, "SQLiteStateStore", lambda _paths: store)

    with pytest.raises(PermissionError, match="final database security"):
        build_default_service(paths=paths)

    assert store._memory_session_finalizer.alive is False
    with sqlite3.connect(store.database_path) as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM memory_sessions WHERE session_nonce = ?",
                (store._memory_session_nonce,),
            ).fetchone()[0]
            == 0
        )


def test_activity_list_paginates_beyond_five_hundred(tmp_path: Path) -> None:
    paths = AppPaths(
        data_dir=tmp_path / "data",
        state_dir=tmp_path / "state",
        runtime_dir=tmp_path / "runtime",
        backups_dir=tmp_path / "backups",
        graveyard_dir=tmp_path / "graveyard",
    )
    service = build_default_service(paths=paths)
    try:
        with sqlite3.connect(paths.state_dir / "zombie-killer.sqlite3") as connection:
            rows = []
            for index in range(501):
                created_at = f"2026-08-12T12:{index // 60:02d}:{index % 60:02d}+00:00"
                receipt_id = f"receipt-{index:04d}"
                plan_id = f"plan-{index:04d}"
                body = {
                    "receipt_id": receipt_id,
                    "correlation_id": f"correlation-{index:04d}",
                    "plan_id": plan_id,
                    "actor": "synthetic-actor",
                    "session_id": "synthetic-session",
                    "action": "terminate",
                    "target": {
                        "boot_id": "synthetic-boot",
                        "pid": 4242,
                        "create_time": 1_765_000_000.25,
                        "executable": "[REDACTED]/python",
                        "user": "[CURRENT USER]",
                        "executable_hash": "a" * 64,
                        "user_hash": "b" * 64,
                    },
                    "before": "running",
                    "after": "not_found",
                    "result": "completed",
                    "action_issued": True,
                    "started_at": created_at,
                    "finished_at": created_at,
                    "partial_failures": [],
                    "restore_reference": None,
                }
                rows.append(
                    (
                        receipt_id,
                        plan_id,
                        body["correlation_id"],
                        json.dumps(body, separators=(",", ":")),
                        created_at,
                    )
                )
            connection.executemany(
                "INSERT INTO receipts("
                "receipt_id, plan_id, correlation_id, receipt_json, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                rows,
            )
        context = RequestContext(
            client=ClientKind.CONTROLLER,
            capability=Capability.READ,
            local_control=True,
        )

        first = service.dispatch(
            RequestEnvelope(
                protocol_version=PROTOCOL_VERSION,
                request_id=uuid4(),
                method=Method.ACTIVITY_LIST.value,
                payload={"limit": 500},
            ),
            context=context,
        )
        assert first.ok is True
        assert first.result is not None
        first_page = first.result.model_dump(mode="json")
        assert len(first_page["receipts"]) == 500
        assert first_page["next_cursor"] is not None

        second = service.dispatch(
            RequestEnvelope(
                protocol_version=PROTOCOL_VERSION,
                request_id=uuid4(),
                method=Method.ACTIVITY_LIST.value,
                payload={"limit": 500, "cursor": first_page["next_cursor"]},
            ),
            context=context,
        )
        assert second.ok is True
        assert second.result is not None
        second_page = second.result.model_dump(mode="json")
        assert len(second_page["receipts"]) == 1
        assert second_page["next_cursor"] is None
        first_ids = {receipt["receipt_id"] for receipt in first_page["receipts"]}
        second_ids = {receipt["receipt_id"] for receipt in second_page["receipts"]}
        assert first_ids.isdisjoint(second_ids)
        assert len(first_ids | second_ids) == 501
    finally:
        service.close()


def test_vault_query_cursor_is_bound_to_query_and_source(tmp_path: Path) -> None:
    paths = AppPaths(
        data_dir=tmp_path / "data",
        state_dir=tmp_path / "state",
        runtime_dir=tmp_path / "runtime",
        backups_dir=tmp_path / "backups",
        graveyard_dir=tmp_path / "graveyard",
    )
    source_a = tmp_path / "source-a.json"
    source_b = tmp_path / "source-b.json"
    records = [{"id": f"record-{index:02d}", "content": "needle"} for index in range(30)]
    source_a.write_text(json.dumps(records), encoding="utf-8")
    source_b.write_text(json.dumps(records), encoding="utf-8")
    service = build_default_service(paths=paths)
    try:
        planning = RequestContext(
            client=ClientKind.CONTROLLER, capability=Capability.PLANNING, local_control=True
        )
        reading = RequestContext(
            client=ClientKind.CONTROLLER, capability=Capability.READ, local_control=True
        )
        for source in (source_a, source_b):
            registered = service.dispatch(
                RequestEnvelope(
                    protocol_version=PROTOCOL_VERSION,
                    request_id=uuid4(),
                    method="vault.register",
                    payload={"path": str(source)},
                ),
                context=planning,
            )
            assert registered.ok is True
        listed_response = service.dispatch(
            RequestEnvelope(
                protocol_version=PROTOCOL_VERSION,
                request_id=uuid4(),
                method="vault.list",
                payload={"limit": 500},
            ),
            context=reading,
        )
        assert listed_response.ok is True and listed_response.result is not None
        listed = listed_response.result.model_dump(mode="json")
        source_ids = [item["source_id"] for item in listed["sources"]]
        source_a_id = next(item for item in source_ids if item != source_ids[0])
        source_b_id = source_ids[0]

        def query(payload: dict[str, object]):
            return service.dispatch(
                RequestEnvelope(
                    protocol_version=PROTOCOL_VERSION,
                    request_id=uuid4(),
                    method="vault.query",
                    payload=payload,
                ),
                context=reading,
            )

        first_response = query({"source_id": source_a_id, "text": "needle", "limit": 25})
        assert first_response.ok is True and first_response.result is not None
        first = first_response.result.model_dump(mode="json")
        assert len(first["records"]) == 25
        cursor = first["next_cursor"]
        assert isinstance(cursor, str)

        cursor_parts = cursor.split(".")
        tampered_offset = ".".join((cursor_parts[0], "0", cursor_parts[2]))
        tampered = query(
            {
                "source_id": source_a_id,
                "text": "needle",
                "limit": 25,
                "cursor": tampered_offset,
            }
        )
        assert tampered.ok is False
        assert tampered.error is not None and tampered.error.code is ErrorCode.CONFLICT

        second_response = query(
            {"source_id": source_a_id, "text": "needle", "limit": 25, "cursor": cursor}
        )
        assert second_response.ok is True and second_response.result is not None
        second = second_response.result.model_dump(mode="json")
        assert len(second["records"]) == 5
        assert second["next_cursor"] is None

        changed_filter = query(
            {"source_id": source_a_id, "text": "need", "limit": 25, "cursor": cursor}
        )
        assert changed_filter.ok is False
        assert changed_filter.error is not None and changed_filter.error.code is ErrorCode.CONFLICT

        changed_namespace = query(
            {
                "source_id": source_a_id,
                "namespace": "default",
                "text": "needle",
                "limit": 25,
                "cursor": cursor,
            }
        )
        assert changed_namespace.ok is False
        assert (
            changed_namespace.error is not None
            and changed_namespace.error.code is ErrorCode.CONFLICT
        )

        changed_limit = query(
            {"source_id": source_a_id, "text": "needle", "limit": 10, "cursor": cursor}
        )
        assert changed_limit.ok is False
        assert changed_limit.error is not None and changed_limit.error.code is ErrorCode.CONFLICT

        source_a.write_text(
            json.dumps(records + [{"id": "record-30", "content": "needle"}]), encoding="utf-8"
        )
        changed = query({"source_id": source_a_id, "text": "needle", "limit": 25, "cursor": cursor})
        assert changed.ok is False
        assert changed.error is not None and changed.error.code is ErrorCode.CONFLICT

        stale = query({"source_id": source_b_id, "text": "needle", "limit": 25, "cursor": cursor})
        assert stale.ok is False
        assert stale.error is not None and stale.error.code is ErrorCode.CONFLICT
    finally:
        service.close()


def test_vault_query_cursor_survives_one_request_sidecar_restart(tmp_path: Path) -> None:
    paths = AppPaths(
        data_dir=tmp_path / "data",
        state_dir=tmp_path / "state",
        runtime_dir=tmp_path / "runtime",
        backups_dir=tmp_path / "backups",
        graveyard_dir=tmp_path / "graveyard",
    )
    source = tmp_path / "restart-source.json"
    source.write_text(
        json.dumps([{"id": f"record-{index:02d}", "content": "needle"} for index in range(30)]),
        encoding="utf-8",
    )
    planning = RequestContext(
        client=ClientKind.CONTROLLER,
        capability=Capability.PLANNING,
        local_control=True,
    )
    reading = RequestContext(
        client=ClientKind.CONTROLLER,
        capability=Capability.READ,
        local_control=True,
    )

    first_service = build_default_service(paths=paths)
    try:
        registered = first_service.dispatch(
            RequestEnvelope(
                protocol_version=PROTOCOL_VERSION,
                request_id=uuid4(),
                method="vault.register",
                payload={"path": str(source)},
            ),
            context=planning,
        )
        assert registered.ok is True
        listed = first_service.dispatch(
            RequestEnvelope(
                protocol_version=PROTOCOL_VERSION,
                request_id=uuid4(),
                method="vault.list",
                payload={"limit": 500},
            ),
            context=reading,
        )
        assert listed.ok is True and listed.result is not None
        source_id = listed.result.sources[0].source_id
        first = first_service.dispatch(
            RequestEnvelope(
                protocol_version=PROTOCOL_VERSION,
                request_id=uuid4(),
                method="vault.query",
                payload={"source_id": source_id, "text": "needle", "limit": 25},
            ),
            context=reading,
        )
        assert first.ok is True and first.result is not None
        cursor = first.result.next_cursor
        assert isinstance(cursor, str)
    finally:
        first_service.close()

    second_service = build_default_service(paths=paths)
    try:
        second = second_service.dispatch(
            RequestEnvelope(
                protocol_version=PROTOCOL_VERSION,
                request_id=uuid4(),
                method="vault.query",
                payload={
                    "source_id": source_id,
                    "text": "needle",
                    "limit": 25,
                    "cursor": cursor,
                },
            ),
            context=reading,
        )
        assert second.ok is True and second.result is not None
        assert len(second.result.records) == 5
        assert second.result.next_cursor is None
    finally:
        second_service.close()


def test_vault_list_paginates_beyond_five_hundred_across_sidecar_restarts(
    tmp_path: Path,
) -> None:
    paths = AppPaths(
        data_dir=tmp_path / "data",
        state_dir=tmp_path / "state",
        runtime_dir=tmp_path / "runtime",
        backups_dir=tmp_path / "backups",
        graveyard_dir=tmp_path / "graveyard",
    )
    store = SQLiteStateStore(paths)
    try:
        store.initialize()
        for index in range(501):
            store.register_vault_source(
                VaultSource(
                    source_id=f"source-{index:04d}",
                    path=str(tmp_path / f"source-{index:04d}.json"),
                    format=VaultFormat.JSON,
                    capabilities=VaultCapabilities(readable=True),
                    revision=f"{index:064x}",
                )
            )
    finally:
        store.close()

    reading = RequestContext(
        client=ClientKind.CONTROLLER,
        capability=Capability.READ,
        local_control=True,
    )

    first_service = build_default_service(paths=paths)
    try:
        first = first_service.dispatch(
            RequestEnvelope(
                protocol_version=PROTOCOL_VERSION,
                request_id=uuid4(),
                method="vault.list",
                payload={"limit": 500},
            ),
            context=reading,
        )
        assert first.ok is True and first.result is not None
        assert len(first.result.sources) == 500
        cursor = first.result.next_cursor
        assert isinstance(cursor, str)
    finally:
        first_service.close()

    second_service = build_default_service(paths=paths)
    try:
        second = second_service.dispatch(
            RequestEnvelope(
                protocol_version=PROTOCOL_VERSION,
                request_id=uuid4(),
                method="vault.list",
                payload={"limit": 500, "cursor": cursor},
            ),
            context=reading,
        )
        assert second.ok is True and second.result is not None
        assert len(second.result.sources) == 1
        assert second.result.next_cursor is None
    finally:
        second_service.close()

    changed_store = SQLiteStateStore(paths)
    try:
        changed_store.initialize()
        changed_store.register_vault_source(
            VaultSource(
                source_id="source-new",
                path=str(tmp_path / "source-new.json"),
                format=VaultFormat.JSON,
                capabilities=VaultCapabilities(readable=True),
                revision="f" * 64,
            )
        )
    finally:
        changed_store.close()
    changed_service = build_default_service(paths=paths)
    try:
        stale = changed_service.dispatch(
            RequestEnvelope(
                protocol_version=PROTOCOL_VERSION,
                request_id=uuid4(),
                method="vault.list",
                payload={"limit": 500, "cursor": cursor},
            ),
            context=reading,
        )
        assert stale.ok is False
        assert stale.error is not None and stale.error.code is ErrorCode.CONFLICT
    finally:
        changed_service.close()


def test_execution_requires_local_control_exact_plan_and_digest_binding() -> None:
    calls: list[tuple[Method, str, str]] = []

    def authorize(method: Method, plan_id: str, digest: str) -> bool:
        calls.append((method, plan_id, digest))
        return plan_id == "plan-1" and digest == "a" * 64

    service = EngineService(
        handlers={Method.ACTION_EXECUTE: lambda payload, _context: receipt_result(payload.plan_id)},
        execution_authorizer=authorize,
    )
    execution = RequestContext(
        client=ClientKind.CONTROLLER,
        capability=Capability.EXECUTION,
        local_control=True,
    )
    remote = RequestContext(
        client=ClientKind.CONTROLLER,
        capability=Capability.EXECUTION,
        local_control=False,
    )

    rejected = decode(
        handle_frame(
            request("action.execute", {"plan_id": "plan-1", "digest": "b" * 64}),
            service,
            context=execution,
        )
    )
    local_only = decode(
        handle_frame(
            request("action.execute", {"plan_id": "plan-1", "digest": "a" * 64}),
            service,
            context=remote,
        )
    )
    accepted = decode(
        handle_frame(
            request("action.execute", {"plan_id": "plan-1", "digest": "a" * 64}),
            service,
            context=execution,
        )
    )

    assert rejected["error"]["code"] == "conflict"
    assert local_only["error"]["code"] == "permission_denied"
    assert accepted["ok"] is True
    assert calls == [
        (Method.ACTION_EXECUTE, "plan-1", "b" * 64),
        (Method.ACTION_EXECUTE, "plan-1", "a" * 64),
    ]


@pytest.mark.parametrize(
    "method",
    [Method.ACTION_EXECUTE, Method.VAULT_MUTATION_EXECUTE],
    ids=["action", "vault-mutation"],
)
def test_execution_rejects_handler_receipt_for_a_different_plan(method: Method) -> None:
    service = EngineService(
        handlers={method: lambda _payload, _context: receipt_result("different-plan")},
        execution_authorizer=lambda _method, _plan_id, _digest: True,
    )

    response = decode(
        handle_frame(
            request(method.value, {"plan_id": "requested-plan", "digest": "a" * 64}),
            service,
            context=RequestContext(
                client=ClientKind.CONTROLLER,
                capability=Capability.EXECUTION,
                local_control=True,
            ),
        )
    )

    assert response["ok"] is False
    assert response["result"] is None
    assert response["error"]["code"] == "internal"


@pytest.mark.parametrize("state", ["partial", "interrupted"])
def test_quarantine_contract_rejects_nonrestorable_state_marked_restorable(
    state: str,
) -> None:
    service = EngineService(
        handlers={
            Method.QUARANTINE_LIST: lambda _payload, _context: {
                "entries": [
                    {
                        "entry_id": "entry-1",
                        "agent_id": "agent-1",
                        "resource_type": "file",
                        "state": state,
                        "restorable": True,
                        "created_at": "2026-08-12T12:00:00Z",
                        "updated_at": "2026-08-12T12:00:00Z",
                    }
                ],
                "next_cursor": None,
            }
        }
    )

    response = decode(handle_frame(request("quarantine.list"), service))

    assert response["ok"] is False
    assert response["error"]["code"] == "internal"


def test_settings_reject_unknown_and_out_of_range_fields() -> None:
    context = RequestContext(
        client=ClientKind.CONTROLLER,
        capability=Capability.PLANNING,
        local_control=True,
    )

    unknown = decode(
        handle_frame(
            request("settings.update", {"expected_revision": 0, "api_key": "nope"}),
            EngineService(),
            context=context,
        )
    )
    out_of_range = decode(
        handle_frame(
            request(
                "settings.update",
                {"expected_revision": 0, "scan_interval_seconds": 0},
            ),
            EngineService(),
            context=context,
        )
    )
    explicit_null = decode(
        handle_frame(
            request(
                "settings.update",
                {"expected_revision": 0, "appearance": None},
            ),
            EngineService(),
            context=context,
        )
    )

    assert unknown["error"]["code"] == "invalid_request"
    assert out_of_range["error"]["code"] == "invalid_request"
    assert explicit_null["error"]["code"] == "invalid_request"


def test_independent_services_enforce_persisted_settings_revision(
    tmp_path: Path, request: pytest.FixtureRequest
) -> None:
    make_request = globals()["request"]
    paths = AppPaths(
        data_dir=tmp_path / "data",
        state_dir=tmp_path / "state",
        runtime_dir=tmp_path / "runtime",
        backups_dir=tmp_path / "backups",
        graveyard_dir=tmp_path / "graveyard",
    )
    first = build_default_service(paths=paths)
    second = build_default_service(paths=paths)
    request.addfinalizer(lambda: getattr(first, "close", lambda: None)())
    request.addfinalizer(lambda: getattr(second, "close", lambda: None)())
    context = RequestContext(
        client=ClientKind.CONTROLLER,
        capability=Capability.PLANNING,
        local_control=True,
    )

    initial = decode(handle_frame(make_request("settings.get"), first, context=context))
    assert initial["result"]["revision"] == 0
    first_update = decode(
        handle_frame(
            make_request(
                "settings.update",
                {"expected_revision": 0, "appearance": "dark"},
            ),
            first,
            context=context,
        )
    )
    stale_update = decode(
        handle_frame(
            make_request(
                "settings.update",
                {"expected_revision": 0, "reduced_motion": True},
            ),
            second,
            context=context,
        )
    )
    observed = decode(handle_frame(make_request("settings.get"), second, context=context))

    assert first_update["ok"] is True
    assert first_update["result"]["revision"] == 1
    assert first_update["result"]["settings"]["appearance"] == "dark"
    assert stale_update["ok"] is False
    assert stale_update["error"]["code"] == "conflict"
    assert stale_update["error"]["details"] == {"reason": "settings_revision_mismatch"}
    assert observed["result"] == first_update["result"]


@pytest.mark.parametrize(
    ("method", "payload"),
    [
        (
            "action.plan",
            {
                "agent_id": " agent-1",
                "mode": "terminate",
                "target": action_target(),
            },
        ),
        ("agent.detail", {"agent_id": "agent-1 "}),
        ("vault.probe", {"path": " C:/selected/vault.json"}),
        ("vault.register", {"path": "C:/selected/vault.json "}),
    ],
)
def test_identifiers_and_paths_reject_outer_whitespace(
    method: str, payload: dict[str, object]
) -> None:
    response = decode(handle_frame(request(method, payload), EngineService()))

    assert response["ok"] is False
    assert response["error"]["code"] == "invalid_request"


@pytest.mark.parametrize(
    "binding",
    [
        {"expected_pid": 4112},
        {"expected_process_instance_id": "c" * 64},
        {"expected_pid": None},
        {"expected_process_instance_id": None},
        {"expected_pid": None, "expected_process_instance_id": None},
        {"expected_pid": 4112, "expected_process_instance_id": None},
        {"expected_pid": None, "expected_process_instance_id": "c" * 64},
    ],
)
def test_agent_detail_rejects_partial_or_null_binding_in_schema_and_engine(
    binding: dict[str, object],
) -> None:
    payload = {"agent_id": "agent-1", **binding}
    schema = json.loads(
        (ROOT / "packages/protocol/schema/protocol.schema.json").read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema, format_checker=FormatChecker())

    with pytest.raises(JsonSchemaValidationError):
        validator.validate(
            {
                "protocol_version": PROTOCOL_VERSION,
                "request_id": str(uuid4()),
                "method": "agent.detail",
                "payload": payload,
            }
        )

    response = decode(
        handle_frame(
            request("agent.detail", payload),
            EngineService(),
        )
    )

    assert response["ok"] is False
    assert response["error"]["code"] == "invalid_request"


@pytest.mark.parametrize(
    "binding",
    [
        {},
        {"expected_pid": 123, "expected_process_instance_id": "c" * 64},
    ],
)
def test_agent_detail_accepts_omitted_or_complete_non_null_binding_in_schema_and_engine(
    binding: dict[str, object],
) -> None:
    payload = {"agent_id": "agent-1", **binding}
    schema = json.loads(
        (ROOT / "packages/protocol/schema/protocol.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(
        {
            "protocol_version": PROTOCOL_VERSION,
            "request_id": str(uuid4()),
            "method": "agent.detail",
            "payload": payload,
        }
    )
    service = EngineService(
        handlers={Method.AGENT_DETAIL: lambda _payload, _context: agent_result()}
    )

    response = decode(handle_frame(request("agent.detail", payload), service))

    assert response["ok"] is True


def test_action_target_pid_uses_the_unsigned_32_bit_boundary_in_schema_and_engine() -> None:
    maximum_pid = 4_294_967_295
    schema = json.loads(
        (ROOT / "packages/protocol/schema/protocol.schema.json").read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema, format_checker=FormatChecker())

    def envelope(pid: int) -> dict[str, object]:
        return {
            "protocol_version": PROTOCOL_VERSION,
            "request_id": str(uuid4()),
            "method": "action.plan",
            "payload": {
                "agent_id": "agent-1",
                "mode": "terminate",
                "target": {"pid": pid, "process_instance_id": "c" * 64},
            },
        }

    def plan(
        payload: service_module.StrictModel,
        _context: RequestContext,
    ) -> object:
        target = payload.model_dump(mode="json")["target"]
        return {**plan_result(), "target": {**target, "state": "stale"}}

    maximum_request = envelope(maximum_pid)
    context = RequestContext(
        client=ClientKind.CONTROLLER,
        capability=Capability.PLANNING,
        local_control=True,
    )
    validator.validate(maximum_request)
    maximum_response = decode(
        handle_frame(
            json.dumps(maximum_request, separators=(",", ":")).encode(),
            EngineService(handlers={Method.ACTION_PLAN: plan}),
            context=context,
        )
    )
    validator.validate(maximum_response)
    assert maximum_response["ok"] is True, maximum_response
    assert maximum_response["result"]["target"]["pid"] == maximum_pid

    oversized_request = envelope(maximum_pid + 1)
    with pytest.raises(JsonSchemaValidationError):
        validator.validate(oversized_request)
    oversized_response = decode(
        handle_frame(
            json.dumps(oversized_request, separators=(",", ":")).encode(),
            EngineService(handlers={Method.ACTION_PLAN: plan}),
            context=context,
        )
    )
    assert oversized_response["ok"] is False
    assert oversized_response["error"]["code"] == "invalid_request"


def test_json_schema_rejects_outer_whitespace_in_identifiers_and_paths() -> None:
    schema = json.loads(
        (ROOT / "packages/protocol/schema/protocol.schema.json").read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    base = {
        "protocol_version": PROTOCOL_VERSION,
        "request_id": str(uuid4()),
    }

    with pytest.raises(JsonSchemaValidationError):
        validator.validate(
            {
                **base,
                "method": "agent.detail",
                "payload": {"agent_id": " agent-1"},
            }
        )
    with pytest.raises(JsonSchemaValidationError):
        validator.validate(
            {
                **base,
                "method": "vault.probe",
                "payload": {"path": "C:/vault.json "},
            }
        )


@pytest.mark.parametrize(
    "method",
    [method for method in Method if method.value.startswith("vault.")],
)
def test_every_successful_vault_result_has_constant_local_only_warning(
    method: Method,
) -> None:
    service = EngineService(
        handlers={method: lambda _payload, _context: vault_result(method)},
        execution_authorizer=lambda _method, _plan_id, _digest: True,
    )
    payloads: dict[Method, dict[str, object]] = {
        Method.VAULT_LIST: {},
        Method.VAULT_REGISTER: {"path": "C:/selected/vault.json"},
        Method.VAULT_PROBE: {"path": "C:/selected/vault.json"},
        Method.VAULT_QUERY: {"source_id": "source-1"},
        Method.VAULT_GET: {"source_id": "source-1", "record_id": "record-1"},
        Method.VAULT_MUTATION_PLAN: {
            "source_id": "source-1",
            "expected_revision": "a" * 64,
            "operation": "update_content",
            "record_id": "record-1",
            "value": "new",
        },
        Method.VAULT_MUTATION_EXECUTE: {"plan_id": "plan-1", "digest": "a" * 64},
        Method.VAULT_SNAPSHOT_LIST: {"source_id": "source-1"},
        Method.VAULT_RESTORE_PLAN: {
            "source_id": "source-1",
            "snapshot_id": "snapshot-1",
            "snapshot_digest": "b" * 64,
            "expected_revision": "a" * 64,
        },
        Method.VAULT_RESTORE_EXECUTE: {"plan_id": "plan-1", "digest": "a" * 64},
    }
    capability = (
        Capability.EXECUTION
        if method
        in {
            Method.VAULT_MUTATION_EXECUTE,
            Method.VAULT_RESTORE_EXECUTE,
        }
        else Capability.PLANNING
        if method
        in {
            Method.VAULT_REGISTER,
            Method.VAULT_MUTATION_PLAN,
            Method.VAULT_RESTORE_PLAN,
        }
        else Capability.READ
    )
    context = RequestContext(
        client=ClientKind.CONTROLLER,
        capability=capability,
        local_control=capability is Capability.EXECUTION,
    )

    response = decode(
        handle_frame(request(method.value, payloads[method]), service, context=context)
    )

    assert response["ok"] is True, response
    assert response["result"]["local_only_warning"] == VAULT_LOCAL_ONLY_WARNING


def test_every_method_has_a_strict_runtime_result_contract() -> None:
    assert set(RESULT_MODELS) == set(Method)
    assert all(model.model_config.get("extra") == "forbid" for model in RESULT_MODELS.values())


def test_doctor_rejects_warning_longer_than_schema_bound() -> None:
    service = EngineService(
        handlers={
            Method.DOCTOR: lambda _payload, _context: {
                "healthy": True,
                "checks": [],
                "warnings": ["x" * 1_000],
            }
        }
    )

    response = decode(handle_frame(request("doctor"), service))

    assert response["ok"] is False
    assert response["error"]["code"] == "internal"


def test_runtime_result_string_collections_have_item_bounds() -> None:
    unconstrained: list[str] = []

    def inspect_schema(value: object, path: str) -> None:
        if isinstance(value, dict):
            items = value.get("items")
            if (
                value.get("type") == "array"
                and isinstance(items, dict)
                and items.get("type") == "string"
                and "maxLength" not in items
                and "enum" not in items
            ):
                unconstrained.append(path)
            for key, child in value.items():
                inspect_schema(child, f"{path}/{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                inspect_schema(child, f"{path}/{index}")

    for method, model in RESULT_MODELS.items():
        inspect_schema(model.model_json_schema(), method.value)

    assert unconstrained == []


def test_response_envelope_rejects_result_for_a_different_method() -> None:
    doctor = DoctorResult(healthy=True, checks=(), warnings=())

    with pytest.raises(ValueError):
        ResponseEnvelope(
            request_id=uuid4(),
            method=Method.SYSTEM_INFO,
            ok=True,
            result=doctor,
            error=None,
        )


def test_every_method_success_and_error_response_validates_against_json_schema() -> None:
    schema = json.loads(
        (ROOT / "packages/protocol/schema/protocol.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())

    for method in Method:
        result_model = RESULT_MODELS[method].model_validate_json(
            json.dumps(representative_result(method))
        )
        success = ResponseEnvelope(
            request_id=uuid4(),
            method=method,
            ok=True,
            result=result_model,
            error=None,
        )
        error = ResponseEnvelope(
            request_id=uuid4(),
            method=method,
            ok=False,
            result=None,
            error=ErrorBody(code=ErrorCode.UNSUPPORTED, message="Not supported."),
        )

        validator.validate(success.model_dump(mode="json"))
        validator.validate(error.model_dump(mode="json"))


def test_json_schema_requires_exact_bounded_partial_receipt_failures() -> None:
    schema = json.loads(
        (ROOT / "packages/protocol/schema/protocol.schema.json").read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema, format_checker=FormatChecker())

    def response(result: dict[str, object]) -> dict[str, object]:
        return {
            "protocol_version": PROTOCOL_VERSION,
            "request_id": str(uuid4()),
            "method": Method.ACTION_EXECUTE.value,
            "ok": True,
            "result": result,
            "error": None,
        }

    valid = receipt_result("plan-1")
    validator.validate(response(valid))

    missing = dict(valid)
    missing.pop("partial_failures")
    invalid_receipts = (
        missing,
        {**valid, "partial_failures": ["bounded"] * 65},
        {**valid, "partial_failures": ["x" * 2_049]},
        {**valid, "partial_failures": [""]},
        {**valid, "unexpected": True},
    )
    for invalid in invalid_receipts:
        with pytest.raises(JsonSchemaValidationError):
            validator.validate(response(invalid))


@pytest.mark.parametrize("result", [None, {}, {"healthy": True}])
def test_invalid_handler_success_result_becomes_redacted_internal_error(
    result: object,
) -> None:
    service = EngineService(handlers={Method.SYSTEM_INFO: lambda _payload, _context: result})

    encoded = handle_frame(request("system.info"), service).decode()
    response = json.loads(encoded)

    assert response["ok"] is False
    assert response["method"] == "system.info"
    assert response["error"]["code"] == "internal"
    assert set(response["error"]["details"]) == {"correlation_id"}
    assert response["result"] is None


def test_language_neutral_schema_and_types_share_version_and_methods() -> None:
    schema = json.loads(
        (ROOT / "packages/protocol/schema/protocol.schema.json").read_text(encoding="utf-8")
    )
    typescript = (ROOT / "packages/protocol/src/types.ts").read_text(encoding="utf-8")

    assert schema["$defs"]["protocolVersion"]["const"] == PROTOCOL_VERSION
    assert f'PROTOCOL_VERSION = "{PROTOCOL_VERSION}"' in typescript
    schema_methods = set(schema["$defs"]["method"]["enum"])
    assert schema_methods == {method.value for method in Method}
    assert "context" not in schema["$defs"]["request"]["properties"]
    request_mappings = schema["$defs"]["request"]["allOf"]
    response_mappings = schema["$defs"]["response"]["allOf"]
    assert {
        mapping["if"]["properties"]["method"]["const"] for mapping in request_mappings
    } == schema_methods
    assert {
        mapping["if"]["properties"]["method"]["const"] for mapping in response_mappings
    } == schema_methods
    assert "unknown" in typescript
    assert "defunct" in typescript
    assert "signature_only" in typescript
    assert 'availability: "unknown"; amount_usd: null' in typescript
    assert "ReadonlyArray<unknown>" not in typescript
    assert "context: RequestContext" not in typescript
    assert "M extends Method ?" in typescript
    assert "agent_id: Identifier" in typescript
    assert "path: LocalPath" in typescript


def test_protocol_readme_documents_boundaries_and_posix_defunct_semantics() -> None:
    readme = (ROOT / "packages/protocol/README.md").read_text(encoding="utf-8").casefold()

    assert "1 mib" in readme
    assert "4 mib" in readme
    assert "local-only" in readme
    assert "unknown" in readme and "$0" in readme
    assert "posix" in readme and "wait" in readme and "exit status" in readme
    assert "partial visibility" in readme
    assert "receipt" in readme and "uncertain" in readme
    assert "trusted launcher state supplied out of band" in readme
    assert "bounded lru/ttl cache" in readme
    assert "do not change provider safety" in readme
