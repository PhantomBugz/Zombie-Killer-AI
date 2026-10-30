"""Validate literal wire fixtures against the language-neutral protocol artifact."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker

SCHEMA = json.loads(
    (Path(__file__).resolve().parents[1] / "schema" / "protocol.schema.json").read_text(
        encoding="utf-8"
    )
)
VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FormatChecker())
WARNING = (
    "Changes affect only local user-controlled memory; they do not change provider safety, "
    "rate limits, account state, or guarantee continuation."
)


def response(method: str, result: dict[str, Any]) -> dict[str, Any]:
    return {
        "protocol_version": "1.0",
        "request_id": "83baf264-2bac-41e1-8b34-c39b768227fc",
        "method": method,
        "ok": True,
        "result": result,
        "error": None,
    }


def request(method: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "protocol_version": "1.0",
        "request_id": "83baf264-2bac-41e1-8b34-c39b768227fc",
        "method": method,
        "payload": payload,
    }


def record() -> dict[str, Any]:
    return {
        "record_id": "record-1",
        "namespace": "default",
        "content": "reviewed content",
        "metadata": {},
        "embedding_present": False,
        "source_revision": "a" * 64,
        "editable_fields": [
            {"field": "content", "kind": "update_content", "value_type": "string", "value": "old"},
            {"field": "score", "kind": "update_field", "value_type": "number", "value": 1.5},
            {"field": "active", "kind": "update_metadata", "value_type": "boolean", "value": True},
            {"field": "empty", "kind": "update_field", "value_type": "null", "value": None},
        ],
    }


def plan() -> dict[str, Any]:
    return {
        "plan_id": "plan-1",
        "digest": "a" * 64,
        "expires_at": "2026-10-02T12:00:30Z",
        "consequences": ["Update one reviewed scalar."],
        "warnings": [],
        "local_only_warning": WARNING,
        "source_id": "source-1",
        "record_id": "record-1",
        "snapshot_id": None,
        "before_revision": "b" * 64,
        "backup_verified": True,
        "diff": [
            {
                "field_name": "content",
                "old_hash": "b" * 64,
                "new_hash": "c" * 64,
                "old_preview": "[REDACTED]",
                "new_preview": "[REDACTED]",
            }
        ],
    }


def receipt() -> dict[str, Any]:
    return {
        "receipt_id": "receipt-1",
        "plan_id": "plan-1",
        "outcome": "updated",
        "certainty": "verified",
        "action_issued": True,
        "partial_failures": [],
        "created_at": "2026-10-02T12:00:10Z",
        "kind": "memory",
        "local_only_warning": WARNING,
        "source_id": "source-1",
        "record_id": "record-1",
        "snapshot_id": "snapshot-1",
        "before_revision": "a" * 64,
        "after_revision": "b" * 64,
        "operation": "update_content",
    }


def test_schema_accepts_explicit_scalar_editor_contract() -> None:
    VALIDATOR.validate(response("vault.get", {"record": record(), "local_only_warning": WARNING}))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("field", ""),
        ("field", "x" * 129),
        ("kind", "quarantine"),
        ("value_type", "object"),
        ("value", {"nested": "not scalar"}),
        ("value", ["not scalar"]),
        ("value", "x" * 65_537),
        ("value", True),
        ("unexpected", "extra"),
    ],
    ids=[
        "empty",
        "name-bound",
        "operation",
        "type",
        "object",
        "array",
        "value-bound",
        "mismatch",
        "extra",
    ],
)
def test_scalar_editor_rejects_invalid_field_type_bound_or_extra(field: str, value: Any) -> None:
    item = record()
    item["editable_fields"][0][field] = value
    assert not VALIDATOR.is_valid(
        response("vault.get", {"record": item, "local_only_warning": WARNING})
    )


def test_scalar_editor_collection_is_bounded() -> None:
    item = record()
    item["editable_fields"] = [item["editable_fields"][0]] * 129
    assert not VALIDATOR.is_valid(
        response("vault.get", {"record": item, "local_only_warning": WARNING})
    )


def test_schema_accepts_reviewed_memory_plan_and_receipt_metadata() -> None:
    VALIDATOR.validate(response("vault.mutation.plan", plan()))
    VALIDATOR.validate(response("vault.mutation.execute", receipt()))
    nullable = receipt()
    for key in (
        "source_id",
        "record_id",
        "snapshot_id",
        "before_revision",
        "after_revision",
        "operation",
    ):
        nullable[key] = None
    VALIDATOR.validate(response("vault.restore.execute", nullable))


def test_protocol_one_zero_accepts_omitted_new_default_fields() -> None:
    legacy_record = record()
    del legacy_record["editable_fields"]
    VALIDATOR.validate(
        response("vault.get", {"record": legacy_record, "local_only_warning": WARNING})
    )
    legacy_plan = plan()
    for key in (
        "source_id",
        "record_id",
        "snapshot_id",
        "before_revision",
        "backup_verified",
        "diff",
    ):
        del legacy_plan[key]
    VALIDATOR.validate(response("vault.mutation.plan", legacy_plan))
    legacy_receipt = receipt()
    for key in (
        "kind",
        "source_id",
        "record_id",
        "snapshot_id",
        "before_revision",
        "after_revision",
        "operation",
    ):
        del legacy_receipt[key]
    VALIDATOR.validate(response("vault.mutation.execute", legacy_receipt))


@pytest.mark.parametrize(
    ("field", "value"),
    [("source_id", " outer"), ("before_revision", "x" * 64), ("backup_verified", None)],
)
def test_memory_plan_rejects_invalid_bound_authority(field: str, value: Any) -> None:
    item = plan()
    item[field] = value
    assert not VALIDATOR.is_valid(response("vault.mutation.plan", item))


@pytest.mark.parametrize(
    ("field", "value"),
    [("field_name", "x" * 129), ("old_hash", "not a hash"), ("old_preview", "private contents")],
)
def test_memory_diff_requires_bounded_names_hashes_and_redacted_previews(
    field: str, value: Any
) -> None:
    item = plan()
    item["diff"][0][field] = value
    assert not VALIDATOR.is_valid(response("vault.mutation.plan", item))


def test_memory_diff_collection_is_bounded() -> None:
    item = plan()
    item["diff"] = [item["diff"][0]] * 9
    assert not VALIDATOR.is_valid(response("vault.mutation.plan", item))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("kind", None),
        ("kind", "arbitrary"),
        ("after_revision", "bad"),
        ("operation", ""),
        ("operation", "x" * 129),
    ],
)
def test_memory_receipt_rejects_invalid_kind_revision_or_operation(field: str, value: Any) -> None:
    item = receipt()
    item[field] = value
    assert not VALIDATOR.is_valid(response("vault.mutation.execute", item))


def test_schema_accepts_finite_cleanup_requests_and_results() -> None:
    VALIDATOR.validate(request("quarantine.resource-list", {"agent_id": "agent-1"}))
    VALIDATOR.validate(
        request(
            "quarantine.plan",
            {"agent_id": "agent-1", "resource_index": 63, "expected_declaration_digest": "b" * 64},
        )
    )
    VALIDATOR.validate(request("quarantine.execute", {"plan_id": "plan-1", "digest": "a" * 64}))
    VALIDATOR.validate(
        response(
            "quarantine.resource-list",
            {
                "agent_id": "agent-1",
                "resources": [
                    {
                        "resource_index": 0,
                        "kind": "temporary",
                        "resource_type": "file",
                        "cleanup_available": True,
                        "reason": "Explicitly declared.",
                        "declaration_digest": "b" * 64,
                    }
                ],
                "returned": 1,
            },
        )
    )
    cleanup_plan = {
        key: value
        for key, value in plan().items()
        if key in {"plan_id", "digest", "expires_at", "consequences", "warnings"}
    }
    VALIDATOR.validate(response("quarantine.plan", cleanup_plan))
    cleanup_receipt = {
        key: value
        for key, value in receipt().items()
        if key
        in {
            "receipt_id",
            "plan_id",
            "outcome",
            "certainty",
            "action_issued",
            "partial_failures",
            "created_at",
            "kind",
        }
    }
    cleanup_receipt["kind"] = "quarantine"
    VALIDATOR.validate(response("quarantine.execute", cleanup_receipt))


@pytest.mark.parametrize("index", [-1, 64, 1.5, True])
def test_cleanup_plan_requires_a_bounded_integer_index(index: Any) -> None:
    assert not VALIDATOR.is_valid(
        request(
            "quarantine.plan",
            {
                "agent_id": "agent-1",
                "resource_index": index,
                "expected_declaration_digest": "b" * 64,
            },
        )
    )


def test_cleanup_resource_result_is_bounded_and_not_a_filesystem_primitive() -> None:
    item = {
        "agent_id": "agent-1",
        "resources": [
            {
                "resource_index": 0,
                "kind": "temporary",
                "resource_type": "unknown",
                "cleanup_available": False,
                "reason": "Unavailable.",
                "declaration_digest": None,
            }
        ],
        "returned": 1,
    }
    VALIDATOR.validate(response("quarantine.resource-list", item))
    for key, value in [
        ("kind", "permanent"),
        ("resource_type", "symlink"),
        ("reason", "x" * 513),
        ("path", "C:/private"),
    ]:
        invalid = deepcopy(item)
        invalid["resources"][0][key] = value
        assert not VALIDATOR.is_valid(response("quarantine.resource-list", invalid))
    invalid = deepcopy(item)
    invalid["resources"] *= 65
    assert not VALIDATOR.is_valid(response("quarantine.resource-list", invalid))
    assert not VALIDATOR.is_valid(
        request(
            "quarantine.plan",
            {
                "agent_id": "agent-1",
                "resource_index": 0,
                "expected_declaration_digest": "b" * 64,
                "path": "C:/private",
            },
        )
    )


@pytest.mark.parametrize("method", ["quarantine.resource-list", "quarantine.plan"])
def test_cleanup_requests_accept_exact_complete_process_binding(method: str) -> None:
    payload = {
        "agent_id": "agent-1",
        "expected_pid": 4242,
        "expected_process_instance_id": "c" * 64,
    }
    if method == "quarantine.plan":
        payload.update({"resource_index": 0, "expected_declaration_digest": "b" * 64})
    VALIDATOR.validate(request(method, payload))


@pytest.mark.parametrize("method", ["quarantine.resource-list", "quarantine.plan"])
@pytest.mark.parametrize(
    "binding",
    [
        {"expected_pid": 4242},
        {"expected_process_instance_id": "c" * 64},
        {"expected_pid": None, "expected_process_instance_id": None},
        {"expected_pid": 4242, "expected_process_instance_id": None},
        {"expected_pid": 0, "expected_process_instance_id": "c" * 64},
        {"expected_pid": True, "expected_process_instance_id": "c" * 64},
        {"expected_pid": 4242, "expected_process_instance_id": "not-a-digest"},
    ],
)
def test_cleanup_requests_reject_partial_null_or_invalid_process_binding(
    method: str, binding: dict[str, Any]
) -> None:
    payload = {"agent_id": "agent-1", **binding}
    if method == "quarantine.plan":
        payload.update({"resource_index": 0, "expected_declaration_digest": "b" * 64})
    assert not VALIDATOR.is_valid(request(method, payload))


@pytest.mark.parametrize("digest", [None, "not-a-digest", "B" * 64, "b" * 63])
def test_cleanup_plan_requires_the_exact_reviewed_declaration_digest(digest: Any) -> None:
    assert not VALIDATOR.is_valid(
        request(
            "quarantine.plan",
            {"agent_id": "agent-1", "resource_index": 0, "expected_declaration_digest": digest},
        )
    )


def test_cleanup_plan_cannot_omit_the_reviewed_declaration_digest() -> None:
    assert not VALIDATOR.is_valid(
        request("quarantine.plan", {"agent_id": "agent-1", "resource_index": 0})
    )


@pytest.mark.parametrize("digest", ["b" * 64, None])
def test_cleanup_resource_result_carries_required_nullable_declaration_digest(digest: Any) -> None:
    resource = {
        "resource_index": 0,
        "kind": "temporary",
        "resource_type": "file",
        "cleanup_available": digest is not None,
        "reason": "Reviewed declaration.",
        "declaration_digest": digest,
    }
    result = {"agent_id": "agent-1", "resources": [resource], "returned": 1}
    VALIDATOR.validate(response("quarantine.resource-list", result))
    del resource["declaration_digest"]
    assert not VALIDATOR.is_valid(response("quarantine.resource-list", result))
