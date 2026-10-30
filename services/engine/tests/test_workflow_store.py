from __future__ import annotations

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from zombie_killer_engine.actions import ActionMode, ActionPlan, ActionReceipt, ActionResult
from zombie_killer_engine.models import ProcessIdentity
from zombie_killer_engine.paths import AppPaths
from zombie_killer_engine.store import (
    ExpiredPlanError,
    PlanClaimError,
    SQLiteStateStore,
    StoreError,
)

NOW = datetime(2026, 10, 2, 12, 0, tzinfo=UTC)


def new_store(tmp_path: Path, *, now: datetime = NOW) -> SQLiteStateStore:
    paths = AppPaths(
        data_dir=tmp_path / "data",
        state_dir=tmp_path / "state",
        runtime_dir=tmp_path / "runtime",
        backups_dir=tmp_path / "backups",
        graveyard_dir=tmp_path / "graveyard",
    )
    store = SQLiteStateStore(paths, clock=lambda: now)
    store.initialize(now=now)
    return store


def test_workflow_payload_preserves_private_authority_and_receipt_survives_restart(
    tmp_path: Path,
) -> None:
    store = new_store(tmp_path)
    payload = {"destination": "synthetic/sk-" + "fixture" + "A" * 20, "revision": "b" * 64}
    store.save_workflow_plan(
        "test_export", "fixture-plan", "a" * 64, payload, expires_at=NOW + timedelta(seconds=30)
    )
    restarted = new_store(tmp_path)
    assert restarted.get_workflow_plan("test_export", "fixture-plan") == payload
    assert (
        restarted.claim_workflow_plan("test_export", "fixture-plan", expected_digest="a" * 64)
        == payload
    )
    receipt = {"receipt_id": "fixture-receipt", "plan_id": "fixture-plan", "outcome": "written"}
    restarted.finish_workflow_plan("test_export", "fixture-plan", receipt)
    assert new_store(tmp_path).get_workflow_receipt("test_export", "fixture-plan") == receipt
    assert (
        new_store(tmp_path, now=NOW + timedelta(days=1)).get_workflow_plan(
            "test_export",
            "fixture-plan",
        )
        == payload
    )
    with pytest.raises(PlanClaimError):
        new_store(tmp_path).claim_workflow_plan(
            "test_export", "fixture-plan", expected_digest="a" * 64
        )


def test_workflow_claim_rejects_wrong_digest_live_owner_and_expired_plan(tmp_path: Path) -> None:
    store = new_store(tmp_path)
    store.save_workflow_plan(
        "test_export",
        "fixture-plan",
        "a" * 64,
        {"value": "private"},
        expires_at=NOW + timedelta(seconds=30),
    )
    with pytest.raises(PlanClaimError):
        store.claim_workflow_plan("test_export", "fixture-plan", expected_digest="b" * 64)
    with pytest.raises(ExpiredPlanError):
        new_store(tmp_path, now=NOW + timedelta(seconds=31)).claim_workflow_plan(
            "test_export",
            "fixture-plan",
            expected_digest="a" * 64,
        )
    store.claim_workflow_plan("test_export", "fixture-plan", expected_digest="a" * 64)
    with pytest.raises(PlanClaimError):
        new_store(tmp_path).claim_workflow_plan(
            "test_export", "fixture-plan", expected_digest="a" * 64
        )
    with pytest.raises(StoreError):
        new_store(tmp_path).finish_workflow_plan(
            "test_export",
            "fixture-plan",
            {
                "plan_id": "fixture-plan",
                "outcome": "forged-other-owner",
            },
        )


def test_corrupt_workflow_authority_cannot_be_read_or_claimed(tmp_path: Path) -> None:
    store = new_store(tmp_path)
    store.save_workflow_plan(
        "test_export",
        "fixture-plan",
        "a" * 64,
        {"value": "original"},
        expires_at=NOW + timedelta(seconds=30),
    )
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE workflow_plans SET payload_json = ? WHERE plan_id = ?",
            ('{"value":"tampered"}', "fixture-plan"),
        )
    with pytest.raises(StoreError):
        store.get_workflow_plan("test_export", "fixture-plan")
    with pytest.raises(StoreError):
        store.claim_workflow_plan("test_export", "fixture-plan", expected_digest="a" * 64)


def test_dead_owner_workflow_requires_explicit_domain_reconciliation(tmp_path: Path) -> None:
    store = new_store(tmp_path)
    store.save_workflow_plan(
        "test_export",
        "fixture-plan",
        "a" * 64,
        {"value": "original"},
        expires_at=NOW + timedelta(seconds=30),
    )
    store.claim_workflow_plan("test_export", "fixture-plan", expected_digest="a" * 64)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE workflow_plans SET claim_owner_pid = 999999999, "
            "claim_owner_create_time = 1.0 WHERE plan_id = 'fixture-plan'"
        )
    restarted = new_store(tmp_path)
    with pytest.raises(PlanClaimError):
        restarted.claim_workflow_plan("test_export", "fixture-plan", expected_digest="a" * 64)
    assert restarted.claim_workflow_plan(
        "test_export", "fixture-plan", expected_digest="a" * 64, reconcile=True
    ) == {"value": "original", "_workflow_reconcile_required": True}


def test_competing_workflow_instances_issue_only_one_claim(tmp_path: Path) -> None:
    store = new_store(tmp_path)
    store.save_workflow_plan(
        "test_export",
        "fixture-plan",
        "a" * 64,
        {"value": "original"},
        expires_at=NOW + timedelta(seconds=30),
    )
    competitors = [new_store(tmp_path), new_store(tmp_path)]

    def claim(candidate: SQLiteStateStore) -> bool:
        try:
            candidate.claim_workflow_plan("test_export", "fixture-plan", expected_digest="a" * 64)
            return True
        except PlanClaimError:
            return False

    with ThreadPoolExecutor(max_workers=2) as executor:
        assert sorted(executor.map(claim, competitors)) == [False, True]


def test_oversized_private_workflow_payload_never_becomes_executable(tmp_path: Path) -> None:
    store = new_store(tmp_path)
    with pytest.raises(ValueError, match="byte limit"):
        store.save_workflow_plan(
            "test_export",
            "fixture-plan",
            "a" * 64,
            {"value": "x" * 65536},
            expires_at=NOW + timedelta(seconds=30),
        )
    assert store.get_workflow_plan("test_export", "fixture-plan") is None


def test_public_workflow_receipt_lookup_and_pages_never_expose_private_plans(
    tmp_path: Path,
) -> None:
    store = new_store(tmp_path)
    for index in range(2):
        plan_id = f"fixture-plan-{index}"
        store.save_workflow_plan(
            "test_export",
            plan_id,
            "a" * 64,
            {"private_path": "hidden"},
            expires_at=NOW + timedelta(seconds=30),
        )
        store.claim_workflow_plan("test_export", plan_id, expected_digest="a" * 64)
        store.finish_workflow_plan(
            "test_export",
            plan_id,
            {
                "receipt_id": f"fixture-receipt-{index}",
                "plan_id": plan_id,
                "outcome": "written",
            },
        )

    first = store.list_workflow_receipts(limit=1)
    second = store.list_workflow_receipts(limit=1, cursor="fixture-receipt-1")

    assert [item["receipt_id"] for item in first] == ["fixture-receipt-1"]
    assert [item["receipt_id"] for item in second] == ["fixture-receipt-0"]
    assert all("private_path" not in item for item in (*first, *second))
    assert store.get_workflow_receipt_by_id("fixture-receipt-0") == second[0]
    assert store.get_workflow_receipt_by_id("missing-receipt") is None
    with pytest.raises(ValueError):
        store.list_workflow_receipts(limit=501)
    with pytest.raises(ValueError):
        store.list_workflow_receipts(cursor="missing-receipt")


def add_action_receipt(
    store: SQLiteStateStore, *, receipt_id: str, finished_at: datetime
) -> ActionReceipt:
    plan = ActionPlan.create(
        identity=ProcessIdentity(
            boot_id="fixture-boot",
            pid=4242,
            create_time=1.25,
            executable="/synthetic/python",
            user="synthetic-user",
        ),
        mode=ActionMode.TERMINATE,
        agent_id="synthetic-agent",
        managed=True,
        consequences=("Only the exact synthetic process instance would be terminated.",),
        created_at=NOW,
        platform_name="linux",
    )
    store.save_plan(plan)
    claimed = store.claim_plan(plan.plan_id, expected_digest=plan.digest)
    receipt = ActionReceipt.create(
        plan=claimed,
        actor="synthetic-user",
        session_id=store.session_id,
        result=ActionResult.FAILED,
        action_issued=False,
        before="running",
        after="unchanged",
        started_at=NOW,
        finished_at=finished_at,
    ).model_copy(update={"receipt_id": receipt_id})
    store.finish_plan(receipt)
    return receipt


def test_mixed_public_receipt_pages_use_receipt_time_and_cross_domain_cursors(
    tmp_path: Path,
) -> None:
    store = new_store(tmp_path)
    early = add_action_receipt(
        store, receipt_id="action-early", finished_at=NOW + timedelta(seconds=1)
    )
    later = add_action_receipt(
        store, receipt_id="action-later", finished_at=NOW + timedelta(seconds=2)
    )
    for receipt_id, timestamp in (
        ("workflow-latest", "2026-10-02T12:00:02.000001Z"),
        ("workflow-tie", "2026-10-02T12:00:02+00:00"),
        ("workflow-oldest", "2026-10-02T12:00:00Z"),
    ):
        store.save_workflow_plan(
            "test_export",
            receipt_id,
            "a" * 64,
            {"private_path": "hidden"},
            expires_at=NOW + timedelta(seconds=30),
        )
        store.claim_workflow_plan("test_export", receipt_id, expected_digest="a" * 64)
        store.finish_workflow_plan(
            "test_export",
            receipt_id,
            {"receipt_id": receipt_id, "plan_id": receipt_id, "created_at": timestamp},
        )

    pages: list[ActionReceipt | dict[str, object]] = []
    cursor = None
    while page := store.list_public_receipts(limit=1, cursor=cursor):
        item = page[0]
        pages.append(item)
        cursor = item.receipt_id if isinstance(item, ActionReceipt) else str(item["receipt_id"])

    assert [
        item.receipt_id if isinstance(item, ActionReceipt) else item["receipt_id"] for item in pages
    ] == ["workflow-latest", "workflow-tie", "action-later", "action-early", "workflow-oldest"]
    assert later in pages and early in pages
    assert all("private_path" not in item for item in pages if isinstance(item, dict))
    with pytest.raises(ValueError):
        store.list_public_receipts(limit=501)
    with pytest.raises(ValueError):
        store.list_public_receipts(limit=True)
    with pytest.raises(ValueError):
        store.list_public_receipts(cursor="missing-receipt")


def test_mixed_public_receipt_cursor_requires_one_integrity_verified_receipt(
    tmp_path: Path,
) -> None:
    store = new_store(tmp_path)
    add_action_receipt(store, receipt_id="shared-receipt", finished_at=NOW)
    store.save_workflow_plan(
        "test_export", "fixture-plan", "a" * 64, {}, expires_at=NOW + timedelta(seconds=30)
    )
    store.claim_workflow_plan("test_export", "fixture-plan", expected_digest="a" * 64)
    store.finish_workflow_plan(
        "test_export",
        "fixture-plan",
        {"receipt_id": "shared-receipt", "plan_id": "fixture-plan", "created_at": NOW.isoformat()},
    )
    with pytest.raises(ValueError, match="cursor"):
        store.list_public_receipts(cursor="shared-receipt")
    with sqlite3.connect(store.database_path) as connection:
        connection.execute("UPDATE workflow_plans SET receipt_hash = ?", ("0" * 64,))
    with pytest.raises(StoreError, match="integrity"):
        store.list_public_receipts()


@pytest.mark.parametrize("historical_format", ["utc_suffix", "utc_offset"])
def test_mixed_public_receipt_pages_accept_legacy_iso_action_timestamps(
    tmp_path: Path, historical_format: str
) -> None:
    store = new_store(tmp_path)
    for receipt_id, seconds in (("action-old", 1), ("action-new", 2)):
        finished_at = NOW + timedelta(seconds=seconds)
        add_action_receipt(store, receipt_id=receipt_id, finished_at=finished_at)
        historical = finished_at.isoformat()
        if historical_format == "utc_suffix":
            historical = historical.replace("+00:00", "Z")
        with sqlite3.connect(store.database_path) as connection:
            connection.execute(
                "UPDATE receipts SET created_at=? WHERE receipt_id=?", (historical, receipt_id)
            )
    store.save_workflow_plan(
        "test_export",
        "workflow-middle",
        "a" * 64,
        {},
        expires_at=NOW + timedelta(seconds=30),
    )
    store.claim_workflow_plan("test_export", "workflow-middle", expected_digest="a" * 64)
    store.finish_workflow_plan(
        "test_export",
        "workflow-middle",
        {
            "receipt_id": "workflow-middle",
            "plan_id": "workflow-middle",
            "created_at": "2026-10-02T12:00:01.500000Z",
        },
    )

    first = store.list_public_receipts(limit=2)
    second = store.list_public_receipts(limit=2, cursor="workflow-middle")
    after_legacy_cursor = store.list_public_receipts(limit=1, cursor="action-new")

    assert isinstance(first[0], ActionReceipt) and first[0].receipt_id == "action-new"
    assert isinstance(first[1], dict) and first[1]["receipt_id"] == "workflow-middle"
    assert len(second) == 1 and isinstance(second[0], ActionReceipt)
    assert second[0].receipt_id == "action-old"
    assert after_legacy_cursor == (first[1],)


@pytest.mark.parametrize(
    ("workflow_kind", "public_kind"),
    [
        ("quarantine_execution", "quarantine"),
        ("quarantine_restore", "quarantine"),
        ("memory_mutation", "memory"),
        ("memory_restore", "memory"),
        ("diagnostics_export", "diagnostics"),
        ("quarantine_unknown", None),
        ("test_export", None),
    ],
)
def test_legacy_receipt_kind_projection_uses_only_exact_verified_workflow_kind(
    tmp_path: Path, workflow_kind: str, public_kind: str | None
) -> None:
    store = new_store(tmp_path)
    store.save_workflow_plan(
        workflow_kind,
        "fixture-plan",
        "a" * 64,
        {},
        expires_at=NOW + timedelta(seconds=30),
    )
    store.claim_workflow_plan(workflow_kind, "fixture-plan", expected_digest="a" * 64)
    original = {
        "receipt_id": "fixture-receipt",
        "plan_id": "fixture-plan",
        "created_at": NOW.isoformat(),
    }
    store.finish_workflow_plan(workflow_kind, "fixture-plan", original)
    with sqlite3.connect(store.database_path) as connection:
        before = connection.execute(
            "SELECT receipt_json, receipt_hash FROM workflow_plans WHERE kind=?", (workflow_kind,)
        ).fetchone()

    projected = dict(original)
    if public_kind is not None:
        projected["kind"] = public_kind
    assert store.get_workflow_receipt(workflow_kind, "fixture-plan") == projected
    assert store.get_workflow_receipt_by_id("fixture-receipt") == projected
    assert store.list_public_receipts() == (projected,)
    assert store.list_workflow_receipts() == (projected,)
    with sqlite3.connect(store.database_path) as connection:
        after = connection.execute(
            "SELECT receipt_json, receipt_hash FROM workflow_plans WHERE kind=?", (workflow_kind,)
        ).fetchone()
    assert after == before
    assert "kind" not in json.loads(after[0])
