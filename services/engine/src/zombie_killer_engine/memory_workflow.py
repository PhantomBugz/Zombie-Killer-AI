"""Durable, content-private composition of local memory adapter operations."""

from __future__ import annotations

import json
import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

from zombie_killer_engine.memory.base import (
    MemoryError,
    MemoryReceipt,
    MutationOperation,
    MutationPlan,
    SnapshotStatus,
    canonical_hash,
    read_prefix_pinned,
    utc_now,
)
from zombie_killer_engine.memory.json_store import JsonMemoryAdapter
from zombie_killer_engine.memory.sqlite_store import SQLiteMemoryAdapter
from zombie_killer_engine.store import SQLiteStateStore

Adapter = JsonMemoryAdapter | SQLiteMemoryAdapter
AdapterFactory = Callable[[str], Adapter]
MUTATION_KIND = "memory_mutation"
RESTORE_KIND = "memory_restore"


class MemoryWorkflow:
    def __init__(self, store: SQLiteStateStore, adapter_factory: AdapterFactory) -> None:
        self._store = store
        self._adapter = adapter_factory

    @staticmethod
    def _warnings(adapter: Adapter) -> tuple[str, ...]:
        if isinstance(adapter, JsonMemoryAdapter):
            return (
                "Pause other writers before JSON/JSONL edits or restore on every platform. "
                "File locks exclude only cooperative writers on POSIX; non-cooperating path "
                "replacement cannot be made transactional.",
            )
        return (
            "SQLite edits require a quiescent, supported local schema and reject active writers "
            "or WAL state. Non-cooperating file replacement is outside SQLite locking "
            "guarantees on POSIX.",
        )

    def plan_mutation(
        self, source_id: str, operation: MutationOperation, revision: str
    ) -> dict[str, object]:
        adapter = self._adapter(source_id)
        plan = adapter.plan_mutation(operation, expected_revision=revision)
        # MutationPlan deliberately excludes the proposed private value from its
        # domain journal. A separate bounded private executable authority keeps
        # one-shot execution possible without putting contents in public receipts.
        private = plan.model_dump(mode="json")
        private["operation"] = {
            **operation.model_dump(mode="json"),
            "value": operation.unsealed_value(),
        }
        self._store.save_workflow_plan(
            MUTATION_KIND, plan.plan_id, plan.digest, private, expires_at=plan.expires_at
        )
        return {
            "plan_id": plan.plan_id,
            "digest": plan.digest,
            "expires_at": plan.expires_at.isoformat(),
            "consequences": (
                "Create and verify a recoverable snapshot, then update this exact local record.",
            ),
            "warnings": self._warnings(adapter),
            "source_id": source_id,
            "record_id": plan.record_id,
            "snapshot_id": None,
            "before_revision": plan.source_revision,
            "backup_verified": False,
            "diff": [item.model_dump(mode="json") for item in plan.diff],
        }

    @staticmethod
    def _receipt(
        plan_id: str,
        payload: dict[str, object],
        receipt: MemoryReceipt | None,
        *,
        uncertain: bool = False,
    ) -> dict[str, object]:
        # A reconciled rollback proves the observed content, not whether a write
        # had once been issued before its owner died. Do not label it 'unissued'.
        uncertain = uncertain or (receipt is not None and "rollback" in receipt.operation)
        successful = receipt is not None and not uncertain
        return {
            "receipt_id": receipt.receipt_id
            if receipt is not None
            else "memory-receipt-" + secrets.token_hex(16),
            "plan_id": plan_id,
            "kind": "memory",
            "outcome": "completed" if successful else "interrupted" if uncertain else "failed",
            "certainty": "uncertain"
            if uncertain
            else "verified"
            if successful
            else "failed_before_issue",
            "action_issued": None if uncertain else successful,
            "partial_failures": (
                "Outcome could not be proven; retained snapshots and journals require review.",
            )
            if uncertain
            else ()
            if successful
            else ("The reviewed operation was not issued.",),
            "created_at": receipt.created_at.isoformat()
            if receipt is not None
            else utc_now().isoformat(),
            "source_id": payload.get("source_id"),
            "record_id": payload.get("record_id"),
            "snapshot_id": receipt.snapshot_id
            if receipt is not None
            else payload.get("snapshot_id"),
            "before_revision": receipt.before_revision
            if receipt is not None
            else payload.get("source_revision", payload.get("expected_revision")),
            "after_revision": receipt.after_revision if receipt is not None else None,
            "operation": receipt.operation
            if receipt is not None
            else payload.get("operation_kind", "restore"),
        }

    def execute_mutation(self, plan_id: str, digest: str) -> dict[str, object]:
        payload = self._store.claim_workflow_plan(
            MUTATION_KIND, plan_id, expected_digest=digest, reconcile=True
        )
        reconcile = payload.pop("_workflow_reconcile_required", False)
        plan = MutationPlan.model_validate_json(json.dumps(payload))
        try:
            adapter = self._adapter(plan.source_id)
        except Exception:
            result = self._receipt(plan_id, payload, None, uncertain=bool(reconcile))
            self._store.finish_workflow_plan(MUTATION_KIND, plan_id, result)
            return result
        if reconcile:
            # Opening the adapter reconciles the domain journal, but never grant
            # permission to repeat an action whose issuing boundary was lost.
            existing = self._store.get_memory_receipt_for_plan(plan_id)
            result = self._receipt(plan_id, payload, existing, uncertain=existing is None)
        else:
            try:
                receipt = adapter.apply(plan)
            except MemoryError as error:
                existing = self._store.get_memory_receipt_for_plan(plan_id)
                uncertain = existing is None and any(
                    word in str(error).casefold()
                    for word in ("uncertain", "journal", "committed", "reconciliation")
                )
                result = self._receipt(plan_id, payload, existing, uncertain=uncertain)
            else:
                result = self._receipt(plan_id, payload, receipt)
        self._store.finish_workflow_plan(MUTATION_KIND, plan_id, result)
        return result

    def snapshots(self, source_id: str, limit: int) -> dict[str, object]:
        self._adapter(source_id)
        return {
            "snapshots": [
                {
                    "snapshot_id": snapshot.snapshot_id,
                    "source_id": snapshot.source_id,
                    "source_revision": snapshot.source_revision,
                    "digest": snapshot.digest,
                    "size": snapshot.size,
                    "status": snapshot.status.value,
                    "created_at": snapshot.created_at.isoformat(),
                }
                for snapshot in self._store.list_memory_snapshots(source_id, limit=limit)
            ]
        }

    def plan_restore(
        self, source_id: str, snapshot_id: str, snapshot_digest: str, revision: str
    ) -> dict[str, object]:
        adapter = self._adapter(source_id)
        source = self._store.get_vault_source(source_id)
        if source is None or not source.capabilities.restore:
            raise MemoryError("vault source does not support restore")
        snapshot = self._store.get_memory_snapshot(snapshot_id)
        if (
            snapshot is None
            or snapshot.source_id != source_id
            or snapshot.digest != snapshot_digest
            or snapshot.status is not SnapshotStatus.VERIFIED
        ):
            raise MemoryError("snapshot authority does not match this source")
        if adapter.current_revision() != revision:
            raise MemoryError("vault revision changed before restore planning")
        # Preview verifies preserved backup evidence. Execution verifies it again
        # and creates a separate before-restore rollback snapshot in the adapter.
        if isinstance(adapter, JsonMemoryAdapter):
            adapter._verified_snapshot(snapshot_id, snapshot_digest)
        else:
            adapter._verified_snapshot_model(snapshot)
        _prefix, identity = read_prefix_pinned(Path(source.path), prefix_bytes=16)
        now = datetime.now(UTC)
        plan_id = "memory-restore-" + secrets.token_hex(16)
        expires = now + timedelta(seconds=30)
        payload: dict[str, object] = {
            "plan_id": plan_id,
            "source_id": source_id,
            "snapshot_id": snapshot_id,
            "snapshot_digest": snapshot_digest,
            "expected_revision": revision,
            "source_identity": identity.model_dump(mode="json"),
            "created_at": now.isoformat(),
            "expires_at": expires.isoformat(),
        }
        digest = canonical_hash(payload)
        payload["digest"] = digest
        self._store.save_workflow_plan(RESTORE_KIND, plan_id, digest, payload, expires_at=expires)
        return {
            "plan_id": plan_id,
            "digest": digest,
            "expires_at": expires.isoformat(),
            "source_id": source_id,
            "snapshot_id": snapshot_id,
            "before_revision": revision,
            "record_id": None,
            "backup_verified": True,
            "diff": (),
            "consequences": (
                "Verify this selected snapshot, back up the current vault, "
                "then restore the local source.",
            ),
            "warnings": self._warnings(adapter),
        }

    def execute_restore(self, plan_id: str, digest: str) -> dict[str, object]:
        payload = self._store.claim_workflow_plan(
            RESTORE_KIND, plan_id, expected_digest=digest, reconcile=True
        )
        reconcile = payload.pop("_workflow_reconcile_required", False)
        try:
            adapter = self._adapter(str(payload["source_id"]))
        except Exception:
            result = self._receipt(plan_id, payload, None, uncertain=bool(reconcile))
            self._store.finish_workflow_plan(RESTORE_KIND, plan_id, result)
            return result
        if reconcile:
            # No public domain restore ID is available across a crashed dispatch.
            # Do not issue a second restore even if the file currently looks old.
            result = self._receipt(plan_id, payload, None, uncertain=True)
        else:
            source = self._store.get_vault_source(str(payload["source_id"]))
            assert source is not None
            try:
                _prefix, identity = read_prefix_pinned(Path(source.path), prefix_bytes=16)
            except (MemoryError, OSError):
                result = self._receipt(plan_id, payload, None)
                self._store.finish_workflow_plan(RESTORE_KIND, plan_id, result)
                return result
            if identity.model_dump(mode="json") != payload["source_identity"]:
                result = self._receipt(plan_id, payload, None)
            else:
                try:
                    receipt = adapter.restore(
                        str(payload["snapshot_id"]),
                        expected_snapshot_digest=str(payload["snapshot_digest"]),
                        expected_revision=str(payload["expected_revision"]),
                        reviewed_expires_at=datetime.fromisoformat(str(payload["expires_at"])),
                    )
                except MemoryError as error:
                    uncertain = any(
                        word in str(error).casefold()
                        for word in ("uncertain", "journal", "committed", "reconciliation")
                    )
                    result = self._receipt(plan_id, payload, None, uncertain=uncertain)
                else:
                    result = self._receipt(plan_id, payload, receipt)
        self._store.finish_workflow_plan(RESTORE_KIND, plan_id, result)
        return result

    def authorize(self, kind: str, plan_id: str, digest: str) -> bool:
        payload = self._store.get_workflow_plan(kind, plan_id)
        return payload is not None and payload.get("digest") == digest
