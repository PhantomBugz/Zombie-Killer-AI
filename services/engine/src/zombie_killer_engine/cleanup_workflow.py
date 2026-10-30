"""Persistent composition of declared-resource cleanup and Graveyard recovery.

Private declaration evidence is never projected into renderer-selected paths.
The SDK remains standalone; the portable creation fingerprint below implements
its versioned JSON evidence contract and is checked against real SDK fixtures.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

from zombie_killer_engine.actions import process_instance_id
from zombie_killer_engine.leases import (
    DeclaredResource,
    LeaseDocument,
    read_resource_registration,
)
from zombie_killer_engine.paths import AppPaths, _has_redirected_component
from zombie_killer_engine.quarantine import (
    CleanupAuthority,
    CleanupManifest,
    CleanupRejectedError,
    QuarantineExecutor,
    QuarantinePlanner,
    QuarantineReceipt,
    QuarantineResult,
    QuarantineState,
    ResourceType,
    _authority_from_manifest,
)
from zombie_killer_engine.scanner import is_current_user
from zombie_killer_engine.store import PlanClaimError, SQLiteStateStore, StoreError

_AUTHORITY_KIND = "quarantine_authority"
_RESTORE_KIND = "quarantine_restore"
_LIFETIME = timedelta(seconds=30)


def _digest(value: dict[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


def _creation_fingerprint(path: Path) -> dict[str, object]:
    initial = path.lstat()
    inventory: list[list[object]] = []
    total_bytes = 0

    def snapshot(value: os.stat_result) -> tuple[int, ...]:
        return (
            int(value.st_dev),
            int(value.st_ino),
            int(value.st_mode),
            int(value.st_size),
            int(value.st_mtime_ns),
            0 if os.name == "nt" else int(value.st_ctime_ns),
            int(value.st_nlink),
            int(getattr(value, "st_file_attributes", 0)),
        )

    def visit(candidate: Path, depth: int) -> str:
        nonlocal total_bytes
        if depth > 16 or len(inventory) >= 1024:
            raise CleanupRejectedError("declared inventory exceeds its bounds")
        if _has_redirected_component(candidate):
            raise CleanupRejectedError("declared inventory contains a redirected component")
        before = candidate.lstat()
        if before.st_dev != initial.st_dev:
            raise CleanupRejectedError("declared inventory crosses a mount boundary")
        if stat.S_ISREG(before.st_mode):
            if before.st_nlink != 1:
                raise CleanupRejectedError("declared inventory contains a hard link")
            total_bytes += before.st_size
            if total_bytes > 64 * 1024 * 1024:
                raise CleanupRejectedError("declared inventory exceeds its byte bounds")
            descriptor = os.open(candidate, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(descriptor, "rb") as stream:
                if snapshot(os.fstat(stream.fileno())) != snapshot(before):
                    raise CleanupRejectedError("declared inventory changed while opening")
                digest = hashlib.sha256()
                remaining = before.st_size
                while chunk := stream.read(min(1024 * 1024, remaining + 1)):
                    remaining -= len(chunk)
                    if remaining < 0:
                        raise CleanupRejectedError("declared inventory grew while reading")
                    digest.update(chunk)
                if remaining or snapshot(os.fstat(stream.fileno())) != snapshot(before):
                    raise CleanupRejectedError("declared inventory changed while reading")
            content = digest.hexdigest()
        elif stat.S_ISDIR(before.st_mode):
            content = "directory"
            with os.scandir(candidate) as children:
                names = []
                for child in children:
                    names.append(child.name)
                    if len(names) + len(inventory) > 1024:
                        raise CleanupRejectedError("declared inventory exceeds its bounds")
            for name in sorted(names):
                visit(candidate / name, depth + 1)
        else:
            raise CleanupRejectedError("declared inventory contains a special file")
        if snapshot(candidate.lstat()) != snapshot(before):
            raise CleanupRejectedError("declared inventory changed while reading")
        inventory.append(
            [
                candidate.relative_to(path).as_posix(),
                int(before.st_dev),
                int(before.st_ino),
                int(before.st_mode),
                int(before.st_size),
                int(before.st_mtime_ns),
                int(before.st_ctime_ns),
                content,
            ]
        )
        return content

    content = visit(path, 0)
    if stat.S_ISDIR(initial.st_mode):
        content = hashlib.sha256(
            json.dumps(
                inventory,
                ensure_ascii=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
    return {
        "device": int(initial.st_dev),
        "inode": int(initial.st_ino),
        "mode": int(initial.st_mode),
        "size": int(initial.st_size),
        "mtime_ns": int(initial.st_mtime_ns),
        "ctime_ns": int(initial.st_ctime_ns),
        "content_digest": content,
    }


def _receipt_result(receipt: QuarantineReceipt, *, plan_id: str | None = None) -> dict[str, object]:
    success = receipt.result in {
        QuarantineResult.QUARANTINED,
        QuarantineResult.RESTORED,
        QuarantineResult.ALREADY_RESTORED,
    }
    uncertain = receipt.result in {QuarantineResult.INTERRUPTED, QuarantineResult.PARTIAL}
    return {
        "receipt_id": receipt.receipt_id,
        "plan_id": plan_id or receipt.plan_id,
        "kind": "quarantine",
        "outcome": receipt.result.value,
        "certainty": "verified" if success else "uncertain" if uncertain else "failed_before_issue",
        "action_issued": (
            False
            if receipt.result is QuarantineResult.ALREADY_RESTORED
            else True
            if success
            else None
            if uncertain
            else False
        ),
        "partial_failures": [] if success else [receipt.message],
        "created_at": receipt.finished_at.isoformat().replace("+00:00", "Z"),
    }


class CleanupWorkflow:
    def __init__(
        self,
        store: SQLiteStateStore,
        paths: AppPaths,
        *,
        current_user: str,
        clock: Callable[[], datetime] | None = None,
        retention_days: int = 30,
    ) -> None:
        self._store = store
        self._paths = paths
        self._current_user = current_user
        self._clock = clock or (lambda: datetime.now(UTC))
        self._retention = timedelta(days=retention_days)

    def _registration(
        self,
        agent_id: str,
        *,
        expected_pid: int | None = None,
        expected_process_instance_id: str | None = None,
    ) -> LeaseDocument:
        try:
            document = read_resource_registration(self._paths.leases_dir, agent_id)
        except (OSError, ValueError, OverflowError) as error:
            raise CleanupRejectedError("exact resource registration is unavailable") from error
        if not is_current_user(document.lease.identity.user, self._current_user):
            raise CleanupRejectedError("resource registration is outside the current user")
        if (
            not document.lease.registration_nonce
            or not document.lease.identity.executable
            or not document.lease.identity.user
        ):
            raise CleanupRejectedError("resource registration identity is incomplete")
        if (expected_pid is None) != (expected_process_instance_id is None):
            raise CleanupRejectedError(
                "expected resource process identity must be supplied together"
            )
        if expected_pid is not None and (
            isinstance(expected_pid, bool)
            or not isinstance(expected_pid, int)
            or expected_pid != document.lease.identity.pid
            or not isinstance(expected_process_instance_id, str)
            or len(expected_process_instance_id) != 64
            or any(
                character not in "0123456789abcdef" for character in expected_process_instance_id
            )
            or not secrets.compare_digest(
                process_instance_id(document.lease.identity), expected_process_instance_id
            )
        ):
            raise CleanupRejectedError("expected resource process identity changed")
        return document

    @staticmethod
    def _resource(document: LeaseDocument, index: int) -> DeclaredResource:
        if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < 64:
            raise CleanupRejectedError("resource index must be between zero and sixty-three")
        if index >= len(document.resources):
            raise CleanupRejectedError("resource index is not declared")
        resource = document.resources[index]
        if (
            resource.approved_root is None
            or resource.creation_fingerprint is None
            or resource.resource_type is None
            or resource.cleanup_policy != "quarantine"
        ):
            raise CleanupRejectedError("legacy path-only resource has no cleanup authority")
        return resource

    @staticmethod
    def _match_creation(resource: DeclaredResource) -> None:
        assert resource.creation_fingerprint is not None
        try:
            actual = _creation_fingerprint(Path(resource.path))
        except (OSError, ValueError) as error:
            raise CleanupRejectedError("declared resource cannot be inspected safely") from error
        if actual != resource.creation_fingerprint.model_dump(mode="json"):
            raise CleanupRejectedError("declared resource changed since registration")

    def _manifest(self, document: LeaseDocument, resource: DeclaredResource) -> CleanupManifest:
        assert resource.approved_root is not None and resource.resource_type is not None
        return CleanupManifest.create(
            agent_id=document.lease.agent_id,
            creating_identity=document.lease.identity,
            approved_root=resource.approved_root,
            target=resource.path,
            resource_type=ResourceType(resource.resource_type),
            declaration_source="sdk",
            managed=True,
            created_at=self._clock(),
        )

    @staticmethod
    def _declaration_digest(
        document: LeaseDocument, resource_index: int, resource: DeclaredResource
    ) -> str:
        return _digest(
            {
                "version": "sdk-resource-selection-v1",
                "agent_id": document.lease.agent_id,
                "creating_identity": document.lease.identity.model_dump(mode="json"),
                "registration_nonce": document.lease.registration_nonce,
                "resource_index": resource_index,
                "declaration": resource.model_dump(mode="json"),
            }
        )

    def list_resources(
        self,
        agent_id: str,
        *,
        expected_pid: int | None = None,
        expected_process_instance_id: str | None = None,
    ) -> dict[str, object]:
        document = self._registration(
            agent_id,
            expected_pid=expected_pid,
            expected_process_instance_id=expected_process_instance_id,
        )
        resources: list[dict[str, object]] = []
        for index, candidate in enumerate(document.resources):
            available = False
            declaration_digest = None
            reason = "Resource has no complete declaration for cleanup."
            try:
                resource = self._resource(document, index)
                self._match_creation(resource)
                manifest = self._manifest(document, resource)
                expected_authority = _authority_from_manifest(manifest)
                assert resource.approved_root is not None
                QuarantinePlanner(
                    (resource.approved_root,),
                    registration_resolver=lambda authority, expected=expected_authority: (
                        authority == expected
                    ),
                    clock=self._clock,
                ).create_plan(manifest)
                available = True
                declaration_digest = self._declaration_digest(document, index, resource)
                reason = "Declared temporary resource is available for quarantine review."
            except (CleanupRejectedError, OSError, ValueError):
                reason = "Declaration is incomplete, changed, or unavailable for safe cleanup."
            resources.append(
                {
                    "resource_index": index,
                    "kind": "temporary",
                    "resource_type": candidate.resource_type or "unknown",
                    "cleanup_available": available,
                    "declaration_digest": declaration_digest,
                    "reason": reason,
                }
            )
        return {"agent_id": agent_id, "resources": resources, "returned": len(resources)}

    def _resolve(self, authority: CleanupAuthority, *, current_registration: bool = True) -> bool:
        try:
            payload = self._store.get_workflow_plan(_AUTHORITY_KIND, authority.manifest_id)
            if payload is None:
                return False
            manifest = CleanupManifest.model_validate_json(json.dumps(payload["manifest"]))
            if authority != _authority_from_manifest(manifest):
                return False
            if not is_current_user(manifest.creating_identity.user, self._current_user):
                return False
            if not current_registration:
                return True
            document = self._registration(manifest.agent_id)
            if (
                document.lease.identity != manifest.creating_identity
                or document.lease.registration_nonce != payload["registration_nonce"]
            ):
                return False
            index = cast(int, payload["resource_index"])
            resource = self._resource(document, index)
            # Execution revalidates the retained native plan fingerprint with
            # pinned handles. Reopening a Windows DELETE-pinned file via the
            # CRT would incorrectly reject it because CRT sharing omits DELETE.
            return bool(resource.model_dump(mode="json") == payload["declaration"])
        except (OSError, ValueError, KeyError, TypeError):
            return False

    def plan(
        self,
        agent_id: str,
        resource_index: int,
        *,
        expected_declaration_digest: str,
        expected_pid: int | None = None,
        expected_process_instance_id: str | None = None,
    ) -> dict[str, object]:
        document = self._registration(
            agent_id,
            expected_pid=expected_pid,
            expected_process_instance_id=expected_process_instance_id,
        )
        resource = self._resource(document, resource_index)
        if (
            not isinstance(expected_declaration_digest, str)
            or len(expected_declaration_digest) != 64
            or any(character not in "0123456789abcdef" for character in expected_declaration_digest)
            or not secrets.compare_digest(
                self._declaration_digest(document, resource_index, resource),
                expected_declaration_digest,
            )
        ):
            raise CleanupRejectedError("reviewed resource declaration changed or is unavailable")
        self._match_creation(resource)
        manifest = self._manifest(document, resource)
        self._store.save_workflow_plan(
            _AUTHORITY_KIND,
            manifest.manifest_id,
            manifest.digest,
            {
                "manifest": manifest.model_dump(mode="json"),
                "registration_nonce": document.lease.registration_nonce,
                "resource_index": resource_index,
                "declaration": resource.model_dump(mode="json"),
            },
            expires_at=manifest.expires_at,
        )
        assert resource.approved_root is not None
        plan = QuarantinePlanner(
            (resource.approved_root,),
            registration_resolver=self._resolve,
            clock=self._clock,
        ).create_plan(manifest)
        self._match_creation(resource)
        self._store.save_quarantine_plan(plan)
        return {
            "plan_id": plan.plan_id,
            "digest": plan.digest,
            "expires_at": plan.expires_at.isoformat().replace("+00:00", "Z"),
            "consequences": ("Move this exact declared resource into the per-user Graveyard.",),
            "warnings": ("Restore refuses to replace an existing destination.",),
        }

    def _executor(
        self,
        *,
        restore: bool = False,
        expires_at: datetime | None = None,
    ) -> QuarantineExecutor:
        return QuarantineExecutor(
            self._store,
            self._paths,
            actor="local-controller",
            clock=self._clock,
            registration_resolver=lambda authority: (
                self._resolve(
                    authority,
                    current_registration=not restore,
                )
                and (expires_at is None or self._clock() < expires_at)
            ),
            retention=self._retention,
            restore_expires_at=expires_at,
        )

    def execute(self, plan_id: str, digest: str) -> dict[str, object]:
        return _receipt_result(self._executor().execute(plan_id, expected_digest=digest))

    def restore_plan(self, entry_id: str) -> dict[str, object]:
        entry = self._store.get_quarantine_entry(entry_id)
        if entry is None or entry.state is not QuarantineState.SUCCEEDED:
            raise CleanupRejectedError("quarantine entry is unavailable for restore")
        if not is_current_user(entry.creating_identity.user, self._current_user):
            raise CleanupRejectedError("quarantine entry belongs to a different user")
        legacy_restore_only = self._store.get_legacy_quarantine_reason(entry.plan_id) is not None
        if legacy_restore_only:
            try:
                self._store.get_legacy_restore_plan(entry_id, expected_entry_digest=entry.digest)
            except StoreError as error:
                raise CleanupRejectedError("legacy restore evidence is unavailable") from error
        else:
            domain_plan = self._store.get_quarantine_plan(entry.plan_id)
            if domain_plan is None or not self._resolve(
                CleanupAuthority(
                    manifest_id=domain_plan.manifest_id,
                    manifest_digest=domain_plan.manifest_digest,
                    agent_id=domain_plan.agent_id,
                    creating_identity=domain_plan.creating_identity,
                    approved_root=domain_plan.approved_root,
                    target=domain_plan.target,
                    resource_type=domain_plan.resource_type,
                    declaration_source=domain_plan.declaration_source,
                    cleanup_policy=domain_plan.cleanup_policy,
                    created_at=domain_plan.manifest_created_at,
                    expires_at=domain_plan.manifest_expires_at,
                ),
                current_registration=False,
            ):
                raise CleanupRejectedError("preserved cleanup authority is unavailable")
        created_at = self._clock()
        plan_id = secrets.token_urlsafe(24)
        expires_at = created_at + _LIFETIME
        payload: dict[str, object] = {
            "plan_id": plan_id,
            "entry_id": entry_id,
            "entry_digest": entry.digest,
            "legacy_restore_only": legacy_restore_only,
            "created_at": created_at.isoformat(),
            "expires_at": expires_at.isoformat(),
        }
        digest = _digest(payload)
        payload["digest"] = digest
        self._store.save_workflow_plan(
            _RESTORE_KIND,
            plan_id,
            digest,
            payload,
            expires_at=expires_at,
        )
        return {
            "plan_id": plan_id,
            "digest": digest,
            "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
            "consequences": ("Restore this Graveyard entry to its exact original location.",),
            "warnings": ("An existing destination will be preserved and restore will fail.",),
        }

    def restore_execute(self, plan_id: str, digest: str) -> dict[str, object]:
        payload = self._store.get_workflow_plan(_RESTORE_KIND, plan_id)
        if payload is None or payload.get("digest") != digest:
            raise PlanClaimError("restore plan digest did not match")
        unsigned = {key: value for key, value in payload.items() if key != "digest"}
        if not secrets.compare_digest(_digest(unsigned), digest):
            raise PlanClaimError("restore plan authority changed")
        existing = self._store.get_workflow_receipt(_RESTORE_KIND, plan_id)
        if existing is not None:
            return existing
        claimed = self._store.claim_workflow_plan(
            _RESTORE_KIND,
            plan_id,
            expected_digest=digest,
            reconcile=True,
        )
        entry_id = cast(str, claimed["entry_id"])
        entry = self._store.get_quarantine_entry(entry_id)
        if entry is None or entry.digest != claimed["entry_digest"]:
            raise PlanClaimError("reviewed restore entry changed")
        expires_at = datetime.fromisoformat(cast(str, claimed["expires_at"]))
        executor = self._executor(restore=True, expires_at=expires_at)
        receipt = (
            executor.restore_legacy(entry_id, expected_entry_digest=entry.digest)
            if claimed.get("legacy_restore_only") is True
            else executor.restore(entry_id)
        )
        result = _receipt_result(receipt, plan_id=plan_id)
        self._store.finish_workflow_plan(_RESTORE_KIND, plan_id, result)
        return result
