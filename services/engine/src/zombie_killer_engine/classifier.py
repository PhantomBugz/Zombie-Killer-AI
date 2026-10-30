"""Pure, deterministic classification of agent lifecycle evidence."""

from __future__ import annotations

from datetime import UTC, datetime
from math import isfinite

from zombie_killer_engine.models import (
    AgentRecord,
    AgentState,
    Classification,
    Evidence,
    EvidenceGrade,
    ProcessIdentity,
)


def _classification(
    *,
    state: AgentState,
    grade: EvidenceGrade,
    confidence: float,
    reason_codes: tuple[str, ...],
    explanation: str,
    evidence: tuple[Evidence, ...],
    now: datetime,
) -> Classification:
    return Classification(
        state=state,
        evidence_grade=grade,
        confidence=confidence,
        reason_codes=reason_codes,
        explanation=explanation,
        evidence=evidence,
        classified_at=now,
    )


def _identities_match(
    lease_identity: ProcessIdentity, snapshot_identity: ProcessIdentity | None
) -> bool:
    if snapshot_identity is None:
        return False
    if (
        lease_identity.boot_id,
        lease_identity.pid,
        lease_identity.create_time,
    ) != (
        snapshot_identity.boot_id,
        snapshot_identity.pid,
        snapshot_identity.create_time,
    ):
        return False
    return all(
        lease_value is None or snapshot_value is None or lease_value == snapshot_value
        for lease_value, snapshot_value in (
            (lease_identity.executable, snapshot_identity.executable),
            (lease_identity.user, snapshot_identity.user),
        )
    )


def _unknown_for_contradiction(
    *,
    code: str,
    detail: str,
    explanation: str,
    observed_at: datetime,
    now: datetime,
) -> Classification:
    evidence = Evidence(
        code=code,
        grade=EvidenceGrade.INSUFFICIENT,
        observed_at=observed_at,
        detail=detail,
    )
    return _classification(
        state=AgentState.UNKNOWN,
        grade=EvidenceGrade.INSUFFICIENT,
        confidence=0.0,
        reason_codes=(code,),
        explanation=explanation,
        evidence=(evidence,),
        now=now,
    )


def classify(
    record: AgentRecord,
    *,
    now: datetime | None = None,
    max_future_skew_seconds: float = 5.0,
    max_snapshot_age_seconds: float = 300.0,
    current_boot_id: str | None = None,
) -> Classification:
    """Classify an agent record without reading external state."""
    if not isfinite(max_future_skew_seconds) or max_future_skew_seconds < 0:
        raise ValueError("max_future_skew_seconds must be finite and non-negative")
    if not isfinite(max_snapshot_age_seconds) or max_snapshot_age_seconds <= 0:
        raise ValueError("max_snapshot_age_seconds must be finite and positive")
    classified_at = now or datetime.now(UTC)
    if classified_at.tzinfo is None or classified_at.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    classified_at = classified_at.astimezone(UTC)
    if current_boot_id is not None:
        current_boot_id = current_boot_id.strip()
        if not current_boot_id or len(current_boot_id) > 256:
            raise ValueError("current_boot_id must be non-empty and at most 256 characters")
    if (
        current_boot_id is not None
        and record.current_boot_id is not None
        and current_boot_id != record.current_boot_id
    ):
        evidence = Evidence(
            code="CURRENT_BOOT_ID_MISMATCH",
            grade=EvidenceGrade.INSUFFICIENT,
            observed_at=classified_at,
            detail="The explicit current boot ID conflicts with the record boot ID.",
        )
        return _classification(
            state=AgentState.UNKNOWN,
            grade=EvidenceGrade.INSUFFICIENT,
            confidence=0.0,
            reason_codes=("CURRENT_BOOT_ID_MISMATCH",),
            explanation="Conflicting current-boot evidence prevents classification.",
            evidence=(evidence,),
            now=classified_at,
        )
    resolved_current_boot_id = current_boot_id or record.current_boot_id
    process = record.process
    lease = record.lease

    if (
        process is not None
        and (process.observed_at - classified_at).total_seconds() > max_future_skew_seconds
    ):
        return _unknown_for_contradiction(
            code="SNAPSHOT_OBSERVED_IN_FUTURE",
            detail="The process snapshot timestamp exceeds the allowed clock-skew window.",
            explanation="Future-dated process evidence prevents classification.",
            observed_at=process.observed_at,
            now=classified_at,
        )
    if (
        process is not None
        and (classified_at - process.observed_at).total_seconds() > max_snapshot_age_seconds
    ):
        return _unknown_for_contradiction(
            code="PROCESS_SNAPSHOT_TOO_OLD",
            detail="The process snapshot exceeds the configured freshness window.",
            explanation="Stale process evidence cannot support a current lifecycle state.",
            observed_at=process.observed_at,
            now=classified_at,
        )
    if process is not None and process.identity is not None:
        if process.identity.create_time - classified_at.timestamp() > max_future_skew_seconds:
            return _unknown_for_contradiction(
                code="PROCESS_CREATED_IN_FUTURE",
                detail="The process creation time is beyond the allowed clock-skew window.",
                explanation="Future-dated process creation evidence prevents classification.",
                observed_at=process.observed_at,
                now=classified_at,
            )
        if process.identity.create_time - process.observed_at.timestamp() > max_future_skew_seconds:
            return _unknown_for_contradiction(
                code="PROCESS_CREATED_AFTER_OBSERVATION",
                detail="The claimed process creation time occurs after its snapshot.",
                explanation="Contradictory process chronology prevents classification.",
                observed_at=process.observed_at,
                now=classified_at,
            )
    if lease is not None:
        if (lease.heartbeat_at - classified_at).total_seconds() > max_future_skew_seconds:
            return _unknown_for_contradiction(
                code="HEARTBEAT_IN_FUTURE",
                detail="The heartbeat timestamp exceeds the allowed clock-skew window.",
                explanation="Future-dated heartbeat evidence prevents classification.",
                observed_at=lease.heartbeat_at,
                now=classified_at,
            )
        if lease.identity.create_time - lease.heartbeat_at.timestamp() > max_future_skew_seconds:
            return _unknown_for_contradiction(
                code="HEARTBEAT_BEFORE_PROCESS_CREATION",
                detail="The heartbeat predates its claimed process creation time.",
                explanation="Contradictory lease chronology prevents classification.",
                observed_at=lease.heartbeat_at,
                now=classified_at,
            )

    if (
        process is not None
        and process.process_present
        and process.identity is not None
        and resolved_current_boot_id is not None
        and process.identity.boot_id != resolved_current_boot_id
    ):
        evidence = Evidence(
            code="LIVE_PROCESS_PREVIOUS_BOOT",
            grade=EvidenceGrade.INSUFFICIENT,
            observed_at=process.observed_at,
            detail="A live snapshot claims a boot ID other than the current boot.",
        )
        return _classification(
            state=AgentState.UNKNOWN,
            grade=EvidenceGrade.INSUFFICIENT,
            confidence=0.0,
            reason_codes=("LIVE_PROCESS_PREVIOUS_BOOT",),
            explanation="Contradictory process boot evidence prevents classification.",
            evidence=(evidence,),
            now=classified_at,
        )

    if process is not None and process.process_present and process.os_status.lower() == "zombie":
        evidence = Evidence(
            code="OS_ZOMBIE",
            grade=EvidenceGrade.CONFIRMED,
            observed_at=process.observed_at,
            detail="The operating system reports a true POSIX zombie process.",
        )
        return _classification(
            state=AgentState.DEFUNCT,
            grade=EvidenceGrade.CONFIRMED,
            confidence=1.0,
            reason_codes=("OS_ZOMBIE",),
            explanation="The process is defunct; it has exited and awaits parent reaping.",
            evidence=(evidence,),
            now=classified_at,
        )

    if (
        lease is not None
        and lease.terminal_at is not None
        and lease.declared_state in {AgentState.COMPLETED, AgentState.FAILED, AgentState.CANCELLED}
    ):
        code = f"TERMINAL_{lease.declared_state.value.upper()}"
        evidence = Evidence(
            code=code,
            grade=EvidenceGrade.CONFIRMED,
            observed_at=lease.terminal_at,
            detail="The managed lease records a terminal workload lifecycle.",
        )
        return _classification(
            state=lease.declared_state,
            grade=EvidenceGrade.CONFIRMED,
            confidence=0.99,
            reason_codes=(code,),
            explanation="The workload is retained as non-actionable terminal history.",
            evidence=(evidence,),
            now=classified_at,
        )

    if process is not None and not process.visibility_complete:
        evidence = Evidence(
            code="PROCESS_VISIBILITY_INCOMPLETE",
            grade=EvidenceGrade.INSUFFICIENT,
            observed_at=process.observed_at,
            detail="Process evidence is incomplete because visibility or permissions are limited.",
        )
        return _classification(
            state=AgentState.UNKNOWN,
            grade=EvidenceGrade.INSUFFICIENT,
            confidence=0.1,
            reason_codes=("PROCESS_VISIBILITY_INCOMPLETE",),
            explanation="Permissions or visibility are insufficient to classify this process.",
            evidence=(evidence,),
            now=classified_at,
        )

    if (
        lease is None
        and process is not None
        and process.process_present
        and process.signature_matched
    ):
        evidence = Evidence(
            code="SIGNATURE_MATCH_ONLY",
            grade=EvidenceGrade.SIGNATURE_ONLY,
            observed_at=process.observed_at,
            detail="A tooling signature matched, but no managed lease confirms an agent.",
        )
        return _classification(
            state=AgentState.UNMANAGED,
            grade=EvidenceGrade.SIGNATURE_ONLY,
            confidence=0.4,
            reason_codes=("SIGNATURE_MATCH_ONLY",),
            explanation="The process is an unmanaged candidate based only on a signature match.",
            evidence=(evidence,),
            now=classified_at,
        )

    matching_live_process = (
        lease is not None
        and process is not None
        and process.process_present
        and _identities_match(lease.identity, process.identity)
    )
    if (
        lease is not None
        and resolved_current_boot_id is not None
        and lease.identity.boot_id != resolved_current_boot_id
        and not matching_live_process
    ):
        evidence = Evidence(
            code="PREVIOUS_BOOT_LEASE",
            grade=EvidenceGrade.CONFIRMED,
            observed_at=lease.heartbeat_at,
            detail="The managed lease belongs to a previous operating-system boot.",
        )
        return _classification(
            state=AgentState.INTERRUPTED,
            grade=EvidenceGrade.CONFIRMED,
            confidence=0.99,
            reason_codes=("PREVIOUS_BOOT_LEASE", "NO_MATCHING_LIVE_PROCESS"),
            explanation="A previous-boot lease has no matching live process.",
            evidence=(evidence,),
            now=classified_at,
        )

    if (
        lease is not None
        and process is not None
        and process.process_present
        and not matching_live_process
    ):
        evidence = Evidence(
            code="PROCESS_IDENTITY_MISMATCH",
            grade=EvidenceGrade.INSUFFICIENT,
            observed_at=process.observed_at,
            detail="The live process identity does not match the managed lease identity.",
        )
        return _classification(
            state=AgentState.UNKNOWN,
            grade=EvidenceGrade.INSUFFICIENT,
            confidence=0.05,
            reason_codes=("PROCESS_IDENTITY_MISMATCH",),
            explanation="The lease cannot be applied to a different process instance.",
            evidence=(evidence,),
            now=classified_at,
        )

    if record.control_unresponsive and matching_live_process and process is not None:
        evidence = Evidence(
            code="CONTROL_UNRESPONSIVE",
            grade=EvidenceGrade.STRONG,
            observed_at=process.observed_at,
            detail="Cooperative control requests are repeatedly unanswered.",
        )
        return _classification(
            state=AgentState.UNRESPONSIVE,
            grade=EvidenceGrade.STRONG,
            confidence=0.9,
            reason_codes=("CONTROL_UNRESPONSIVE",),
            explanation="The managed process is live but cooperative control is unresponsive.",
            evidence=(evidence,),
            now=classified_at,
        )

    if lease is not None and process is not None and process.process_present:
        future_seconds = (lease.heartbeat_at - classified_at).total_seconds()
        tolerated_skew = future_seconds > 0
        elapsed_seconds = (classified_at - lease.heartbeat_at).total_seconds()
        expired = elapsed_seconds >= lease.heartbeat_timeout_seconds
        heartbeat = Evidence(
            code="HEARTBEAT_EXPIRED" if expired else "HEARTBEAT_RECENT",
            grade=EvidenceGrade.STRONG if expired else EvidenceGrade.CONFIRMED,
            observed_at=lease.heartbeat_at,
            detail="The managed heartbeat lease is expired."
            if expired
            else "The managed heartbeat lease is recent.",
        )
        parent_absent = lease.expected_parent_pid is not None and process.parent_alive is False
        owner_absent = lease.expected_owner is not None and process.owner_alive is False
        if expired and not lease.detached and (parent_absent or owner_absent):
            absent_code = "EXPECTED_PARENT_ABSENT" if parent_absent else "EXPECTED_OWNER_ABSENT"
            absent_evidence = Evidence(
                code=absent_code,
                grade=EvidenceGrade.CONFIRMED,
                observed_at=process.observed_at,
                detail="The expected process parent or owner is confirmed absent.",
            )
            return _classification(
                state=AgentState.ORPHANED,
                grade=EvidenceGrade.CONFIRMED,
                confidence=0.98,
                reason_codes=("HEARTBEAT_EXPIRED", absent_code),
                explanation=(
                    "The managed lease expired and its expected parent or owner is "
                    "confirmed absent; detached execution was not declared."
                ),
                evidence=(heartbeat, absent_evidence),
                now=classified_at,
            )
        if expired:
            return _classification(
                state=AgentState.STALE,
                grade=EvidenceGrade.STRONG,
                confidence=0.9,
                reason_codes=("HEARTBEAT_EXPIRED",),
                explanation="The managed lease expired while the process remains alive.",
                evidence=(heartbeat,),
                now=classified_at,
            )
        if lease.declared_state is AgentState.IDLE:
            reasons: tuple[str, ...] = ("HEARTBEAT_RECENT", "DECLARED_IDLE")
            if tolerated_skew:
                reasons += ("CLOCK_SKEW_TOLERATED",)
            return _classification(
                state=AgentState.IDLE,
                grade=EvidenceGrade.CONFIRMED,
                confidence=0.99,
                reason_codes=reasons,
                explanation="The managed heartbeat is recent and the agent declared itself idle.",
                evidence=(heartbeat,),
                now=classified_at,
            )
        reasons = ("HEARTBEAT_RECENT",)
        if tolerated_skew:
            reasons += ("CLOCK_SKEW_TOLERATED",)
        return _classification(
            state=AgentState.HEALTHY,
            grade=EvidenceGrade.CONFIRMED,
            confidence=0.99,
            reason_codes=reasons,
            explanation="The managed process identity is live and its heartbeat is recent.",
            evidence=(heartbeat,),
            now=classified_at,
        )

    evidence_at = process.observed_at if process is not None else classified_at
    evidence = Evidence(
        code="INSUFFICIENT_EVIDENCE",
        grade=EvidenceGrade.INSUFFICIENT,
        observed_at=evidence_at,
        detail="Available evidence is insufficient for a lifecycle decision.",
    )
    return _classification(
        state=AgentState.UNKNOWN,
        grade=EvidenceGrade.INSUFFICIENT,
        confidence=0.0,
        reason_codes=("INSUFFICIENT_EVIDENCE",),
        explanation="The available process or lease evidence is insufficient.",
        evidence=(evidence,),
        now=classified_at,
    )
