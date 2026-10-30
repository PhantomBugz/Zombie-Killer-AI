from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from zombie_killer_engine.classifier import classify
from zombie_killer_engine.models import (
    AgentRecord,
    AgentState,
    Classification,
    Evidence,
    EvidenceGrade,
    Lease,
    ProcessIdentity,
    ProcessSnapshot,
)

NOW = datetime(2026, 8, 12, 12, 0, tzinfo=UTC)
IDENTITY = ProcessIdentity(
    boot_id="synthetic-boot-current",
    pid=4242,
    create_time=1_786_532_300.0,
    executable="/synthetic/bin/agent",
    user="synthetic-user",
)


def record(
    *,
    heartbeat_age_seconds: int,
    parent_alive: bool | None,
    detached: bool,
    os_status: str,
) -> AgentRecord:
    return AgentRecord(
        current_boot_id="synthetic-boot-current",
        lease=Lease(
            agent_id="synthetic-agent",
            identity=IDENTITY,
            heartbeat_at=NOW - timedelta(seconds=heartbeat_age_seconds),
            heartbeat_timeout_seconds=15,
            expected_parent_pid=100,
            detached=detached,
        ),
        process=ProcessSnapshot(
            identity=IDENTITY,
            observed_at=NOW,
            process_present=True,
            os_status=os_status,
            parent_alive=parent_alive,
        ),
    )


@pytest.mark.parametrize(
    ("heartbeat_age_seconds", "parent_alive", "detached", "os_status", "expected"),
    [
        (2, True, False, "running", AgentState.HEALTHY),
        (30, True, False, "running", AgentState.STALE),
        (30, False, False, "running", AgentState.ORPHANED),
        (30, False, True, "running", AgentState.STALE),
        (2, True, False, "zombie", AgentState.DEFUNCT),
    ],
)
def test_classification_is_evidence_based(
    heartbeat_age_seconds: int,
    parent_alive: bool,
    detached: bool,
    os_status: str,
    expected: AgentState,
) -> None:
    result = classify(
        record(
            heartbeat_age_seconds=heartbeat_age_seconds,
            parent_alive=parent_alive,
            detached=detached,
            os_status=os_status,
        ),
        now=NOW,
    )

    assert result.state is expected
    assert result.reason_codes
    assert result.explanation
    assert result.evidence
    assert all(item.observed_at.tzinfo is not None for item in result.evidence)


def test_recent_managed_heartbeat_honors_explicit_idle_state() -> None:
    candidate = record(
        heartbeat_age_seconds=2,
        parent_alive=True,
        detached=False,
        os_status="running",
    )
    assert candidate.lease is not None
    candidate = candidate.model_copy(
        update={"lease": candidate.lease.model_copy(update={"declared_state": AgentState.IDLE})}
    )

    result = classify(candidate, now=NOW)

    assert result.state is AgentState.IDLE
    assert "DECLARED_IDLE" in result.reason_codes


def test_signature_only_candidate_stays_unmanaged_and_unconfirmed() -> None:
    candidate = AgentRecord(
        current_boot_id="synthetic-boot-current",
        process=ProcessSnapshot(
            identity=IDENTITY,
            observed_at=NOW,
            process_present=True,
            os_status="running",
            signature_matched=True,
        ),
    )

    result = classify(candidate, now=NOW)

    assert result.state is AgentState.UNMANAGED
    assert result.evidence_grade is EvidenceGrade.SIGNATURE_ONLY
    assert result.confidence < 1.0
    assert all(item.grade is not EvidenceGrade.CONFIRMED for item in result.evidence)


def test_absent_signature_snapshot_is_not_an_unmanaged_candidate() -> None:
    candidate = AgentRecord(
        current_boot_id="synthetic-boot-current",
        process=ProcessSnapshot(
            identity=None,
            observed_at=NOW,
            process_present=False,
            os_status="not-found",
            signature_matched=True,
        ),
    )

    result = classify(candidate, now=NOW)

    assert result.state is AgentState.UNKNOWN
    assert result.state is not AgentState.UNMANAGED


def test_signature_only_candidate_with_incomplete_visibility_is_unknown() -> None:
    candidate = AgentRecord(
        current_boot_id="synthetic-boot-current",
        process=ProcessSnapshot(
            identity=IDENTITY,
            observed_at=NOW,
            process_present=True,
            os_status="access-denied",
            visibility_complete=False,
            signature_matched=True,
        ),
    )

    result = classify(candidate, now=NOW)

    assert result.state is AgentState.UNKNOWN
    assert result.reason_codes == ("PROCESS_VISIBILITY_INCOMPLETE",)


def test_previous_boot_lease_without_live_process_is_interrupted() -> None:
    candidate = AgentRecord(
        current_boot_id="synthetic-boot-current",
        lease=Lease(
            agent_id="synthetic-agent",
            identity=IDENTITY.model_copy(update={"boot_id": "synthetic-boot-previous"}),
            heartbeat_at=NOW - timedelta(hours=1),
            heartbeat_timeout_seconds=15,
        ),
        process=None,
    )

    result = classify(candidate, now=NOW)

    assert result.state is AgentState.INTERRUPTED
    assert result.evidence_grade is EvidenceGrade.CONFIRMED
    assert result.reason_codes == ("PREVIOUS_BOOT_LEASE", "NO_MATCHING_LIVE_PROCESS")


def test_previous_boot_lease_needs_complete_visibility_before_interrupted() -> None:
    candidate = AgentRecord(
        current_boot_id="synthetic-boot-current",
        lease=Lease(
            agent_id="synthetic-agent",
            identity=IDENTITY.model_copy(update={"boot_id": "synthetic-boot-previous"}),
            heartbeat_at=NOW - timedelta(hours=1),
            heartbeat_timeout_seconds=15,
        ),
        process=ProcessSnapshot(
            identity=None,
            observed_at=NOW,
            process_present=False,
            os_status="access-denied",
            visibility_complete=False,
        ),
    )

    result = classify(candidate, now=NOW)

    assert result.state is AgentState.UNKNOWN
    assert result.reason_codes == ("PROCESS_VISIBILITY_INCOMPLETE",)


def test_incomplete_process_visibility_is_unknown() -> None:
    candidate = record(
        heartbeat_age_seconds=2,
        parent_alive=True,
        detached=False,
        os_status="access-denied",
    )
    assert candidate.process is not None
    candidate = candidate.model_copy(
        update={"process": candidate.process.model_copy(update={"visibility_complete": False})}
    )

    result = classify(candidate, now=NOW)

    assert result.state is AgentState.UNKNOWN
    assert result.evidence_grade is EvidenceGrade.INSUFFICIENT
    assert result.reason_codes == ("PROCESS_VISIBILITY_INCOMPLETE",)


def test_managed_lease_requires_matching_process_identity() -> None:
    candidate = record(
        heartbeat_age_seconds=2,
        parent_alive=True,
        detached=False,
        os_status="running",
    )
    assert candidate.process is not None
    assert candidate.process.identity is not None
    candidate = candidate.model_copy(
        update={
            "process": candidate.process.model_copy(
                update={"identity": candidate.process.identity.model_copy(update={"pid": 4343})}
            )
        }
    )

    result = classify(candidate, now=NOW)

    assert result.state is AgentState.UNKNOWN
    assert result.reason_codes == ("PROCESS_IDENTITY_MISMATCH",)


def test_enriched_snapshot_matches_less_enriched_lease_identity() -> None:
    candidate = record(
        heartbeat_age_seconds=2,
        parent_alive=True,
        detached=False,
        os_status="running",
    )
    assert candidate.lease is not None
    candidate = candidate.model_copy(
        update={
            "lease": candidate.lease.model_copy(
                update={
                    "identity": candidate.lease.identity.model_copy(
                        update={"executable": None, "user": None}
                    )
                }
            )
        }
    )

    result = classify(candidate, now=NOW)

    assert result.state is AgentState.HEALTHY
    assert "PROCESS_IDENTITY_MISMATCH" not in result.reason_codes


@pytest.mark.parametrize(
    "snapshot_identity",
    [
        IDENTITY.model_copy(update={"executable": "/synthetic/bin/different"}),
        IDENTITY.model_copy(update={"user": "different-user"}),
    ],
)
def test_conflicting_present_optional_identity_fields_reject_match(
    snapshot_identity: ProcessIdentity,
) -> None:
    candidate = record(
        heartbeat_age_seconds=2,
        parent_alive=True,
        detached=False,
        os_status="running",
    )
    assert candidate.process is not None
    candidate = candidate.model_copy(
        update={"process": candidate.process.model_copy(update={"identity": snapshot_identity})}
    )

    result = classify(candidate, now=NOW)

    assert result.state is AgentState.UNKNOWN
    assert result.reason_codes == ("PROCESS_IDENTITY_MISMATCH",)


@pytest.mark.parametrize(
    ("future_seconds", "expected", "reason_code"),
    [
        (4, AgentState.HEALTHY, "CLOCK_SKEW_TOLERATED"),
        (6, AgentState.UNKNOWN, "HEARTBEAT_IN_FUTURE"),
    ],
)
def test_future_heartbeat_skew_is_bounded_and_explicit(
    future_seconds: int,
    expected: AgentState,
    reason_code: str,
) -> None:
    candidate = record(
        heartbeat_age_seconds=-future_seconds,
        parent_alive=True,
        detached=False,
        os_status="running",
    )

    result = classify(candidate, now=NOW, max_future_skew_seconds=5)

    assert result.state is expected
    assert reason_code in result.reason_codes


@pytest.mark.parametrize(
    "max_future_skew_seconds",
    [-1.0, float("nan"), float("inf"), float("-inf")],
)
def test_classifier_rejects_invalid_future_skew_thresholds(
    max_future_skew_seconds: float,
) -> None:
    candidate = record(
        heartbeat_age_seconds=0,
        parent_alive=True,
        detached=False,
        os_status="running",
    )

    with pytest.raises(ValueError, match="finite and non-negative"):
        classify(
            candidate,
            now=NOW,
            max_future_skew_seconds=max_future_skew_seconds,
        )


def test_heartbeat_expiry_threshold_is_expired_at_the_exact_boundary() -> None:
    candidate = record(
        heartbeat_age_seconds=15,
        parent_alive=True,
        detached=False,
        os_status="running",
    )

    result = classify(candidate, now=NOW)

    assert result.state is AgentState.STALE
    assert "HEARTBEAT_EXPIRED" in result.reason_codes


def test_missing_parent_knowledge_does_not_prove_orphaning() -> None:
    candidate = record(
        heartbeat_age_seconds=30,
        parent_alive=None,
        detached=False,
        os_status="running",
    )

    result = classify(candidate, now=NOW)

    assert result.state is AgentState.STALE
    assert "EXPECTED_PARENT_ABSENT" not in result.reason_codes


def test_managed_agent_with_unanswered_control_is_unresponsive() -> None:
    candidate = record(
        heartbeat_age_seconds=2,
        parent_alive=True,
        detached=False,
        os_status="running",
    ).model_copy(update={"control_unresponsive": True})

    result = classify(candidate, now=NOW)

    assert result.state is AgentState.UNRESPONSIVE
    assert result.reason_codes == ("CONTROL_UNRESPONSIVE",)


@pytest.mark.parametrize(
    ("pid", "create_time"),
    [
        (0, 1.0),
        (-1, 1.0),
        (1, -0.001),
        (1, float("nan")),
        (1, float("inf")),
    ],
)
def test_process_identity_rejects_non_positive_pid_or_invalid_creation_time(
    pid: int, create_time: float
) -> None:
    with pytest.raises(ValidationError):
        ProcessIdentity(
            boot_id="synthetic-boot",
            pid=pid,
            create_time=create_time,
        )


@pytest.mark.parametrize(
    ("pid", "create_time"),
    [(True, 1.0), ("42", 1.0), (42, "1.0")],
)
def test_process_identity_does_not_coerce_numeric_telemetry(
    pid: object,
    create_time: object,
) -> None:
    with pytest.raises(ValidationError):
        ProcessIdentity.model_validate(
            {
                "boot_id": "synthetic-boot",
                "pid": pid,
                "create_time": create_time,
            }
        )


def test_domain_models_forbid_typo_extra_fields() -> None:
    with pytest.raises(ValidationError, match="extra_forbidden"):
        ProcessIdentity.model_validate(
            {
                "boot_id": "synthetic-boot",
                "pid": 42,
                "pdi": 43,
                "create_time": 1.0,
            }
        )


@pytest.mark.parametrize("boot_id", ["", "   ", "x" * 257])
def test_process_identity_rejects_invalid_boot_ids(boot_id: str) -> None:
    with pytest.raises(ValidationError):
        ProcessIdentity(boot_id=boot_id, pid=42, create_time=1.0)


@pytest.mark.parametrize(
    "executable",
    ["", "   ", pytest.param("x" * 32_769, id="overbound")],
)
def test_process_identity_rejects_empty_or_unbounded_executable(
    executable: str,
) -> None:
    with pytest.raises(ValidationError):
        ProcessIdentity(
            boot_id="synthetic-boot",
            pid=42,
            create_time=1.0,
            executable=executable,
        )


def test_process_identity_preserves_executable_path_whitespace() -> None:
    executable = " /synthetic/bin/agent "

    identity = ProcessIdentity(
        boot_id="synthetic-boot",
        pid=42,
        create_time=1.0,
        executable=executable,
    )

    assert identity.executable == executable


@pytest.mark.parametrize("identifier", ["", "   ", "x" * 257])
def test_agent_and_current_boot_identifiers_are_non_empty_and_bounded(
    identifier: str,
) -> None:
    with pytest.raises(ValidationError):
        Lease(
            agent_id=identifier,
            identity=IDENTITY,
            heartbeat_at=NOW,
            heartbeat_timeout_seconds=15,
        )
    with pytest.raises(ValidationError):
        AgentRecord(current_boot_id=identifier)


def test_expected_parent_pid_must_be_positive_when_present() -> None:
    with pytest.raises(ValidationError):
        Lease(
            agent_id="synthetic-agent",
            identity=IDENTITY,
            heartbeat_at=NOW,
            heartbeat_timeout_seconds=15,
            expected_parent_pid=0,
        )


@pytest.mark.parametrize("os_status", ["", "   ", "x" * 65])
def test_process_snapshot_rejects_empty_or_unbounded_status_text(
    os_status: str,
) -> None:
    with pytest.raises(ValidationError):
        ProcessSnapshot(
            identity=IDENTITY,
            observed_at=NOW,
            process_present=True,
            os_status=os_status,
        )


@pytest.mark.parametrize(
    "timeout_seconds",
    [0.0, -1.0, float("nan"), float("inf"), float("-inf")],
)
def test_lease_rejects_non_positive_or_non_finite_heartbeat_timeout(
    timeout_seconds: float,
) -> None:
    with pytest.raises(ValidationError):
        Lease(
            agent_id="synthetic-agent",
            identity=IDENTITY,
            heartbeat_at=NOW,
            heartbeat_timeout_seconds=timeout_seconds,
        )


def test_finite_huge_heartbeat_timeout_does_not_overflow_classifier() -> None:
    candidate = record(
        heartbeat_age_seconds=2,
        parent_alive=True,
        detached=False,
        os_status="running",
    )
    assert candidate.lease is not None
    candidate = candidate.model_copy(
        update={"lease": candidate.lease.model_copy(update={"heartbeat_timeout_seconds": 1e308})}
    )

    result = classify(candidate, now=NOW, max_future_skew_seconds=1e308)

    assert result.state is AgentState.HEALTHY
    assert "HEARTBEAT_RECENT" in result.reason_codes


def test_timestamps_must_be_aware_and_are_normalized_to_utc() -> None:
    with pytest.raises(ValidationError):
        Lease(
            agent_id="synthetic-agent",
            identity=IDENTITY,
            heartbeat_at=datetime(2026, 8, 12, 12, 0),
            heartbeat_timeout_seconds=15,
        )

    offset_time = datetime(
        2026,
        8,
        12,
        14,
        0,
        tzinfo=timezone(timedelta(hours=2)),
    )
    lease = Lease(
        agent_id="synthetic-agent",
        identity=IDENTITY,
        heartbeat_at=offset_time,
        heartbeat_timeout_seconds=15,
    )

    assert lease.heartbeat_at == NOW
    assert lease.heartbeat_at.tzinfo is UTC


def test_classifier_rejects_a_naive_reference_time() -> None:
    candidate = record(
        heartbeat_age_seconds=2,
        parent_alive=True,
        detached=False,
        os_status="running",
    )

    with pytest.raises(ValueError, match="timezone-aware"):
        classify(candidate, now=datetime(2026, 8, 12, 12, 0))


def test_explicit_current_boot_disagreement_is_unknown() -> None:
    candidate = record(
        heartbeat_age_seconds=2,
        parent_alive=True,
        detached=False,
        os_status="running",
    )

    result = classify(
        candidate,
        now=NOW,
        current_boot_id="different-current-boot",
    )

    assert result.state is AgentState.UNKNOWN
    assert result.reason_codes == ("CURRENT_BOOT_ID_MISMATCH",)


def test_live_previous_boot_snapshot_is_unknown_before_defunct_precedence() -> None:
    candidate = AgentRecord(
        current_boot_id="synthetic-boot-current",
        process=ProcessSnapshot(
            identity=IDENTITY.model_copy(update={"boot_id": "synthetic-boot-previous"}),
            observed_at=NOW,
            process_present=True,
            os_status="zombie",
        ),
    )

    result = classify(candidate, now=NOW)

    assert result.state is AgentState.UNKNOWN
    assert result.reason_codes == ("LIVE_PROCESS_PREVIOUS_BOOT",)


@pytest.mark.parametrize(
    ("identity_create_time", "observed_at", "reason_code"),
    [
        (
            NOW.timestamp() - 10,
            NOW + timedelta(seconds=6),
            "SNAPSHOT_OBSERVED_IN_FUTURE",
        ),
        (
            NOW.timestamp() + 6,
            NOW,
            "PROCESS_CREATED_IN_FUTURE",
        ),
        (
            NOW.timestamp(),
            NOW - timedelta(seconds=6),
            "PROCESS_CREATED_AFTER_OBSERVATION",
        ),
    ],
)
def test_contradictory_process_chronology_is_unknown_before_state_precedence(
    identity_create_time: float,
    observed_at: datetime,
    reason_code: str,
) -> None:
    candidate = AgentRecord(
        current_boot_id="synthetic-boot-current",
        process=ProcessSnapshot(
            identity=IDENTITY.model_copy(update={"create_time": identity_create_time}),
            observed_at=observed_at,
            process_present=True,
            os_status="zombie",
        ),
    )

    result = classify(candidate, now=NOW, max_future_skew_seconds=5)

    assert result.state is AgentState.UNKNOWN
    assert result.reason_codes == (reason_code,)


@pytest.mark.parametrize(
    ("heartbeat_at", "create_time", "reason_code"),
    [
        (
            NOW + timedelta(seconds=6),
            NOW.timestamp() - 10,
            "HEARTBEAT_IN_FUTURE",
        ),
        (
            NOW - timedelta(seconds=20),
            NOW.timestamp() - 10,
            "HEARTBEAT_BEFORE_PROCESS_CREATION",
        ),
    ],
)
def test_contradictory_lease_chronology_is_unknown_before_state_precedence(
    heartbeat_at: datetime,
    create_time: float,
    reason_code: str,
) -> None:
    identity = IDENTITY.model_copy(update={"create_time": create_time})
    candidate = AgentRecord(
        current_boot_id="synthetic-boot-current",
        lease=Lease(
            agent_id="synthetic-agent",
            identity=identity,
            heartbeat_at=heartbeat_at,
            heartbeat_timeout_seconds=15,
        ),
        process=ProcessSnapshot(
            identity=identity,
            observed_at=NOW,
            process_present=True,
            os_status="zombie",
        ),
    )

    result = classify(candidate, now=NOW, max_future_skew_seconds=5)

    assert result.state is AgentState.UNKNOWN
    assert result.reason_codes == (reason_code,)


def test_confirmed_missing_expected_owner_can_prove_orphaning() -> None:
    candidate = record(
        heartbeat_age_seconds=30,
        parent_alive=None,
        detached=False,
        os_status="running",
    )
    assert candidate.lease is not None
    assert candidate.process is not None
    candidate = candidate.model_copy(
        update={
            "lease": candidate.lease.model_copy(
                update={"expected_parent_pid": None, "expected_owner": "synthetic-owner"}
            ),
            "process": candidate.process.model_copy(update={"owner_alive": False}),
        }
    )

    result = classify(candidate, now=NOW)

    assert result.state is AgentState.ORPHANED
    assert "EXPECTED_OWNER_ABSENT" in result.reason_codes


def test_runtime_without_managed_evidence_never_proves_orphaning() -> None:
    long_running_identity = IDENTITY.model_copy(update={"create_time": 1.0})
    candidate = AgentRecord(
        current_boot_id="synthetic-boot-current",
        process=ProcessSnapshot(
            identity=long_running_identity,
            observed_at=NOW,
            process_present=True,
            os_status="running",
        ),
    )

    result = classify(candidate, now=NOW)

    assert result.state is AgentState.UNKNOWN
    assert result.state is not AgentState.ORPHANED


def test_stale_process_snapshot_is_unknown_before_every_live_state_branch() -> None:
    old_observed_at = NOW - timedelta(seconds=301)
    managed = record(
        heartbeat_age_seconds=2,
        parent_alive=True,
        detached=False,
        os_status="running",
    )
    assert managed.process is not None
    managed = managed.model_copy(
        update={"process": managed.process.model_copy(update={"observed_at": old_observed_at})}
    )
    unresponsive = managed.model_copy(update={"control_unresponsive": True})
    defunct = managed.model_copy(
        update={"process": managed.process.model_copy(update={"os_status": "zombie"})}
    )
    unmanaged = AgentRecord(
        current_boot_id="synthetic-boot-current",
        process=ProcessSnapshot(
            identity=IDENTITY,
            observed_at=old_observed_at,
            process_present=True,
            os_status="running",
            signature_matched=True,
        ),
    )

    for candidate in (managed, unresponsive, defunct, unmanaged):
        result = classify(candidate, now=NOW, max_snapshot_age_seconds=300)
        assert result.state is AgentState.UNKNOWN
        assert result.reason_codes == ("PROCESS_SNAPSHOT_TOO_OLD",)


@pytest.mark.parametrize(
    "max_snapshot_age_seconds",
    [0.0, -1.0, float("nan"), float("inf"), float("-inf")],
)
def test_classifier_rejects_invalid_snapshot_age_thresholds(
    max_snapshot_age_seconds: float,
) -> None:
    candidate = record(
        heartbeat_age_seconds=2,
        parent_alive=True,
        detached=False,
        os_status="running",
    )

    with pytest.raises(ValueError, match="finite and positive"):
        classify(
            candidate,
            now=NOW,
            max_snapshot_age_seconds=max_snapshot_age_seconds,
        )


@pytest.mark.parametrize(
    ("snapshot_age_seconds", "max_snapshot_age_seconds"),
    [(300, 300.0), (301, 1e308)],
)
def test_snapshot_age_boundary_and_huge_finite_policy_are_safe(
    snapshot_age_seconds: int,
    max_snapshot_age_seconds: float,
) -> None:
    candidate = record(
        heartbeat_age_seconds=2,
        parent_alive=True,
        detached=False,
        os_status="running",
    )
    assert candidate.process is not None
    candidate = candidate.model_copy(
        update={
            "process": candidate.process.model_copy(
                update={"observed_at": NOW - timedelta(seconds=snapshot_age_seconds)}
            )
        }
    )

    result = classify(
        candidate,
        now=NOW,
        max_snapshot_age_seconds=max_snapshot_age_seconds,
    )

    assert result.state is AgentState.HEALTHY


@pytest.mark.parametrize(
    "updates",
    [
        {"confidence": -0.01},
        {"confidence": 1.01},
        {"confidence": float("nan")},
        {"confidence": float("inf")},
        {"reason_codes": ()},
        {"reason_codes": ("",)},
        {"reason_codes": ("   ",)},
        {"explanation": ""},
        {"explanation": "   "},
        {"evidence": ()},
    ],
)
def test_classification_rejects_invalid_or_empty_output_fields(
    updates: dict[str, object],
) -> None:
    values: dict[str, object] = {
        "state": AgentState.HEALTHY,
        "evidence_grade": EvidenceGrade.CONFIRMED,
        "confidence": 0.9,
        "reason_codes": ("HEARTBEAT_RECENT",),
        "explanation": "Synthetic valid classification explanation.",
        "evidence": (
            Evidence(
                code="HEARTBEAT_RECENT",
                grade=EvidenceGrade.CONFIRMED,
                observed_at=NOW,
                detail="Synthetic timestamped evidence.",
            ),
        ),
        "classified_at": NOW,
    }
    values.update(updates)

    with pytest.raises(ValidationError):
        Classification.model_validate(values)


@pytest.mark.parametrize(
    ("code", "detail"),
    [
        ("", "valid detail"),
        ("   ", "valid detail"),
        ("x" * 129, "valid detail"),
        ("VALID_CODE", ""),
        ("VALID_CODE", "   "),
        ("VALID_CODE", "x" * 2049),
    ],
)
def test_evidence_text_fields_are_non_empty_and_bounded(
    code: str,
    detail: str,
) -> None:
    with pytest.raises(ValidationError):
        Evidence(
            code=code,
            grade=EvidenceGrade.CONFIRMED,
            observed_at=NOW,
            detail=detail,
        )
