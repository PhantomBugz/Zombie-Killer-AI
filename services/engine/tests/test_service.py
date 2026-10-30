from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from zombie_killer_engine.actions import process_instance_id
from zombie_killer_engine.models import (
    AgentState,
    Classification,
    Evidence,
    EvidenceGrade,
    ProcessIdentity,
)
from zombie_killer_engine.paths import AppPaths
from zombie_killer_engine.scanner import (
    ProcessDetails,
    ScanCoverage,
    ScannedAgent,
    ScanResult,
    ScanWarning,
)
from zombie_killer_engine.service import (
    RequestContext,
    RequestEnvelope,
    ScanListPayload,
    ScanListResult,
    _scan_projection,
    build_default_service,
)


def synthetic_scan(
    *, managed: int, unmanaged: int = 0, warnings: tuple[ScanWarning, ...] = ()
) -> ScanResult:
    now = datetime(2026, 10, 2, 12, tzinfo=UTC)
    evidence = Evidence(
        code="SYNTHETIC_FIXTURE",
        grade=EvidenceGrade.CONFIRMED,
        observed_at=now,
        detail="Synthetic scan evidence.",
    )
    healthy = Classification(
        state=AgentState.HEALTHY,
        evidence_grade=EvidenceGrade.CONFIRMED,
        confidence=1.0,
        reason_codes=("SYNTHETIC_FIXTURE",),
        explanation="Synthetic managed agent.",
        evidence=(evidence,),
        classified_at=now,
    )
    agents = tuple(
        ScannedAgent(
            agent_id=f"managed-{index}",
            lease_matched=True,
            classification=healthy,
        )
        for index in range(managed)
    ) + tuple(
        ScannedAgent(classification=healthy.model_copy(update={"state": AgentState.UNMANAGED}))
        for _index in range(unmanaged)
    )
    return ScanResult(
        agents=agents,
        coverage=ScanCoverage(
            inspected_count=managed + unmanaged,
            denied_count=0,
            vanished_count=0,
            malformed_lease_count=0,
            lease_file_count=managed,
            skipped_lease_count=0,
            other_user_count=0,
            unknown_owner_count=0,
            identity_denied_count=0,
            complete=True,
            captured_at=now,
            current_boot_id="synthetic-boot",
            warnings=warnings,
        ),
    )


@pytest.mark.parametrize(
    ("managed", "unmanaged", "include_unmanaged", "expected_omitted"),
    [
        (501, 0, True, 1),
        (501, 50, False, 1),
        (1, 500, False, 0),
        (500, 1, True, 1),
    ],
)
def test_scan_projection_reports_only_eligible_truncation(
    managed: int, unmanaged: int, include_unmanaged: bool, expected_omitted: int
) -> None:
    scan = synthetic_scan(managed=managed, unmanaged=unmanaged)

    result = ScanListResult.model_validate_json(
        json.dumps(
            _scan_projection(scan, ScanListPayload(include_unmanaged=include_unmanaged, limit=500))
        )
    )

    assert result.total == managed + unmanaged
    assert result.returned == min(managed + (unmanaged if include_unmanaged else 0), 500)
    assert result.coverage.complete is (expected_omitted == 0)
    truncation = [
        warning for warning in result.coverage.warnings if warning.code == "SCAN_RESULT_TRUNCATED"
    ]
    if expected_omitted:
        assert len(truncation) == 1
        assert truncation[0].message == "The scan result limit omitted 1 eligible agent record."
    else:
        assert not truncation
    assert scan.coverage.complete is True
    assert not scan.coverage.warnings


def test_scan_projection_bounds_truncation_warning_with_full_coverage_warnings() -> None:
    existing = tuple(
        ScanWarning(code=f"FIXTURE_{index}", message="Existing synthetic coverage warning.")
        for index in range(128)
    )
    scan = synthetic_scan(managed=501, warnings=existing)

    result = ScanListResult.model_validate_json(
        json.dumps(_scan_projection(scan, ScanListPayload(limit=500)))
    )

    assert result.coverage.complete is False
    assert len(result.coverage.warnings) == 128
    assert any(warning.code == "SCAN_RESULT_TRUNCATED" for warning in result.coverage.warnings)
    assert len(scan.coverage.warnings) == 128


@pytest.mark.parametrize("binding", ["omitted", "current", "changed_pid", "changed_instance"])
def test_default_agent_detail_finds_target_beyond_scan_list_limit(
    tmp_path: Path, binding: str
) -> None:
    scan = synthetic_scan(managed=1001)
    identity = ProcessIdentity(
        boot_id="synthetic-boot",
        pid=4242,
        create_time=1.0,
        executable="/synthetic/python",
        user="synthetic-user",
    )
    target = scan.agents[-1].model_copy(
        update={
            "process": ProcessDetails(
                identity=identity,
                observed_at=scan.coverage.captured_at,
                status="running",
                cmdline=(),
            )
        }
    )
    scan = scan.model_copy(update={"agents": (*scan.agents[:-1], target)})
    paths = AppPaths(
        data_dir=tmp_path / "data",
        state_dir=tmp_path / "state",
        runtime_dir=tmp_path / "runtime",
        backups_dir=tmp_path / "backups",
        graveyard_dir=tmp_path / "graveyard",
    )
    payload: dict[str, object] = {"agent_id": "managed-1000"}
    if binding != "omitted":
        payload.update(
            expected_pid=4343 if binding == "changed_pid" else 4242,
            expected_process_instance_id=(
                "f" * 64 if binding == "changed_instance" else process_instance_id(identity)
            ),
        )
    envelope = RequestEnvelope(
        protocol_version="1.0",
        request_id=uuid4(),
        method="agent.detail",
        payload=payload,
    )

    with build_default_service(paths=paths, scanner=lambda: scan) as service:
        response = service.dispatch(envelope, context=RequestContext())

    if binding.startswith("changed"):
        assert response.ok is False
        assert response.error is not None
        assert response.error.code.value == "target_changed"
    else:
        assert response.ok is True
        assert response.result is not None
        assert response.result.model_dump()["agent_id"] == "managed-1000"
