"""Typed domain models for process evidence and agent classification."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, TypeAlias

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    model_validator,
)


def _normalize_utc(value: datetime) -> datetime:
    return value.astimezone(UTC)


def _require_non_blank(value: str) -> str:
    if not value.strip():
        raise ValueError("value must contain a non-whitespace character")
    return value


UtcDatetime: TypeAlias = Annotated[AwareDatetime, AfterValidator(_normalize_utc)]
IdentifierText: TypeAlias = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256)
]
StatusText: TypeAlias = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=64)
]
PathText: TypeAlias = Annotated[
    str,
    StringConstraints(min_length=1, max_length=4096),
    AfterValidator(_require_non_blank),
]
ExecutableText: TypeAlias = Annotated[
    str,
    StringConstraints(min_length=1, max_length=32_768),
    AfterValidator(_require_non_blank),
]
CodeText: TypeAlias = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=128)
]
HashText: TypeAlias = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
DisplayText: TypeAlias = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2048)
]


class DomainModel(BaseModel):
    """Fail-closed immutable base for persisted domain data."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class AgentState(StrEnum):
    """User-visible lifecycle state."""

    HEALTHY = "healthy"
    IDLE = "idle"
    STALE = "stale"
    ORPHANED = "orphaned"
    UNRESPONSIVE = "unresponsive"
    UNMANAGED = "unmanaged"
    INTERRUPTED = "interrupted"
    DEFUNCT = "defunct"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    UNKNOWN = "unknown"


class EvidenceGrade(StrEnum):
    """Strength of evidence supporting a classification."""

    CONFIRMED = "confirmed"
    STRONG = "strong"
    PARTIAL = "partial"
    SIGNATURE_ONLY = "signature_only"
    INSUFFICIENT = "insufficient"


class ProcessIdentity(DomainModel):
    """PID-reuse-safe process identity."""

    boot_id: IdentifierText
    pid: int = Field(gt=0)
    create_time: float = Field(ge=0, allow_inf_nan=False)
    executable: ExecutableText | None = None
    user: IdentifierText | None = None
    executable_hash: HashText | None = None
    user_hash: HashText | None = None


class Lease(DomainModel):
    """Managed-agent heartbeat lease."""

    agent_id: IdentifierText
    registration_nonce: IdentifierText | None = None
    identity: ProcessIdentity
    heartbeat_at: UtcDatetime
    heartbeat_timeout_seconds: float = Field(gt=0, allow_inf_nan=False)
    expected_parent_pid: int | None = Field(default=None, gt=0)
    expected_owner: IdentifierText | None = None
    detached: bool = False
    declared_state: AgentState = AgentState.HEALTHY
    terminal_at: UtcDatetime | None = None

    @model_validator(mode="after")
    def terminal_evidence_is_consistent(self) -> Lease:
        terminal = self.declared_state in {
            AgentState.COMPLETED,
            AgentState.FAILED,
            AgentState.CANCELLED,
        }
        if terminal != (self.terminal_at is not None):
            raise ValueError("terminal state and timestamp must be present together")
        return self


class ProcessSnapshot(DomainModel):
    """Bounded process evidence captured at one instant."""

    identity: ProcessIdentity | None = None
    observed_at: UtcDatetime
    process_present: bool
    os_status: StatusText
    parent_alive: bool | None = None
    owner_alive: bool | None = None
    visibility_complete: bool = True
    signature_matched: bool = False


class Evidence(DomainModel):
    """One timestamped fact supporting a classification."""

    code: CodeText
    grade: EvidenceGrade
    observed_at: UtcDatetime
    detail: DisplayText


class AgentRecord(DomainModel):
    """Available managed and operating-system evidence for one candidate."""

    current_boot_id: IdentifierText | None = None
    lease: Lease | None = None
    process: ProcessSnapshot | None = None
    control_unresponsive: bool = False


class Classification(DomainModel):
    """Deterministic lifecycle decision with its supporting evidence."""

    state: AgentState
    evidence_grade: EvidenceGrade
    confidence: float = Field(ge=0, le=1, allow_inf_nan=False)
    reason_codes: tuple[CodeText, ...] = Field(min_length=1)
    explanation: DisplayText
    evidence: tuple[Evidence, ...] = Field(min_length=1)
    classified_at: UtcDatetime
