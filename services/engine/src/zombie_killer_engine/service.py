"""Finite, typed application-service boundary for local Zombie Killer clients."""

from __future__ import annotations

import hmac
import json
import os
import platform
import sys
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Any, Literal, TypeAlias, cast
from uuid import UUID, uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)

from zombie_killer_engine.actions import (
    ActionExecutor,
    ActionMode,
    ActionPlanner,
    ActionReceipt,
    PlanRejectedError,
    ProcessAccessDenied,
    ProcessController,
    ProcessDisappeared,
    ProcessIdentityMismatch,
    PsutilProcessController,
    StableBindingUnavailable,
    process_instance_id,
)
from zombie_killer_engine.cleanup_workflow import CleanupWorkflow
from zombie_killer_engine.diagnostics_workflow import DiagnosticsWorkflow
from zombie_killer_engine.memory.base import (
    MemoryError,
    MemoryJournalError,
    MutationKind,
    MutationOperation,
    QueryFilter,
    VaultFormat,
    read_prefix_pinned,
)
from zombie_killer_engine.memory.inventory import FaissInventoryAdapter
from zombie_killer_engine.memory.json_store import JsonMemoryAdapter
from zombie_killer_engine.memory.sqlite_store import SQLiteMemoryAdapter
from zombie_killer_engine.memory_workflow import MUTATION_KIND, RESTORE_KIND, MemoryWorkflow
from zombie_killer_engine.models import ProcessIdentity
from zombie_killer_engine.paths import AppPaths
from zombie_killer_engine.quarantine import CleanupRejectedError, QuarantineState
from zombie_killer_engine.redaction import (
    contains_sensitive_key_material,
    is_sensitive_key,
    redact_display_text,
)
from zombie_killer_engine.scanner import ScanResult, scan_agents
from zombie_killer_engine.store import (
    ExpiredPlanError,
    PlanClaimError,
    SettingsRevisionConflict,
    SQLiteStateStore,
    StoreError,
)

PROTOCOL_VERSION: Literal["1.0"] = "1.0"
ENGINE_VERSION = "0.1.0-alpha.1"
MAX_PROCESS_ID = 4_294_967_295
MAX_RESULT_DEPTH = 16
MAX_RESULT_COLLECTION = 10_000
MAX_RESULT_STRING = 65_536
MAX_RESULT_NODES = 20_000

Identifier: TypeAlias = Annotated[
    str,
    StringConstraints(min_length=1, max_length=256, pattern=r"^\S(?:.*\S)?$"),
]
Digest: TypeAlias = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
LocalPath: TypeAlias = Annotated[
    str,
    StringConstraints(min_length=1, max_length=4096, pattern=r"^\S(?:.*\S)?$"),
]
DoctorWarning: TypeAlias = Annotated[str, StringConstraints(max_length=512)]
ReasonCode: TypeAlias = Annotated[str, StringConstraints(min_length=1, max_length=128)]
PlanMessage: TypeAlias = Annotated[str, StringConstraints(max_length=2048)]
ReceiptFailure: TypeAlias = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2048)
]
ErrorDetailText: TypeAlias = Annotated[str, StringConstraints(max_length=256)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Method(StrEnum):
    SYSTEM_INFO = "system.info"
    DOCTOR = "doctor"
    SCAN_LIST = "scan.list"
    AGENT_DETAIL = "agent.detail"
    ACTION_PLAN = "action.plan"
    ACTION_EXECUTE = "action.execute"
    ACTIVITY_LIST = "activity.list"
    RECEIPT_GET = "receipt.get"
    QUARANTINE_LIST = "quarantine.list"
    QUARANTINE_RESOURCE_LIST = "quarantine.resource-list"
    QUARANTINE_PLAN = "quarantine.plan"
    QUARANTINE_EXECUTE = "quarantine.execute"
    QUARANTINE_RESTORE_PLAN = "quarantine.restore-plan"
    QUARANTINE_RESTORE_EXECUTE = "quarantine.restore-execute"
    VAULT_LIST = "vault.list"
    VAULT_REGISTER = "vault.register"
    VAULT_PROBE = "vault.probe"
    VAULT_QUERY = "vault.query"
    VAULT_GET = "vault.get"
    VAULT_MUTATION_PLAN = "vault.mutation.plan"
    VAULT_MUTATION_EXECUTE = "vault.mutation.execute"
    VAULT_SNAPSHOT_LIST = "vault.snapshot.list"
    VAULT_RESTORE_PLAN = "vault.restore.plan"
    VAULT_RESTORE_EXECUTE = "vault.restore.execute"
    SETTINGS_GET = "settings.get"
    SETTINGS_UPDATE = "settings.update"
    DIAGNOSTICS_EXPORT_PLAN = "diagnostics.export-plan"
    DIAGNOSTICS_EXPORT_EXECUTE = "diagnostics.export-execute"


class Capability(StrEnum):
    READ = "read"
    PLANNING = "planning"
    EXECUTION = "execution"


class ClientKind(StrEnum):
    CONTROLLER = "controller"
    SDK = "sdk"
    TELEMETRY = "telemetry"


class ErrorCode(StrEnum):
    INVALID_REQUEST = "invalid_request"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    TARGET_CHANGED = "target_changed"
    PERMISSION_DENIED = "permission_denied"
    EXPIRED = "expired"
    UNSUPPORTED = "unsupported"
    PARTIAL = "partial"
    INTERNAL = "internal"


class RequestContext(StrictModel):
    client: ClientKind = ClientKind.CONTROLLER
    capability: Capability = Capability.READ
    local_control: bool = False


class EmptyPayload(StrictModel):
    pass


class ScanListPayload(StrictModel):
    include_unmanaged: bool = True
    limit: int = Field(default=500, ge=1, le=1_000)


class AgentDetailPayload(StrictModel):
    agent_id: Identifier
    expected_pid: int | None = Field(default=None, gt=0)
    expected_process_instance_id: Digest | None = None

    @model_validator(mode="after")
    def binding_fields_are_paired(self) -> AgentDetailPayload:
        fields = {"expected_pid", "expected_process_instance_id"}
        supplied = self.model_fields_set & fields
        if supplied and (
            supplied != fields
            or self.expected_pid is None
            or self.expected_process_instance_id is None
        ):
            raise ValueError(
                "expected process identity fields must be supplied together and non-null"
            )
        return self


class ActionTargetPayload(StrictModel):
    pid: int = Field(gt=0, le=MAX_PROCESS_ID)
    process_instance_id: Digest


class ActionPlanPayload(StrictModel):
    agent_id: Identifier
    mode: Literal["request_stop", "terminate", "kill"]
    target: ActionTargetPayload


class ExecutePayload(StrictModel):
    plan_id: Identifier
    digest: Digest


class PagePayload(StrictModel):
    cursor: Annotated[str, StringConstraints(max_length=256)] | None = None
    limit: int = Field(default=100, ge=1, le=500)


class ReceiptGetPayload(StrictModel):
    receipt_id: Identifier


class RestorePlanPayload(StrictModel):
    entry_id: Identifier


class CleanupResourceListPayload(AgentDetailPayload):
    pass


class CleanupPlanPayload(CleanupResourceListPayload):
    resource_index: int = Field(ge=0, le=63)
    expected_declaration_digest: Digest


class VaultPathPayload(StrictModel):
    path: LocalPath


class VaultQueryPayload(StrictModel):
    source_id: Identifier
    namespace: Identifier | None = None
    text: Annotated[str, StringConstraints(max_length=1024)] | None = None
    cursor: Annotated[str, StringConstraints(max_length=256)] | None = None
    limit: int = Field(default=100, ge=1, le=500)


class VaultGetPayload(StrictModel):
    source_id: Identifier
    record_id: Identifier


class VaultMutationPlanPayload(StrictModel):
    source_id: Identifier
    expected_revision: Digest
    operation: Literal[
        "update_content",
        "update_field",
        "update_metadata",
        "exclude_from_retrieval",
        "quarantine",
        "restore_record",
    ]
    record_id: Identifier
    field: Identifier | None = None
    metadata_key: Identifier | None = None
    value: str | int | float | bool | None = None


class VaultSnapshotListPayload(StrictModel):
    source_id: Identifier
    limit: int = Field(default=100, ge=1, le=500)


class VaultRestorePlanPayload(StrictModel):
    source_id: Identifier
    snapshot_id: Identifier
    snapshot_digest: Digest
    expected_revision: Digest


class SettingsUpdatePayload(StrictModel):
    expected_revision: int = Field(ge=0)
    scan_interval_seconds: int | None = Field(default=None, ge=5, le=3_600)
    heartbeat_grace_seconds: int | None = Field(default=None, ge=10, le=86_400)
    retention_days: int | None = Field(default=None, ge=1, le=365)
    include_unmanaged_candidates: bool | None = None
    appearance: Literal["system", "light", "dark"] | None = None
    reduced_motion: bool | None = None

    @model_validator(mode="after")
    def at_least_one_setting(self) -> SettingsUpdatePayload:
        if not self.model_fields_set - {"expected_revision"}:
            raise ValueError("at least one setting is required")
        return self

    @model_validator(mode="before")
    @classmethod
    def explicit_null_is_not_an_update(cls, value: object) -> object:
        if isinstance(value, Mapping) and any(item is None for item in value.values()):
            raise ValueError("setting values cannot be null")
        return value


class DiagnosticsExportPlanPayload(StrictModel):
    destination: LocalPath
    include_receipts: bool = True
    include_settings: bool = True


class SystemInfoResult(StrictModel):
    engine_version: str = Field(min_length=1, max_length=64)
    protocol_version: Literal["1.0"]
    platform: str = Field(min_length=1, max_length=64)
    python: str = Field(min_length=1, max_length=32)
    local_only: Literal[True]
    network_listener: Literal[False]
    memory_warning: str = Field(min_length=1, max_length=512)


class DoctorCheckResult(StrictModel):
    name: str = Field(min_length=1, max_length=128)
    ok: bool


class DoctorResult(StrictModel):
    healthy: bool
    checks: tuple[DoctorCheckResult, ...] = Field(max_length=128)
    warnings: tuple[DoctorWarning, ...] = Field(max_length=128)


class EvidenceResult(StrictModel):
    code: str = Field(min_length=1, max_length=128)
    grade: Literal["confirmed", "strong", "partial", "signature_only", "insufficient"]
    observed_at: str = Field(min_length=1, max_length=64)
    detail: str = Field(min_length=1, max_length=2048)


class UsageCostResult(StrictModel):
    availability: Literal["known", "unknown"]
    amount_usd: float | None = Field(ge=0, allow_inf_nan=False)
    note: str = Field(min_length=1, max_length=512)

    @model_validator(mode="after")
    def amount_matches_availability(self) -> UsageCostResult:
        if (self.availability == "known") != (self.amount_usd is not None):
            raise ValueError("known cost requires an amount and unknown cost forbids one")
        return self


class AgentSummaryResult(StrictModel):
    agent_id: str | None = Field(default=None, max_length=256)
    provider: str | None = Field(default=None, max_length=256)
    project: str | None = Field(default=None, max_length=256)
    role: str | None = Field(default=None, max_length=256)
    state: Literal[
        "healthy",
        "idle",
        "stale",
        "orphaned",
        "unresponsive",
        "unmanaged",
        "interrupted",
        "defunct",
        "completed",
        "failed",
        "cancelled",
        "unknown",
    ]
    evidence_grade: Literal["confirmed", "strong", "partial", "signature_only", "insufficient"]
    confidence: float = Field(ge=0, le=1, allow_inf_nan=False)
    reason_codes: tuple[ReasonCode, ...] = Field(min_length=1, max_length=128)
    explanation: str = Field(min_length=1, max_length=2048)
    evidence: tuple[EvidenceResult, ...] = Field(min_length=1, max_length=128)
    actionable: bool
    managed: bool
    pid: int | None = Field(default=None, gt=0)
    process_instance_id: Digest | None = None
    process_name: str | None = Field(default=None, max_length=256)
    os_status: str | None = Field(default=None, max_length=64)
    usage_cost: UsageCostResult


class ScanWarningResult(StrictModel):
    code: str = Field(min_length=1, max_length=128)
    message: str = Field(min_length=1, max_length=512)


class ScanCoverageResult(StrictModel):
    inspected_count: int = Field(ge=0)
    denied_count: int = Field(ge=0)
    vanished_count: int = Field(ge=0)
    malformed_lease_count: int = Field(ge=0)
    lease_file_count: int = Field(ge=0)
    skipped_lease_count: int = Field(ge=0)
    other_user_count: int = Field(ge=0)
    unknown_owner_count: int = Field(ge=0)
    identity_denied_count: int = Field(ge=0)
    complete: bool
    captured_at: str = Field(min_length=1, max_length=64)
    current_boot_id: str = Field(min_length=1, max_length=256)
    warnings: tuple[ScanWarningResult, ...] = Field(max_length=128)


class ScanListResult(StrictModel):
    agents: tuple[AgentSummaryResult, ...] = Field(max_length=1_000)
    coverage: ScanCoverageResult
    returned: int = Field(ge=0, le=1_000)
    total: int = Field(ge=0)


class PlanResult(StrictModel):
    plan_id: Identifier
    digest: Digest
    expires_at: str = Field(min_length=1, max_length=64)
    consequences: tuple[PlanMessage, ...] = Field(min_length=1, max_length=64)
    warnings: tuple[PlanMessage, ...] = Field(max_length=64)


class ActionTargetResult(ActionTargetPayload):
    state: Literal[
        "healthy",
        "idle",
        "stale",
        "orphaned",
        "unresponsive",
        "unmanaged",
        "interrupted",
        "defunct",
        "completed",
        "failed",
        "cancelled",
        "unknown",
    ]


class ActionPlanResult(PlanResult):
    target: ActionTargetResult


class ReceiptResult(StrictModel):
    receipt_id: Identifier
    plan_id: Identifier
    outcome: str = Field(min_length=1, max_length=128)
    certainty: Literal["verified", "failed_before_issue", "uncertain"]
    action_issued: bool | None
    partial_failures: tuple[ReceiptFailure, ...] = Field(max_length=64)
    created_at: str = Field(min_length=1, max_length=64)
    kind: Literal["process", "memory", "quarantine", "diagnostics"] = "process"


class ActivityListResult(StrictModel):
    receipts: tuple[ReceiptResult, ...] = Field(max_length=500)
    next_cursor: str | None = Field(default=None, max_length=256)


class QuarantineEntryResult(StrictModel):
    entry_id: Identifier
    agent_id: Identifier
    resource_type: Literal["file", "directory"]
    state: Literal["quarantined", "partial", "restoring", "restored", "interrupted"]
    restorable: bool
    created_at: str = Field(min_length=1, max_length=64)
    updated_at: str = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def nonquarantined_state_is_not_restorable(self) -> QuarantineEntryResult:
        if self.state != "quarantined" and self.restorable:
            raise ValueError("non-quarantined public outcomes cannot be restorable")
        return self


class QuarantineListResult(StrictModel):
    entries: tuple[QuarantineEntryResult, ...] = Field(max_length=500)
    next_cursor: str | None = Field(default=None, max_length=256)


class CleanupResourceResult(StrictModel):
    resource_index: int = Field(ge=0, le=63)
    kind: Literal["temporary"]
    resource_type: Literal["file", "directory", "unknown"]
    cleanup_available: bool
    reason: str = Field(min_length=1, max_length=512)
    declaration_digest: Digest | None


class CleanupResourceListResult(StrictModel):
    agent_id: Identifier
    resources: tuple[CleanupResourceResult, ...] = Field(max_length=64)
    returned: int = Field(ge=0, le=64)


VAULT_LOCAL_ONLY_WARNING = (
    "Changes affect only local user-controlled memory; they do not change provider safety, "
    "rate limits, account state, or guarantee continuation."
)
VaultLocalOnlyWarning: TypeAlias = Literal[
    "Changes affect only local user-controlled memory; they do not change provider safety, "
    "rate limits, account state, or guarantee continuation."
]


class VaultCapabilitiesResult(StrictModel):
    readable: bool
    queryable: bool
    editable: bool
    snapshot: bool
    restore: bool
    reason: str | None = Field(default=None, max_length=512)


class VaultProbeResult(StrictModel):
    format: Literal["json", "jsonl", "sqlite", "chroma", "faiss", "unsupported"]
    recognized: bool
    capabilities: VaultCapabilitiesResult
    reason: str | None = Field(default=None, max_length=512)
    read_only: Literal[True]
    selected_locally: Literal[True]
    local_only_warning: VaultLocalOnlyWarning


class VaultSourceResult(StrictModel):
    source_id: Identifier
    format: Literal["json", "jsonl", "sqlite", "chroma", "faiss", "unsupported"]
    capabilities: VaultCapabilitiesResult
    revision: Digest


class VaultListResult(StrictModel):
    sources: tuple[VaultSourceResult, ...] = Field(max_length=500)
    next_cursor: str | None = Field(default=None, max_length=256)
    local_only_warning: VaultLocalOnlyWarning


class VaultEditableFieldResult(StrictModel):
    field: str = Field(min_length=1, max_length=128)
    kind: Literal["update_content", "update_field", "update_metadata"]
    value_type: Literal["string", "number", "boolean", "null"]
    value: Annotated[str, StringConstraints(max_length=65_536)] | int | float | bool | None

    @model_validator(mode="after")
    def scalar_type_matches(self) -> VaultEditableFieldResult:
        expected = (
            "null"
            if self.value is None
            else "boolean"
            if isinstance(self.value, bool)
            else "string"
            if isinstance(self.value, str)
            else "number"
        )
        if self.value_type != expected or (
            isinstance(self.value, float)
            and (self.value != self.value or abs(self.value) == float("inf"))
        ):
            raise ValueError("editable value type does not match its finite scalar")
        return self


class VaultRecordResult(StrictModel):
    record_id: Identifier
    namespace: Identifier
    content: str = Field(max_length=65_536)
    metadata: dict[str, object] = Field(max_length=256)
    embedding_present: bool
    source_revision: Digest
    editable_fields: tuple[VaultEditableFieldResult, ...] = Field(default=(), max_length=128)


class VaultQueryResult(StrictModel):
    records: tuple[VaultRecordResult, ...] = Field(max_length=500)
    next_cursor: str | None = Field(default=None, max_length=256)
    total: int = Field(ge=0)
    local_only_warning: VaultLocalOnlyWarning


class VaultGetResult(StrictModel):
    record: VaultRecordResult
    local_only_warning: VaultLocalOnlyWarning


class VaultDiffResult(StrictModel):
    field_name: str = Field(min_length=1, max_length=128)
    old_hash: Digest
    new_hash: Digest
    old_preview: Literal["[REDACTED]"]
    new_preview: Literal["[REDACTED]"]


class VaultPlanResult(PlanResult):
    local_only_warning: VaultLocalOnlyWarning
    source_id: Identifier | None = None
    record_id: Identifier | None = None
    snapshot_id: Identifier | None = None
    before_revision: Digest | None = None
    backup_verified: bool = False
    diff: tuple[VaultDiffResult, ...] = Field(default=(), max_length=8)


class VaultReceiptResult(ReceiptResult):
    local_only_warning: VaultLocalOnlyWarning
    source_id: Identifier | None = None
    record_id: Identifier | None = None
    snapshot_id: Identifier | None = None
    before_revision: Digest | None = None
    after_revision: Digest | None = None
    operation: str | None = Field(default=None, min_length=1, max_length=128)


class VaultSnapshotResult(StrictModel):
    snapshot_id: Identifier
    source_id: Identifier
    source_revision: Digest
    digest: Digest
    size: int = Field(ge=0)
    status: Literal["verified", "restored", "invalid"]
    created_at: str = Field(min_length=1, max_length=64)


class VaultSnapshotListResult(StrictModel):
    snapshots: tuple[VaultSnapshotResult, ...] = Field(max_length=500)
    local_only_warning: VaultLocalOnlyWarning


class SettingsValuesResult(StrictModel):
    scan_interval_seconds: int = Field(ge=5, le=3_600)
    heartbeat_grace_seconds: int = Field(ge=10, le=86_400)
    retention_days: int = Field(ge=1, le=365)
    include_unmanaged_candidates: bool
    appearance: Literal["system", "light", "dark"]
    reduced_motion: bool


class SettingsResult(StrictModel):
    settings: SettingsValuesResult
    revision: int = Field(ge=0)


class DiagnosticsPlanResult(PlanResult):
    excluded_by_default: tuple[
        Literal["command_lines", "memory_contents", "paths", "secrets"], ...
    ] = Field(min_length=4, max_length=4)


ResultModel: TypeAlias = type[StrictModel]

RESULT_MODELS: dict[Method, ResultModel] = {
    Method.SYSTEM_INFO: SystemInfoResult,
    Method.DOCTOR: DoctorResult,
    Method.SCAN_LIST: ScanListResult,
    Method.AGENT_DETAIL: AgentSummaryResult,
    Method.ACTION_PLAN: ActionPlanResult,
    Method.ACTION_EXECUTE: ReceiptResult,
    Method.ACTIVITY_LIST: ActivityListResult,
    Method.RECEIPT_GET: ReceiptResult,
    Method.QUARANTINE_LIST: QuarantineListResult,
    Method.QUARANTINE_RESOURCE_LIST: CleanupResourceListResult,
    Method.QUARANTINE_PLAN: PlanResult,
    Method.QUARANTINE_EXECUTE: ReceiptResult,
    Method.QUARANTINE_RESTORE_PLAN: PlanResult,
    Method.QUARANTINE_RESTORE_EXECUTE: ReceiptResult,
    Method.VAULT_LIST: VaultListResult,
    Method.VAULT_REGISTER: VaultProbeResult,
    Method.VAULT_PROBE: VaultProbeResult,
    Method.VAULT_QUERY: VaultQueryResult,
    Method.VAULT_GET: VaultGetResult,
    Method.VAULT_MUTATION_PLAN: VaultPlanResult,
    Method.VAULT_MUTATION_EXECUTE: VaultReceiptResult,
    Method.VAULT_SNAPSHOT_LIST: VaultSnapshotListResult,
    Method.VAULT_RESTORE_PLAN: VaultPlanResult,
    Method.VAULT_RESTORE_EXECUTE: VaultReceiptResult,
    Method.SETTINGS_GET: SettingsResult,
    Method.SETTINGS_UPDATE: SettingsResult,
    Method.DIAGNOSTICS_EXPORT_PLAN: DiagnosticsPlanResult,
    Method.DIAGNOSTICS_EXPORT_EXECUTE: ReceiptResult,
}


PayloadModel: TypeAlias = type[StrictModel]

PAYLOAD_MODELS: dict[Method, PayloadModel] = {
    Method.SYSTEM_INFO: EmptyPayload,
    Method.DOCTOR: EmptyPayload,
    Method.SCAN_LIST: ScanListPayload,
    Method.AGENT_DETAIL: AgentDetailPayload,
    Method.ACTION_PLAN: ActionPlanPayload,
    Method.ACTION_EXECUTE: ExecutePayload,
    Method.ACTIVITY_LIST: PagePayload,
    Method.RECEIPT_GET: ReceiptGetPayload,
    Method.QUARANTINE_LIST: PagePayload,
    Method.QUARANTINE_RESOURCE_LIST: CleanupResourceListPayload,
    Method.QUARANTINE_PLAN: CleanupPlanPayload,
    Method.QUARANTINE_EXECUTE: ExecutePayload,
    Method.QUARANTINE_RESTORE_PLAN: RestorePlanPayload,
    Method.QUARANTINE_RESTORE_EXECUTE: ExecutePayload,
    Method.VAULT_LIST: PagePayload,
    Method.VAULT_REGISTER: VaultPathPayload,
    Method.VAULT_PROBE: VaultPathPayload,
    Method.VAULT_QUERY: VaultQueryPayload,
    Method.VAULT_GET: VaultGetPayload,
    Method.VAULT_MUTATION_PLAN: VaultMutationPlanPayload,
    Method.VAULT_MUTATION_EXECUTE: ExecutePayload,
    Method.VAULT_SNAPSHOT_LIST: VaultSnapshotListPayload,
    Method.VAULT_RESTORE_PLAN: VaultRestorePlanPayload,
    Method.VAULT_RESTORE_EXECUTE: ExecutePayload,
    Method.SETTINGS_GET: EmptyPayload,
    Method.SETTINGS_UPDATE: SettingsUpdatePayload,
    Method.DIAGNOSTICS_EXPORT_PLAN: DiagnosticsExportPlanPayload,
    Method.DIAGNOSTICS_EXPORT_EXECUTE: ExecutePayload,
}

READ_METHODS = {
    Method.SYSTEM_INFO,
    Method.DOCTOR,
    Method.SCAN_LIST,
    Method.AGENT_DETAIL,
    Method.ACTIVITY_LIST,
    Method.RECEIPT_GET,
    Method.QUARANTINE_LIST,
    Method.QUARANTINE_RESOURCE_LIST,
    Method.VAULT_LIST,
    Method.VAULT_PROBE,
    Method.VAULT_QUERY,
    Method.VAULT_GET,
    Method.VAULT_SNAPSHOT_LIST,
    Method.SETTINGS_GET,
}
PLANNING_METHODS = {
    Method.ACTION_PLAN,
    Method.QUARANTINE_RESTORE_PLAN,
    Method.QUARANTINE_PLAN,
    Method.VAULT_REGISTER,
    Method.VAULT_MUTATION_PLAN,
    Method.VAULT_RESTORE_PLAN,
    Method.SETTINGS_UPDATE,
    Method.DIAGNOSTICS_EXPORT_PLAN,
}
EXECUTION_METHODS = {
    Method.ACTION_EXECUTE,
    Method.QUARANTINE_RESTORE_EXECUTE,
    Method.QUARANTINE_EXECUTE,
    Method.VAULT_MUTATION_EXECUTE,
    Method.VAULT_RESTORE_EXECUTE,
    Method.DIAGNOSTICS_EXPORT_EXECUTE,
}


class RequestEnvelope(StrictModel):
    protocol_version: str
    request_id: UUID
    method: str = Field(min_length=1, max_length=128)
    payload: dict[str, Any]


_ALLOWED_ERROR_DETAIL_KEYS = frozenset({"correlation_id", "field", "reason", "supported_version"})


class ErrorBody(StrictModel):
    code: ErrorCode
    message: str = Field(min_length=1, max_length=512)
    retryable: bool = False
    details: dict[str, ErrorDetailText | int | bool | None] = Field(
        default_factory=dict, max_length=16
    )

    @field_validator("details", mode="before")
    @classmethod
    def sanitize_detail_keys_and_values(cls, value: object) -> object:
        if not isinstance(value, Mapping):
            return value
        safe: dict[str, str | int | bool | None] = {}
        for index, (raw_key, item) in enumerate(value.items(), start=1):
            key = str(raw_key)
            if key not in _ALLOWED_ERROR_DETAIL_KEYS:
                safe[f"redacted_detail_{index}"] = "[REDACTED]"
            elif isinstance(item, str):
                safe[key] = redact_display_text(item, max_length=256)
            else:
                safe[key] = item
        return safe


ResultValue: TypeAlias = (
    SystemInfoResult
    | DoctorResult
    | ScanListResult
    | AgentSummaryResult
    | ActionPlanResult
    | PlanResult
    | ReceiptResult
    | ActivityListResult
    | QuarantineListResult
    | CleanupResourceListResult
    | VaultProbeResult
    | VaultListResult
    | VaultQueryResult
    | VaultGetResult
    | VaultPlanResult
    | VaultReceiptResult
    | VaultSnapshotListResult
    | SettingsResult
    | DiagnosticsPlanResult
)


class ResponseEnvelope(StrictModel):
    protocol_version: Literal["1.0"] = PROTOCOL_VERSION
    request_id: UUID
    method: Method | None = None
    ok: bool
    result: ResultValue | None = None
    error: ErrorBody | None = None

    @model_validator(mode="after")
    def result_matches_status(self) -> ResponseEnvelope:
        if self.ok == (self.error is not None):
            raise ValueError("success and error fields are inconsistent")
        if self.ok:
            if self.result is None or self.method is None:
                raise ValueError("success responses require a method and non-null result")
            if type(self.result) is not RESULT_MODELS[self.method]:
                raise ValueError("success result does not match the response method")
        elif self.result is not None:
            raise ValueError("error responses cannot contain a result")
        return self


class ServiceFault(RuntimeError):
    """An intentional, display-safe failure at the application boundary."""

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        *,
        retryable: bool = False,
        details: Mapping[str, str | int | bool | None] | None = None,
    ) -> None:
        super().__init__(message)
        validated = ErrorBody(
            code=code,
            message=redact_display_text(message, max_length=512),
            retryable=retryable,
            details=dict(details or {}),
        )
        self.body = validated


Handler: TypeAlias = Callable[[StrictModel, RequestContext], object]
ExecutionAuthorizer: TypeAlias = Callable[[Method, str, str], bool]
Scanner: TypeAlias = Callable[[], ScanResult]


def _capability_rank(capability: Capability) -> int:
    return {
        Capability.READ: 0,
        Capability.PLANNING: 1,
        Capability.EXECUTION: 2,
    }[capability]


def _required_capability(method: Method) -> Capability:
    if method in EXECUTION_METHODS:
        return Capability.EXECUTION
    if method in PLANNING_METHODS:
        return Capability.PLANNING
    return Capability.READ


_BLOCKED_RESULT_KEYS = {
    "api_key",
    "password",
    "secret",
    "token",
    "environment",
    "cmdline",
    "command_line",
    "destination",
    "executable",
    "path",
    "approved_root",
    "source_path",
    "backup_path",
    "raw_path",
    "registration_nonce",
    "target",
}


def _vault_content_field(method: Method, field_path: tuple[str, ...]) -> bool:
    return (
        (method is Method.VAULT_GET and field_path == ("record", "content"))
        or (method is Method.VAULT_QUERY and field_path == ("records", "record", "content"))
        or (
            method in {Method.VAULT_GET, Method.VAULT_QUERY}
            and field_path[-3:] == ("editable_fields", "record", "value")
        )
    )


def _redacted_result_key(
    index: int,
    *,
    reserved: set[str],
    used: set[str],
) -> str:
    base = f"[REDACTED_KEY_{index}]"
    candidate = base
    suffix = 1
    while candidate in reserved or candidate in used:
        candidate = f"{base[:-1]}_{suffix}]"
        suffix += 1
    return candidate


def _safe_result(
    value: object,
    *,
    method: Method,
    field_path: tuple[str, ...] = (),
    depth: int = 0,
    _active: set[int] | None = None,
    _remaining: list[int] | None = None,
) -> object:
    active = set() if _active is None else _active
    remaining = [MAX_RESULT_NODES] if _remaining is None else _remaining
    if remaining[0] <= 0:
        raise ServiceFault(ErrorCode.PARTIAL, "Result exceeded the cumulative node limit.")
    remaining[0] -= 1
    if depth > MAX_RESULT_DEPTH:
        raise ServiceFault(ErrorCode.PARTIAL, "Result exceeded the supported nesting limit.")
    if isinstance(value, BaseModel):
        return _safe_result(
            value.model_dump(mode="json"),
            method=method,
            field_path=field_path,
            depth=depth,
            _active=active,
            _remaining=remaining,
        )
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, float):
        if value != value or value in {float("inf"), float("-inf")}:
            raise ServiceFault(ErrorCode.PARTIAL, "Result contained a non-finite number.")
        return value
    if isinstance(value, str):
        if len(value) > MAX_RESULT_STRING:
            raise ServiceFault(ErrorCode.PARTIAL, "Result contained an oversized string.")
        return value if _vault_content_field(method, field_path) else redact_display_text(value)
    if isinstance(value, Mapping):
        if len(value) > MAX_RESULT_COLLECTION:
            raise ServiceFault(ErrorCode.PARTIAL, "Result exceeded the collection limit.")
        identity = id(value)
        if identity in active:
            raise ServiceFault(ErrorCode.PARTIAL, "Result contained a cyclic collection.")
        active.add(identity)
        try:
            result: dict[str, object] = {}
            reserved = {str(raw_key) for raw_key in value}
            for index, (raw_key, item) in enumerate(value.items(), start=1):
                key = str(raw_key)
                if len(key) > 128:
                    raise ServiceFault(ErrorCode.PARTIAL, "Result contained an invalid field name.")
                action_target = (
                    method is Method.ACTION_PLAN and not field_path and key.casefold() == "target"
                )
                if (
                    key.casefold() in _BLOCKED_RESULT_KEYS or is_sensitive_key(key)
                ) and not action_target:
                    continue
                output_key = key
                if contains_sensitive_key_material(key) or (
                    redact_display_text(key, max_length=128) != key
                ):
                    output_key = _redacted_result_key(
                        index,
                        reserved=reserved,
                        used=set(result),
                    )
                result[output_key] = _safe_result(
                    item,
                    method=method,
                    field_path=(*field_path, output_key),
                    depth=depth + 1,
                    _active=active,
                    _remaining=remaining,
                )
            return result
        finally:
            active.remove(identity)
    if isinstance(value, tuple | list):
        if len(value) > MAX_RESULT_COLLECTION:
            raise ServiceFault(ErrorCode.PARTIAL, "Result exceeded the collection limit.")
        identity = id(value)
        if identity in active:
            raise ServiceFault(ErrorCode.PARTIAL, "Result contained a cyclic collection.")
        active.add(identity)
        try:
            return [
                _safe_result(
                    item,
                    method=method,
                    field_path=(*field_path, "record"),
                    depth=depth + 1,
                    _active=active,
                    _remaining=remaining,
                )
                for item in value
            ]
        finally:
            active.remove(identity)
    if isinstance(value, StrEnum):
        return value.value
    raise ServiceFault(ErrorCode.PARTIAL, "Result contained an unsupported value.")


def _scan_projection(scan: ScanResult, payload: ScanListPayload) -> dict[str, object]:
    eligible = [
        agent
        for agent in scan.agents
        if payload.include_unmanaged or agent.classification.state.value != "unmanaged"
    ]
    selected = eligible[: payload.limit]
    agents: list[dict[str, object]] = []
    for agent in selected:
        process = agent.process
        classification = agent.classification
        agents.append(
            {
                "agent_id": agent.agent_id,
                "provider": agent.provider,
                "project": agent.project,
                "role": agent.role,
                "state": classification.state.value,
                "evidence_grade": classification.evidence_grade.value,
                "confidence": classification.confidence,
                "reason_codes": classification.reason_codes,
                "explanation": classification.explanation,
                "evidence": [item.model_dump(mode="json") for item in classification.evidence],
                "actionable": agent.actionable,
                "managed": agent.lease_matched,
                "pid": process.identity.pid if process and process.identity else None,
                "process_instance_id": (
                    process_instance_id(process.identity)
                    if process is not None and process.identity is not None
                    else None
                ),
                "process_name": process.name if process else None,
                "os_status": process.status if process else None,
                "usage_cost": {
                    "availability": "unknown",
                    "amount_usd": None,
                    "note": "Provider cost is unknown; no zero-cost estimate is inferred.",
                },
            }
        )
    coverage = scan.coverage.model_dump(mode="json")
    omitted = len(eligible) - len(selected)
    if omitted:
        warnings = cast(list[dict[str, object]], coverage["warnings"])
        record_label = "record" if omitted == 1 else "records"
        message = f"The scan result limit omitted {omitted} eligible agent {record_label}."
        if len(warnings) >= 128:
            message += " An additional coverage warning was omitted to keep the response bounded."
        coverage["complete"] = False
        coverage["warnings"] = [
            {"code": "SCAN_RESULT_TRUNCATED", "message": message},
            *warnings[:127],
        ]
    return {
        "agents": agents,
        "coverage": coverage,
        "returned": len(agents),
        "total": len(scan.agents),
    }


def _map_exception(error: BaseException) -> ErrorBody:
    if isinstance(error, ServiceFault):
        if error.body.code is ErrorCode.INTERNAL:
            return ErrorBody(
                code=ErrorCode.INTERNAL,
                message=(
                    "An internal error occurred. Use the correlation ID for local diagnostics."
                ),
                retryable=False,
                details={"correlation_id": str(uuid4())},
            )
        return error.body
    if isinstance(
        error, ValidationError | TypeError | ValueError | CleanupRejectedError | PlanRejectedError
    ):
        code = ErrorCode.INVALID_REQUEST
        message = "The request was rejected by policy or validation."
    elif isinstance(error, FileNotFoundError | KeyError):
        code = ErrorCode.NOT_FOUND
        message = "The requested object was not found."
    elif isinstance(error, ProcessIdentityMismatch):
        code = ErrorCode.TARGET_CHANGED
        message = "The target identity changed; no action was taken."
    elif isinstance(error, PermissionError):
        code = ErrorCode.PERMISSION_DENIED
        message = "The operation is not permitted in this local context."
    elif isinstance(error, ExpiredPlanError):
        code = ErrorCode.EXPIRED
        message = "The plan expired; create a new preview."
    elif isinstance(error, MemoryJournalError | TimeoutError):
        code = ErrorCode.PARTIAL
        message = "The operation did not produce a complete, verified result."
    elif isinstance(error, SettingsRevisionConflict):
        return ErrorBody(
            code=ErrorCode.CONFLICT,
            message="The settings revision no longer matches.",
            retryable=False,
            details={"reason": "settings_revision_mismatch"},
        )
    elif isinstance(error, PlanClaimError | StoreError | MemoryError):
        code = ErrorCode.CONFLICT
        message = "Stored authority no longer matches the requested operation."
    elif isinstance(error, NotImplementedError):
        code = ErrorCode.UNSUPPORTED
        message = "This method is not supported by the configured engine."
    else:
        correlation_id = str(uuid4())
        return ErrorBody(
            code=ErrorCode.INTERNAL,
            message="An internal error occurred. Use the correlation ID for local diagnostics.",
            retryable=False,
            details={"correlation_id": correlation_id},
        )
    return ErrorBody(code=code, message=message, retryable=False)


class EngineService:
    """Dispatch only named, validated use cases; never arbitrary local operations."""

    def __init__(
        self,
        *,
        handlers: Mapping[Method, Handler] | None = None,
        execution_authorizer: ExecutionAuthorizer | None = None,
        scanner: Scanner | None = None,
        paths: AppPaths | None = None,
        close_callback: Callable[[], None] | None = None,
    ) -> None:
        self._paths = paths or AppPaths.for_current_user()
        self._scanner = scanner or (lambda: scan_agents(self._paths.leases_dir))
        self._execution_authorizer = execution_authorizer
        self._close_callback = close_callback
        self._closed = False
        self._settings: dict[str, object] = {
            "scan_interval_seconds": 30,
            "heartbeat_grace_seconds": 120,
            "retention_days": 30,
            "include_unmanaged_candidates": True,
            "appearance": "system",
            "reduced_motion": False,
        }
        self._settings_revision = 0
        defaults: dict[Method, Handler] = {
            Method.SYSTEM_INFO: self._system_info,
            Method.DOCTOR: self._doctor,
            Method.SCAN_LIST: self._scan_list,
            Method.VAULT_PROBE: self._vault_probe,
            Method.SETTINGS_GET: self._settings_get,
            Method.SETTINGS_UPDATE: self._settings_update,
        }
        defaults.update(handlers or {})
        self._handlers = defaults

    def close(self) -> None:
        """Release service-owned resources exactly once."""
        if self._closed:
            return
        self._closed = True
        if self._close_callback is not None:
            self._close_callback()

    def __enter__(self) -> EngineService:
        return self

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc_value: BaseException | None,
        _traceback: object | None,
    ) -> None:
        self.close()

    def dispatch(self, envelope: RequestEnvelope, *, context: RequestContext) -> ResponseEnvelope:
        method: Method | None = None
        try:
            if envelope.protocol_version != PROTOCOL_VERSION:
                raise ServiceFault(
                    ErrorCode.INVALID_REQUEST,
                    "Unsupported protocol version.",
                    details={"supported_version": PROTOCOL_VERSION},
                )
            try:
                method = Method(envelope.method)
            except ValueError as error:
                raise ServiceFault(
                    ErrorCode.UNSUPPORTED,
                    "The requested method is not supported.",
                ) from error
            payload = PAYLOAD_MODELS[method].model_validate(envelope.payload)
            self._authorize(method, context)
            handler = self._handlers.get(method)
            if handler is None:
                raise ServiceFault(
                    ErrorCode.UNSUPPORTED,
                    "This method is not supported by the configured engine.",
                    details={"reason": "NOT_SUPPORTED"},
                )
            if method in EXECUTION_METHODS:
                assert isinstance(payload, ExecutePayload)
                if self._execution_authorizer is None:
                    raise ServiceFault(
                        ErrorCode.UNSUPPORTED,
                        "Execution authority is not configured.",
                        details={"reason": "NOT_SUPPORTED"},
                    )
                if not self._execution_authorizer(method, payload.plan_id, payload.digest):
                    raise ServiceFault(
                        ErrorCode.CONFLICT,
                        "The plan ID and digest do not match stored executable authority.",
                    )
            # Handlers run to a durable domain outcome before a response is emitted.
            # Domain operations own cooperative deadlines and reconciliation; the
            # service never abandons a mutating thread that can continue invisibly.
            raw_result = handler(payload, context)
            result = _safe_result(raw_result, method=method)
            if method.value.startswith("vault.") and isinstance(result, dict):
                result["local_only_warning"] = VAULT_LOCAL_ONLY_WARNING
            try:
                validated_result = RESULT_MODELS[method].model_validate_json(
                    json.dumps(result, ensure_ascii=False, allow_nan=False)
                )
            except ValidationError as error:
                raise ServiceFault(
                    ErrorCode.INTERNAL,
                    "A handler returned a value outside its protocol contract.",
                ) from error
            if method in EXECUTION_METHODS:
                assert isinstance(payload, ExecutePayload)
                if getattr(validated_result, "plan_id", None) != payload.plan_id:
                    raise ServiceFault(
                        ErrorCode.INTERNAL,
                        "An execution handler returned a receipt for a different plan.",
                    )
            return ResponseEnvelope(
                request_id=envelope.request_id,
                method=method,
                ok=True,
                result=cast(ResultValue, validated_result),
                error=None,
            )
        except Exception as error:
            return ResponseEnvelope(
                request_id=envelope.request_id,
                method=method,
                ok=False,
                result=None,
                error=_map_exception(error),
            )

    def _authorize(self, method: Method, context: RequestContext) -> None:
        required = _required_capability(method)
        if required is not Capability.READ and context.client is not ClientKind.CONTROLLER:
            raise ServiceFault(
                ErrorCode.PERMISSION_DENIED,
                "SDK and telemetry clients cannot invoke control methods.",
            )
        if _capability_rank(context.capability) < _capability_rank(required):
            raise ServiceFault(
                ErrorCode.PERMISSION_DENIED,
                "The request context lacks the required capability.",
            )
        if required is Capability.EXECUTION and not context.local_control:
            raise ServiceFault(
                ErrorCode.PERMISSION_DENIED,
                "Execution requires an authenticated local-control context.",
            )

    def _system_info(self, _payload: StrictModel, _context: RequestContext) -> object:
        return {
            "engine_version": ENGINE_VERSION,
            "protocol_version": PROTOCOL_VERSION,
            "platform": platform.system().casefold(),
            "python": f"{sys.version_info.major}.{sys.version_info.minor}",
            "local_only": True,
            "network_listener": False,
            "memory_warning": "Memory Vault data remains local unless the operator exports it.",
        }

    def _doctor(self, _payload: StrictModel, _context: RequestContext) -> object:
        return {
            "healthy": True,
            "checks": [
                {"name": "protocol", "ok": True},
                {"name": "local_only", "ok": True},
            ],
            "warnings": [],
        }

    def _scan_list(self, payload: StrictModel, _context: RequestContext) -> object:
        assert isinstance(payload, ScanListPayload)
        return _scan_projection(self._scanner(), payload)

    def _vault_probe(self, payload: StrictModel, _context: RequestContext) -> object:
        assert isinstance(payload, VaultPathPayload)
        selected = Path(payload.path)
        adapter = _vault_adapter_class(selected)
        probe = adapter.probe(selected)
        return {
            "format": probe.format.value,
            "recognized": probe.recognized,
            "capabilities": probe.capabilities.model_dump(mode="json"),
            "reason": probe.reason,
            "read_only": True,
            "selected_locally": True,
            "local_only_warning": VAULT_LOCAL_ONLY_WARNING,
        }

    def _settings_get(self, _payload: StrictModel, _context: RequestContext) -> object:
        return {"settings": dict(self._settings), "revision": self._settings_revision}

    def _settings_update(self, payload: StrictModel, _context: RequestContext) -> object:
        assert isinstance(payload, SettingsUpdatePayload)
        if payload.expected_revision != self._settings_revision:
            raise ServiceFault(
                ErrorCode.CONFLICT,
                "The settings revision no longer matches.",
                details={"reason": "settings_revision_mismatch"},
            )
        changes = payload.model_dump(exclude_none=True, exclude={"expected_revision"})
        self._settings.update(changes)
        self._settings_revision += 1
        return {"settings": dict(self._settings), "revision": self._settings_revision}


def _vault_adapter_class(
    path: Path,
) -> type[JsonMemoryAdapter] | type[SQLiteMemoryAdapter] | type[FaissInventoryAdapter]:
    prefix, _identity = read_prefix_pinned(path, prefix_bytes=45)
    if prefix.startswith(b"SQLite format 3\x00"):
        return SQLiteMemoryAdapter
    if prefix[:4] in {b"IxF2", b"IxFI", b"IxFl"}:
        return FaissInventoryAdapter
    return JsonMemoryAdapter


def _action_receipt_result(receipt: ActionReceipt) -> dict[str, object]:
    certainty: Literal["verified", "failed_before_issue", "uncertain"]
    if receipt.action_issued is None:
        certainty = "uncertain"
    elif receipt.action_issued:
        certainty = "verified"
    else:
        certainty = "failed_before_issue"
    return {
        "receipt_id": receipt.receipt_id,
        "plan_id": receipt.plan_id,
        "outcome": receipt.result.value,
        "certainty": certainty,
        "action_issued": receipt.action_issued,
        "partial_failures": receipt.partial_failures,
        "created_at": receipt.finished_at.isoformat(),
        "kind": "process",
    }


def build_default_service(
    *,
    paths: AppPaths | None = None,
    scanner: Scanner | None = None,
    controller: ProcessController | None = None,
) -> EngineService:
    """Compose persistent production use cases without renderer-selected authority."""
    selected_paths = paths or AppPaths.for_current_user()
    state_store = SQLiteStateStore(selected_paths)

    def configured_scan() -> ScanResult:
        settings, _revision = state_store.get_settings()
        return scan_agents(
            selected_paths.leases_dir,
            heartbeat_grace_seconds=cast(int, settings.get("heartbeat_grace_seconds", 120)),
        )

    scan_provider = scanner or configured_scan
    try:
        return _compose_default_service(
            selected_paths=selected_paths,
            scan_provider=scan_provider,
            state_store=state_store,
            controller=controller,
        )
    except BaseException as primary_error:
        try:
            state_store.close()
        except BaseException as close_error:
            primary_error.add_note(
                f"Engine service cleanup also failed ({type(close_error).__name__})."
            )
        raise


def _stable_process_actions_available(
    controller: ProcessController,
    current_identity: ProcessIdentity,
) -> bool:
    if controller.stable_binding_kind not in {"windows_handle", "pidfd"}:
        return False

    try:
        reference = controller.bind(current_identity)
        try:
            reference.validate(current_identity)
        finally:
            reference.close()
    except (StableBindingUnavailable, ProcessAccessDenied, OSError):
        return False
    return True


def _compose_default_service(
    *,
    selected_paths: AppPaths,
    scan_provider: Scanner,
    state_store: SQLiteStateStore,
    controller: ProcessController | None,
) -> EngineService:
    state_store.initialize()
    process_controller = controller or PsutilProcessController()
    current_identity = process_controller.read_identity(os.getpid())
    if current_identity.user is None:
        raise RuntimeError("current process user identity is unavailable")
    process_actions_available = _stable_process_actions_available(
        process_controller,
        current_identity,
    )
    planner = ActionPlanner(
        process_controller,
        current_user=current_identity.user,
    )
    executor = ActionExecutor(
        state_store,
        process_controller,
        selected_paths,
        actor="local-controller",
    )
    settings_defaults: dict[str, object] = {
        "scan_interval_seconds": 30,
        "heartbeat_grace_seconds": 120,
        "retention_days": 30,
        "include_unmanaged_candidates": True,
        "appearance": "system",
        "reduced_motion": False,
    }

    def settings_snapshot() -> tuple[dict[str, object], int]:
        persisted, revision = state_store.get_settings()
        return {**settings_defaults, **persisted}, revision

    def agent_detail(payload: StrictModel, _context: RequestContext) -> object:
        assert isinstance(payload, AgentDetailPayload)
        scan = scan_provider()
        candidate = next(
            (agent for agent in scan.agents if agent.agent_id == payload.agent_id), None
        )
        if candidate is None:
            raise KeyError(payload.agent_id)
        result = _scan_projection(
            ScanResult(agents=(candidate,), coverage=scan.coverage), ScanListPayload(limit=1)
        )
        agents = cast(list[dict[str, object]], result["agents"])
        agent = agents[0]
        if payload.expected_pid is not None and (
            agent.get("pid") != payload.expected_pid
            or agent.get("process_instance_id") != payload.expected_process_instance_id
        ):
            raise ServiceFault(
                ErrorCode.TARGET_CHANGED,
                "The reviewed process instance is no longer the current target.",
                details={"reason": "agent_identity_changed"},
            )
        return agent

    def action_plan(payload: StrictModel, _context: RequestContext) -> object:
        assert isinstance(payload, ActionPlanPayload)
        candidate = next(
            (agent for agent in scan_provider().agents if agent.agent_id == payload.agent_id),
            None,
        )
        if candidate is None or candidate.process is None or candidate.process.identity is None:
            raise ServiceFault(
                ErrorCode.TARGET_CHANGED,
                "The reviewed process instance is no longer the current target.",
                details={"reason": "process_instance_changed"},
            )
        candidate_identity = candidate.process.identity
        if (
            candidate_identity.pid != payload.target.pid
            or process_instance_id(candidate_identity) != payload.target.process_instance_id
        ):
            raise ServiceFault(
                ErrorCode.TARGET_CHANGED,
                "The reviewed process instance is no longer the current target.",
                details={"reason": "process_instance_changed"},
            )
        mode = ActionMode.FORCE if payload.mode == "kill" else ActionMode(payload.mode)
        try:
            plan = planner.create_plan(candidate, mode=mode)
        except PlanRejectedError as error:
            if isinstance(
                error.__cause__, (ProcessAccessDenied, ProcessDisappeared)
            ) or "reused or changed" in str(error):
                raise ServiceFault(
                    ErrorCode.TARGET_CHANGED,
                    "The reviewed process instance is no longer the current target.",
                    details={"reason": "process_instance_changed"},
                ) from error
            raise
        bound_instance_id = process_instance_id(plan.identity)
        if (
            plan.identity.pid != payload.target.pid
            or bound_instance_id != payload.target.process_instance_id
        ):
            raise ServiceFault(
                ErrorCode.TARGET_CHANGED,
                "The reviewed process instance is no longer the current target.",
                details={"reason": "process_instance_changed"},
            )
        state_store.save_plan(plan)
        return {
            "plan_id": plan.plan_id,
            "digest": plan.digest,
            "expires_at": plan.expires_at.isoformat(),
            "consequences": plan.consequences,
            "warnings": plan.warnings,
            "target": {
                "pid": plan.identity.pid,
                "process_instance_id": bound_instance_id,
                "state": candidate.classification.state.value,
            },
        }

    def action_execute(payload: StrictModel, _context: RequestContext) -> object:
        assert isinstance(payload, ExecutePayload)
        return _action_receipt_result(
            executor.execute(payload.plan_id, expected_digest=payload.digest)
        )

    def activity_list(payload: StrictModel, _context: RequestContext) -> object:
        assert isinstance(payload, PagePayload)
        receipts = state_store.list_public_receipts(limit=payload.limit, cursor=payload.cursor)
        selected = [
            _action_receipt_result(receipt) if isinstance(receipt, ActionReceipt) else receipt
            for receipt in receipts
        ]
        next_cursor = None
        if len(selected) == payload.limit:
            candidate_cursor = str(selected[-1]["receipt_id"])
            if state_store.list_public_receipts(limit=1, cursor=candidate_cursor):
                next_cursor = candidate_cursor
        return {
            "receipts": [base_receipt(receipt) for receipt in selected],
            "next_cursor": next_cursor,
        }

    def base_receipt(receipt: dict[str, object]) -> dict[str, object]:
        return {key: receipt[key] for key in ReceiptResult.model_fields if key in receipt}

    def receipt_get(payload: StrictModel, _context: RequestContext) -> object:
        assert isinstance(payload, ReceiptGetPayload)
        receipt = state_store.get_action_receipt(payload.receipt_id)
        if receipt is None:
            workflow_receipt = state_store.get_workflow_receipt_by_id(payload.receipt_id)
            if workflow_receipt is None:
                raise KeyError(payload.receipt_id)
            return base_receipt(workflow_receipt)
        return _action_receipt_result(receipt)

    def quarantine_list(payload: StrictModel, _context: RequestContext) -> object:
        assert isinstance(payload, PagePayload)
        states = {
            QuarantineState.SUCCEEDED: "quarantined",
            QuarantineState.PARTIAL: "partial",
            QuarantineState.RESTORED: "restored",
            QuarantineState.INTERRUPTED: "interrupted",
        }
        entries = []
        listings = state_store.list_quarantine_entries(
            limit=payload.limit,
            cursor=payload.cursor,
        )
        for listing in listings:
            entry = listing.entry
            state = "restoring" if listing.restoring else states.get(entry.state)
            if state is None:
                continue
            entries.append(
                {
                    "entry_id": entry.entry_id,
                    "agent_id": entry.agent_id,
                    "resource_type": entry.resource_type.value,
                    "state": state,
                    "restorable": (
                        not listing.restoring and entry.state is QuarantineState.SUCCEEDED
                    ),
                    "created_at": entry.created_at.isoformat(),
                    "updated_at": entry.updated_at.isoformat(),
                }
            )
        next_cursor = None
        if len(listings) == payload.limit:
            candidate_cursor = listings[-1].entry.entry_id
            if state_store.list_quarantine_entries(limit=1, cursor=candidate_cursor):
                next_cursor = candidate_cursor
        return {"entries": entries, "next_cursor": next_cursor}

    def vault_adapter(source_id: str) -> JsonMemoryAdapter | SQLiteMemoryAdapter:
        source = state_store.get_vault_source(source_id)
        if source is None:
            raise KeyError(source_id)
        source_path = Path(source.path)
        if source.format in {VaultFormat.FAISS, VaultFormat.CHROMA}:
            raise ServiceFault(ErrorCode.UNSUPPORTED, "This recognized source is inventory-only.")
        if source.format in {VaultFormat.SQLITE, VaultFormat.CHROMA}:
            return SQLiteMemoryAdapter(
                source_path,
                backups_dir=selected_paths.backups_dir,
                state_store=state_store,
            )
        return JsonMemoryAdapter(
            source_path,
            backups_dir=selected_paths.backups_dir,
            state_store=state_store,
        )

    def vault_cursor_context(
        source_id: str,
        namespace: str | None,
        text: str | None,
        limit: int,
        revision: str,
    ) -> str:
        source = state_store.get_vault_source(source_id)
        if source is None:
            raise KeyError(source_id)
        canonical = json.dumps(
            {
                "source_id": source_id,
                "namespace": namespace,
                "text": text,
                "limit": limit,
                "revision": revision,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return sha256(canonical).hexdigest()

    def vault_cursor_checksum(context: str, offset: str) -> str:
        # This deterministic checksum keeps cursors valid across the desktop
        # broker's one-request sidecar processes while making the numeric
        # adapter offset an opaque, self-consistent continuation token.
        return sha256(f"{context}.{offset}".encode("ascii")).hexdigest()

    def decode_vault_cursor(cursor: str, context: str) -> str:
        parts = cursor.split(".")
        if (
            len(parts) != 3
            or parts[0] != "v1"
            or not parts[1].isdigit()
            or not hmac.compare_digest(parts[2], vault_cursor_checksum(context, parts[1]))
        ):
            raise MemoryError("query cursor is invalid or no longer available")
        return parts[1]

    def encode_vault_cursor(offset: str, context: str) -> str:
        if not offset.isdigit():
            raise MemoryError("query cursor is invalid")
        return f"v1.{offset}.{vault_cursor_checksum(context, offset)}"

    def vault_register(payload: StrictModel, _context: RequestContext) -> object:
        assert isinstance(payload, VaultPathPayload)
        selected = Path(payload.path)
        adapter_class = _vault_adapter_class(selected)
        if adapter_class is FaissInventoryAdapter:
            inventory_adapter = FaissInventoryAdapter(selected)
            state_store.register_vault_source(inventory_adapter.source)
        elif adapter_class is SQLiteMemoryAdapter:
            SQLiteMemoryAdapter(
                selected, backups_dir=selected_paths.backups_dir, state_store=state_store
            )
        else:
            JsonMemoryAdapter(
                selected, backups_dir=selected_paths.backups_dir, state_store=state_store
            )
        probe = adapter_class.probe(selected)
        return {
            "format": probe.format.value,
            "recognized": probe.recognized,
            "capabilities": probe.capabilities.model_dump(mode="json"),
            "reason": probe.reason,
            "read_only": True,
            "selected_locally": True,
        }

    def vault_list(payload: StrictModel, _context: RequestContext) -> object:
        assert isinstance(payload, PagePayload)
        revision = state_store.vault_sources_revision()
        context = sha256(
            json.dumps(
                {"kind": "vault.list", "limit": payload.limit, "revision": revision},
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
        ).hexdigest()
        offset_text = (
            "0" if payload.cursor is None else decode_vault_cursor(payload.cursor, context)
        )
        offset = int(offset_text)
        if offset > 10_000_000:
            raise MemoryError("vault source cursor is outside the supported bound")
        sources = state_store.list_vault_sources(limit=payload.limit, offset=offset)
        if state_store.vault_sources_revision() != revision:
            raise MemoryError("vault source inventory changed while the page was being read")
        next_cursor = (
            encode_vault_cursor(str(offset + len(sources)), context)
            if len(sources) == payload.limit
            else None
        )
        return {
            "sources": [
                {
                    "source_id": source.source_id,
                    "format": source.format.value,
                    "capabilities": source.capabilities.model_dump(mode="json"),
                    "revision": source.revision,
                }
                for source in sources
            ],
            "next_cursor": next_cursor,
        }

    def vault_query(payload: StrictModel, _context: RequestContext) -> object:
        assert isinstance(payload, VaultQueryPayload)
        adapter = vault_adapter(payload.source_id)
        revision = adapter.current_revision()
        context = vault_cursor_context(
            payload.source_id,
            payload.namespace,
            payload.text,
            payload.limit,
            revision,
        )
        cursor = None if payload.cursor is None else decode_vault_cursor(payload.cursor, context)
        page = adapter.query(
            cursor=cursor,
            limit=payload.limit,
            filter=QueryFilter(text=payload.text),
            namespace=payload.namespace,
        )
        if adapter.current_revision() != revision or any(
            record.source_revision != revision for record in page.records
        ):
            raise MemoryError("vault source changed while the query page was being read")
        return {
            "records": [
                public_record(adapter, record.model_dump(mode="json")) for record in page.records
            ],
            "next_cursor": (
                None if page.next_cursor is None else encode_vault_cursor(page.next_cursor, context)
            ),
            "total": page.total,
        }

    def vault_get(payload: StrictModel, _context: RequestContext) -> object:
        assert isinstance(payload, VaultGetPayload)
        adapter = vault_adapter(payload.source_id)
        record = adapter.get(payload.record_id)
        return {"record": public_record(adapter, record.model_dump(mode="json"))}

    def public_record(
        adapter: JsonMemoryAdapter | SQLiteMemoryAdapter, record: dict[str, object]
    ) -> dict[str, object]:
        fields: list[dict[str, object]] = []

        def append(field: str, kind: str, value: object) -> None:
            if (
                len(fields) >= 128
                or not 1 <= len(field) <= 128
                or is_sensitive_key(field)
                or not field.replace("_", "a").isalnum()
            ):
                return
            if not (value is None or isinstance(value, str | int | float | bool)):
                return
            if (
                isinstance(value, str)
                and kind != "update_content"
                and redact_display_text(value, max_length=65_536) != value
            ):
                return
            fields.append(
                {
                    "field": field,
                    "kind": kind,
                    "value": value,
                    "value_type": "null"
                    if value is None
                    else "boolean"
                    if isinstance(value, bool)
                    else "string"
                    if isinstance(value, str)
                    else "number",
                }
            )

        if isinstance(adapter, JsonMemoryAdapter):
            _data, parsed, _identity = adapter._read()
            raw = adapter._locate(parsed, str(record["record_id"])).raw
            content_field = "content" if "content" in raw else "text" if "text" in raw else None
            if content_field is not None:
                append(content_field, "update_content", raw[content_field])
            for field, value in raw.items():
                if field not in {
                    "id",
                    "record_id",
                    "namespace",
                    "content",
                    "text",
                    "metadata",
                    "embedding",
                }:
                    append(field, "update_field", value)
            metadata = raw.get("metadata", {})
            if isinstance(metadata, dict):
                for field, value in metadata.items():
                    append(field, "update_metadata", value)
        else:
            namespace = str(record["namespace"])
            item = next((item for item in adapter.inventory() if item.name == namespace), None)
            if item is not None and item.editable:
                content_field = next(
                    (
                        name
                        for name in item.columns
                        if name.casefold() in {"content", "text", "document"}
                    ),
                    None,
                )
                if content_field is not None:
                    append(content_field, "update_content", record["content"])
                metadata = record.get("metadata", {})
                if isinstance(metadata, dict):
                    for field, value in metadata.items():
                        append(field, "update_field", value)
        record["editable_fields"] = fields
        if adapter.current_revision() != record["source_revision"]:
            raise MemoryError("vault source changed while editable fields were being read")
        return record

    def settings_get(_payload: StrictModel, _context: RequestContext) -> object:
        current, revision = settings_snapshot()
        return {"settings": current, "revision": revision}

    def settings_update(payload: StrictModel, _context: RequestContext) -> object:
        assert isinstance(payload, SettingsUpdatePayload)
        changes = payload.model_dump(exclude_none=True, exclude={"expected_revision"})
        persisted, revision = state_store.update_settings(
            changes,
            expected_revision=payload.expected_revision,
            now=datetime.now(UTC),
        )
        return {"settings": {**settings_defaults, **persisted}, "revision": revision}

    memory_workflow = MemoryWorkflow(state_store, vault_adapter)
    diagnostics_workflow = DiagnosticsWorkflow(state_store)

    def cleanup_workflow() -> CleanupWorkflow:
        settings, _revision = settings_snapshot()
        return CleanupWorkflow(
            state_store,
            selected_paths,
            current_user=current_identity.user or "",
            retention_days=cast(int, settings["retention_days"]),
        )

    def cleanup_resources(payload: StrictModel, _context: RequestContext) -> object:
        assert isinstance(payload, CleanupResourceListPayload)
        return cleanup_workflow().list_resources(
            payload.agent_id,
            expected_pid=payload.expected_pid,
            expected_process_instance_id=payload.expected_process_instance_id,
        )

    def cleanup_plan(payload: StrictModel, _context: RequestContext) -> object:
        assert isinstance(payload, CleanupPlanPayload)
        result = cleanup_workflow().plan(
            payload.agent_id,
            payload.resource_index,
            expected_declaration_digest=payload.expected_declaration_digest,
            expected_pid=payload.expected_pid,
            expected_process_instance_id=payload.expected_process_instance_id,
        )
        state_store.save_workflow_plan(
            "quarantine_execution",
            str(result["plan_id"]),
            str(result["digest"]),
            result,
            expires_at=datetime.fromisoformat(str(result["expires_at"]).replace("Z", "+00:00")),
        )
        return result

    def cleanup_execute(payload: StrictModel, _context: RequestContext) -> object:
        assert isinstance(payload, ExecutePayload)
        authority = state_store.claim_workflow_plan(
            "quarantine_execution", payload.plan_id, expected_digest=payload.digest, reconcile=True
        )
        if authority.pop("_workflow_reconcile_required", False):
            from zombie_killer_engine.cleanup_workflow import _receipt_result

            existing = state_store.get_quarantine_receipt_for_plan(
                payload.plan_id, expected_digest=payload.digest
            )
            if existing is not None:
                result = _receipt_result(existing)
            else:
                result = {
                    "receipt_id": "quarantine-receipt-" + uuid4().hex,
                    "plan_id": payload.plan_id,
                    "kind": "quarantine",
                    "outcome": "interrupted",
                    "certainty": "uncertain",
                    "action_issued": None,
                    "partial_failures": ("Interrupted outcome requires journal review.",),
                    "created_at": datetime.now(UTC).isoformat(),
                }
        else:
            result = cleanup_workflow().execute(payload.plan_id, payload.digest)
        state_store.finish_workflow_plan("quarantine_execution", payload.plan_id, result)
        return result

    def cleanup_restore_plan(payload: StrictModel, _context: RequestContext) -> object:
        assert isinstance(payload, RestorePlanPayload)
        return cleanup_workflow().restore_plan(payload.entry_id)

    def cleanup_restore_execute(payload: StrictModel, _context: RequestContext) -> object:
        assert isinstance(payload, ExecutePayload)
        return cleanup_workflow().restore_execute(payload.plan_id, payload.digest)

    def vault_mutation_plan(payload: StrictModel, _context: RequestContext) -> object:
        assert isinstance(payload, VaultMutationPlanPayload)
        operation = MutationOperation(
            kind=MutationKind(payload.operation),
            record_id=payload.record_id,
            field=payload.field,
            metadata_key=payload.metadata_key,
            value=payload.value,
        )
        return memory_workflow.plan_mutation(
            payload.source_id, operation, payload.expected_revision
        )

    def vault_mutation_execute(payload: StrictModel, _context: RequestContext) -> object:
        assert isinstance(payload, ExecutePayload)
        return memory_workflow.execute_mutation(payload.plan_id, payload.digest)

    def vault_snapshot_list(payload: StrictModel, _context: RequestContext) -> object:
        assert isinstance(payload, VaultSnapshotListPayload)
        return memory_workflow.snapshots(payload.source_id, payload.limit)

    def vault_restore_plan(payload: StrictModel, _context: RequestContext) -> object:
        assert isinstance(payload, VaultRestorePlanPayload)
        return memory_workflow.plan_restore(
            payload.source_id,
            payload.snapshot_id,
            payload.snapshot_digest,
            payload.expected_revision,
        )

    def vault_restore_execute(payload: StrictModel, _context: RequestContext) -> object:
        assert isinstance(payload, ExecutePayload)
        return memory_workflow.execute_restore(payload.plan_id, payload.digest)

    def diagnostics_plan(payload: StrictModel, context: RequestContext) -> object:
        assert isinstance(payload, DiagnosticsExportPlanPayload)
        settings, revision = settings_snapshot()
        system = {
            "engine_version": ENGINE_VERSION,
            "protocol_version": PROTOCOL_VERSION,
            "platform": platform.system().casefold(),
            "doctor": doctor(EmptyPayload(), context),
            "settings": {**settings, "revision": revision},
            "receipts": cast(dict[str, object], activity_list(PagePayload(limit=20), context))[
                "receipts"
            ],
        }
        try:
            return diagnostics_workflow.plan(
                payload.destination,
                diagnostics=system,
                include_receipts=payload.include_receipts,
                include_settings=payload.include_settings,
            )
        except ValueError as error:
            if "already exists" in str(error):
                raise ServiceFault(
                    ErrorCode.CONFLICT, "The export destination already exists."
                ) from error
            raise

    def diagnostics_execute(payload: StrictModel, _context: RequestContext) -> object:
        assert isinstance(payload, ExecutePayload)
        return diagnostics_workflow.execute(payload.plan_id, payload.digest)

    def scan_list(payload: StrictModel, _context: RequestContext) -> object:
        assert isinstance(payload, ScanListPayload)
        settings, _revision = settings_snapshot()
        effective = (
            payload
            if "include_unmanaged" in payload.model_fields_set
            else payload.model_copy(
                update={"include_unmanaged": settings["include_unmanaged_candidates"]}
            )
        )
        return _scan_projection(scan_provider(), effective)

    handlers: dict[Method, Handler] = {
        Method.AGENT_DETAIL: agent_detail,
        Method.ACTIVITY_LIST: activity_list,
        Method.RECEIPT_GET: receipt_get,
        Method.QUARANTINE_LIST: quarantine_list,
        Method.QUARANTINE_RESOURCE_LIST: cleanup_resources,
        Method.QUARANTINE_PLAN: cleanup_plan,
        Method.QUARANTINE_EXECUTE: cleanup_execute,
        Method.QUARANTINE_RESTORE_PLAN: cleanup_restore_plan,
        Method.QUARANTINE_RESTORE_EXECUTE: cleanup_restore_execute,
        Method.VAULT_LIST: vault_list,
        Method.VAULT_REGISTER: vault_register,
        Method.VAULT_QUERY: vault_query,
        Method.VAULT_GET: vault_get,
        Method.VAULT_MUTATION_PLAN: vault_mutation_plan,
        Method.VAULT_MUTATION_EXECUTE: vault_mutation_execute,
        Method.VAULT_SNAPSHOT_LIST: vault_snapshot_list,
        Method.VAULT_RESTORE_PLAN: vault_restore_plan,
        Method.VAULT_RESTORE_EXECUTE: vault_restore_execute,
        Method.DIAGNOSTICS_EXPORT_PLAN: diagnostics_plan,
        Method.DIAGNOSTICS_EXPORT_EXECUTE: diagnostics_execute,
        Method.SCAN_LIST: scan_list,
        Method.SETTINGS_GET: settings_get,
        Method.SETTINGS_UPDATE: settings_update,
    }
    if process_actions_available:
        handlers.update(
            {
                Method.ACTION_PLAN: action_plan,
                Method.ACTION_EXECUTE: action_execute,
            }
        )
    implemented = {
        Method.SYSTEM_INFO,
        Method.DOCTOR,
        Method.SCAN_LIST,
        Method.VAULT_PROBE,
        *handlers,
    }

    def doctor(_payload: StrictModel, _context: RequestContext) -> object:
        unavailable = [method for method in Method if method not in implemented]
        return {
            "healthy": not unavailable,
            "checks": [
                {"name": f"method:{method.value}", "ok": method in implemented} for method in Method
            ],
            "warnings": [f"Unavailable capability: {method.value}." for method in unavailable],
        }

    handlers[Method.DOCTOR] = doctor

    def authorize(method: Method, plan_id: str, digest: str) -> bool:
        if method is Method.ACTION_EXECUTE:
            plan = state_store.get_plan(plan_id)
            return plan is not None and plan.digest == digest
        kinds = {
            Method.VAULT_MUTATION_EXECUTE: MUTATION_KIND,
            Method.VAULT_RESTORE_EXECUTE: RESTORE_KIND,
            Method.QUARANTINE_EXECUTE: "quarantine_execution",
            Method.QUARANTINE_RESTORE_EXECUTE: "quarantine_restore",
            Method.DIAGNOSTICS_EXPORT_EXECUTE: "diagnostics_export",
        }
        authority = state_store.get_workflow_plan(kinds[method], plan_id)
        return authority is not None and authority.get("digest") == digest

    return EngineService(
        handlers=handlers,
        execution_authorizer=authorize,
        scanner=scan_provider,
        paths=selected_paths,
        close_callback=state_store.close,
    )


__all__ = [
    "ENGINE_VERSION",
    "PROTOCOL_VERSION",
    "Capability",
    "ClientKind",
    "EngineService",
    "ErrorBody",
    "ErrorCode",
    "ExecutePayload",
    "Method",
    "PAYLOAD_MODELS",
    "RequestContext",
    "RequestEnvelope",
    "ResponseEnvelope",
    "ServiceFault",
    "build_default_service",
]
