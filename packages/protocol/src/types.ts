export const PROTOCOL_VERSION = "1.0" as const;
export const MAX_INPUT_FRAME_BYTES = 1024 * 1024;
export const MAX_OUTPUT_FRAME_BYTES = 4 * 1024 * 1024;

export type ProtocolVersion = typeof PROTOCOL_VERSION;
declare const identifierBrand: unique symbol;
declare const localPathBrand: unique symbol;
export type Identifier = string & { readonly [identifierBrand]: "no outer whitespace" };
export type LocalPath = string & { readonly [localPathBrand]: "approved local path" };
export type Digest = string;
export type Method =
  | "system.info"
  | "doctor"
  | "scan.list"
  | "agent.detail"
  | "action.plan"
  | "action.execute"
  | "activity.list"
  | "receipt.get"
  | "quarantine.list"
  | "quarantine.resource-list"
  | "quarantine.plan"
  | "quarantine.execute"
  | "quarantine.restore-plan"
  | "quarantine.restore-execute"
  | "vault.list"
  | "vault.register"
  | "vault.probe"
  | "vault.query"
  | "vault.get"
  | "vault.mutation.plan"
  | "vault.mutation.execute"
  | "vault.snapshot.list"
  | "vault.restore.plan"
  | "vault.restore.execute"
  | "settings.get"
  | "settings.update"
  | "diagnostics.export-plan"
  | "diagnostics.export-execute";

export type AgentState =
  | "healthy"
  | "idle"
  | "stale"
  | "orphaned"
  | "unresponsive"
  | "unmanaged"
  | "interrupted"
  | "defunct"
  | "completed"
  | "failed"
  | "cancelled"
  | "unknown";

export type EvidenceGrade =
  | "confirmed"
  | "strong"
  | "partial"
  | "signature_only"
  | "insufficient";

export interface Evidence {
  code: string;
  grade: EvidenceGrade;
  observed_at: string;
  detail: string;
}

export interface ScanCoverage {
  inspected_count: number;
  denied_count: number;
  vanished_count: number;
  malformed_lease_count: number;
  lease_file_count: number;
  skipped_lease_count: number;
  other_user_count: number;
  unknown_owner_count: number;
  identity_denied_count: number;
  complete: boolean;
  captured_at: string;
  current_boot_id: string;
  warnings: ReadonlyArray<{ code: string; message: string }>;
}

export type UsageCost =
  | { availability: "known"; amount_usd: number; note: string }
  | { availability: "unknown"; amount_usd: null; note: string };

export interface AgentSummary {
  agent_id: Identifier | null;
  provider: string | null;
  project: string | null;
  role: string | null;
  state: AgentState;
  evidence_grade: EvidenceGrade;
  confidence: number;
  reason_codes: ReadonlyArray<string>;
  explanation: string;
  evidence: ReadonlyArray<Evidence>;
  actionable: boolean;
  managed: boolean;
  pid: number | null;
  process_instance_id: string | null;
  process_name: string | null;
  os_status: string | null;
  usage_cost: UsageCost;
}

export interface ScanResult {
  agents: ReadonlyArray<AgentSummary>;
  coverage: ScanCoverage;
  returned: number;
  total: number;
}

export type ReceiptCertainty = "verified" | "failed_before_issue" | "uncertain";
export type ReceiptKind = "process" | "memory" | "quarantine" | "diagnostics";

export interface ReceiptSummary {
  receipt_id: Identifier;
  plan_id: Identifier;
  outcome: string;
  certainty: ReceiptCertainty;
  action_issued: boolean | null;
  partial_failures: ReadonlyArray<string>;
  created_at: string;
  /** Omission retains the protocol 1.0 default of process. */
  kind?: ReceiptKind;
}

export interface PlanPreview {
  plan_id: Identifier;
  digest: string;
  expires_at: string;
  consequences: ReadonlyArray<string>;
  warnings: ReadonlyArray<string>;
}

export interface ProcessInstanceTarget {
  /** Unsigned 32-bit OS process identifier (1 through 4,294,967,295). */
  pid: number;
  process_instance_id: string;
}

export interface ActionPlanTarget extends ProcessInstanceTarget {
  state: AgentState;
}

export interface ActionPlanPreview extends PlanPreview {
  target: ActionPlanTarget;
}

export interface VaultProbeResult {
  format: "json" | "jsonl" | "sqlite" | "chroma" | "faiss" | "unsupported";
  recognized: boolean;
  capabilities: {
    readable: boolean;
    queryable: boolean;
    editable: boolean;
    snapshot: boolean;
    restore: boolean;
    reason: string | null;
  };
  reason: string | null;
  read_only: true;
  selected_locally: true;
  local_only_warning: VaultLocalOnlyWarning;
}

export const VAULT_LOCAL_ONLY_WARNING = "Changes affect only local user-controlled memory; they do not change provider safety, rate limits, account state, or guarantee continuation." as const;
export type VaultLocalOnlyWarning = typeof VAULT_LOCAL_ONLY_WARNING;

export type JsonValue =
  | string
  | number
  | boolean
  | null
  | ReadonlyArray<JsonValue>
  | { readonly [key: string]: JsonValue };

interface QuarantineEntryBase {
  entry_id: string;
  agent_id: string;
  resource_type: "file" | "directory";
  created_at: string;
  updated_at: string;
}

export type QuarantineEntrySummary = QuarantineEntryBase & (
  | { state: "quarantined"; restorable: boolean }
  | { state: "partial" | "restoring" | "restored" | "interrupted"; restorable: false }
);

export interface VaultSourceSummary {
  source_id: string;
  format: VaultProbeResult["format"];
  capabilities: VaultProbeResult["capabilities"];
  revision: string;
}

export interface VaultRecord {
  record_id: string;
  namespace: string;
  content: string;
  metadata: Readonly<Record<string, JsonValue>>;
  embedding_present: boolean;
  source_revision: string;
  editable_fields?: ReadonlyArray<VaultEditableField>;
}

export type VaultEditableField = {
  field: string;
  kind: "update_content" | "update_field" | "update_metadata";
} & (
  | { value_type: "string"; value: string }
  | { value_type: "number"; value: number }
  | { value_type: "boolean"; value: boolean }
  | { value_type: "null"; value: null }
);

export interface VaultDiff {
  field_name: string;
  old_hash: Digest;
  new_hash: Digest;
  old_preview: "[REDACTED]";
  new_preview: "[REDACTED]";
}

export interface VaultPlanPreview extends PlanPreview {
  local_only_warning: VaultLocalOnlyWarning;
  source_id?: Identifier | null;
  record_id?: Identifier | null;
  snapshot_id?: Identifier | null;
  before_revision?: Digest | null;
  backup_verified?: boolean;
  diff?: ReadonlyArray<VaultDiff>;
}

export interface VaultReceiptSummary extends ReceiptSummary {
  local_only_warning: VaultLocalOnlyWarning;
  source_id?: Identifier | null;
  record_id?: Identifier | null;
  snapshot_id?: Identifier | null;
  before_revision?: Digest | null;
  after_revision?: Digest | null;
  operation?: string | null;
}

export interface CleanupResourceSummary {
  resource_index: number;
  kind: "temporary";
  resource_type: "file" | "directory" | "unknown";
  cleanup_available: boolean;
  reason: string;
  declaration_digest: Digest | null;
}

export interface CleanupResourceListResult {
  agent_id: Identifier;
  resources: ReadonlyArray<CleanupResourceSummary>;
  returned: number;
}

export interface SnapshotSummary {
  snapshot_id: string;
  source_id: string;
  source_revision: string;
  digest: string;
  size: number;
  status: "verified" | "restored" | "invalid";
  created_at: string;
}

export interface Settings {
  scan_interval_seconds: number;
  heartbeat_grace_seconds: number;
  retention_days: number;
  include_unmanaged_candidates: boolean;
  appearance: "system" | "light" | "dark";
  reduced_motion: boolean;
}

export type EmptyPayload = Record<string, never>;
export interface PagePayload { cursor?: string | null; limit?: number }
export interface ExecutePayload { plan_id: Identifier; digest: string }
export interface SettingsUpdatePayload {
  expected_revision: number;
  scan_interval_seconds?: number;
  heartbeat_grace_seconds?: number;
  retention_days?: number;
  include_unmanaged_candidates?: boolean;
  appearance?: "system" | "light" | "dark";
  reduced_motion?: boolean;
}

export interface SettingsResult {
  settings: Settings;
  revision: number;
}

export type AgentDetailPayload =
  | {
      agent_id: Identifier;
      expected_pid?: never;
      expected_process_instance_id?: never;
    }
  | {
      agent_id: Identifier;
      expected_pid: number;
      expected_process_instance_id: Digest;
    };

export type CleanupResourceListPayload = AgentDetailPayload;

export type CleanupPlanPayload = CleanupResourceListPayload & {
  resource_index: number;
  expected_declaration_digest: Digest;
};

export interface MethodPayloadMap {
  "system.info": EmptyPayload;
  doctor: EmptyPayload;
  "scan.list": { include_unmanaged?: boolean; limit?: number };
  "agent.detail": AgentDetailPayload;
  "action.plan": { agent_id: Identifier; mode: "request_stop" | "terminate" | "kill"; target: ProcessInstanceTarget };
  "action.execute": ExecutePayload;
  "activity.list": PagePayload;
  "receipt.get": { receipt_id: string };
  "quarantine.list": PagePayload;
  "quarantine.resource-list": CleanupResourceListPayload;
  "quarantine.plan": CleanupPlanPayload;
  "quarantine.execute": ExecutePayload;
  "quarantine.restore-plan": { entry_id: string };
  "quarantine.restore-execute": ExecutePayload;
  "vault.list": PagePayload;
  "vault.register": { path: LocalPath };
  "vault.probe": { path: LocalPath };
  "vault.query": { source_id: string; namespace?: string | null; text?: string | null; cursor?: string | null; limit?: number };
  "vault.get": { source_id: string; record_id: string };
  "vault.mutation.plan": { source_id: string; expected_revision: string; operation: "update_content" | "update_field" | "update_metadata" | "exclude_from_retrieval" | "quarantine" | "restore_record"; record_id: string; field?: string | null; metadata_key?: string | null; value?: string | number | boolean | null };
  "vault.mutation.execute": ExecutePayload;
  "vault.snapshot.list": { source_id: string; limit?: number };
  "vault.restore.plan": { source_id: string; snapshot_id: string; snapshot_digest: string; expected_revision: string };
  "vault.restore.execute": ExecutePayload;
  "settings.get": EmptyPayload;
  "settings.update": SettingsUpdatePayload;
  "diagnostics.export-plan": { destination: string; include_receipts?: boolean; include_settings?: boolean };
  "diagnostics.export-execute": ExecutePayload;
}

export interface MethodResultMap {
  "system.info": { engine_version: string; protocol_version: ProtocolVersion; platform: string; python: string; local_only: true; network_listener: false; memory_warning: string };
  doctor: { healthy: boolean; checks: ReadonlyArray<{ name: string; ok: boolean }>; warnings: ReadonlyArray<string> };
  "scan.list": ScanResult;
  "agent.detail": AgentSummary;
  "action.plan": ActionPlanPreview;
  "action.execute": ReceiptSummary;
  "activity.list": { receipts: ReadonlyArray<ReceiptSummary>; next_cursor: string | null };
  "receipt.get": ReceiptSummary;
  "quarantine.list": { entries: ReadonlyArray<QuarantineEntrySummary>; next_cursor: string | null };
  "quarantine.resource-list": CleanupResourceListResult;
  "quarantine.plan": PlanPreview;
  "quarantine.execute": ReceiptSummary;
  "quarantine.restore-plan": PlanPreview;
  "quarantine.restore-execute": ReceiptSummary;
  "vault.list": { sources: ReadonlyArray<VaultSourceSummary>; local_only_warning: VaultLocalOnlyWarning; next_cursor: string | null };
  "vault.register": VaultProbeResult;
  "vault.probe": VaultProbeResult;
  "vault.query": { records: ReadonlyArray<VaultRecord>; next_cursor: string | null; total: number; local_only_warning: VaultLocalOnlyWarning };
  "vault.get": { record: VaultRecord; local_only_warning: VaultLocalOnlyWarning };
  "vault.mutation.plan": VaultPlanPreview;
  "vault.mutation.execute": VaultReceiptSummary;
  "vault.snapshot.list": { snapshots: ReadonlyArray<SnapshotSummary>; local_only_warning: VaultLocalOnlyWarning };
  "vault.restore.plan": VaultPlanPreview;
  "vault.restore.execute": VaultReceiptSummary;
  "settings.get": SettingsResult;
  "settings.update": SettingsResult;
  "diagnostics.export-plan": PlanPreview & { excluded_by_default: ReadonlyArray<"command_lines" | "memory_contents" | "paths" | "secrets"> };
  "diagnostics.export-execute": ReceiptSummary;
}

export type Request<M extends Method = Method> = M extends Method ? {
  protocol_version: ProtocolVersion;
  request_id: string;
  method: M;
  payload: MethodPayloadMap[M];
} : never;

export type ErrorCode =
  | "invalid_request"
  | "not_found"
  | "conflict"
  | "target_changed"
  | "permission_denied"
  | "expired"
  | "unsupported"
  | "partial"
  | "internal";

export type ErrorDetailKey =
  | "correlation_id"
  | "field"
  | "reason"
  | "supported_version"
  | "redacted_detail_1"
  | "redacted_detail_2"
  | "redacted_detail_3"
  | "redacted_detail_4"
  | "redacted_detail_5"
  | "redacted_detail_6"
  | "redacted_detail_7"
  | "redacted_detail_8"
  | "redacted_detail_9"
  | "redacted_detail_10"
  | "redacted_detail_11"
  | "redacted_detail_12"
  | "redacted_detail_13"
  | "redacted_detail_14"
  | "redacted_detail_15"
  | "redacted_detail_16";

export interface ProtocolError {
  code: ErrorCode;
  message: string;
  retryable: boolean;
  details: Readonly<Partial<Record<ErrorDetailKey, string | number | boolean | null>>>;
}

export type SuccessResponse<M extends Method> = M extends Method ? {
  protocol_version: ProtocolVersion;
  request_id: string;
  method: M;
  ok: true;
  result: MethodResultMap[M];
  error: null;
} : never;

export interface ErrorResponse {
  protocol_version: ProtocolVersion;
  request_id: string;
  method: Method | null;
  ok: false;
  result: null;
  error: ProtocolError;
}

export type Response<M extends Method = Method> = M extends Method
  ? SuccessResponse<M> | ErrorResponse
  : never;
