import type {
  CleanupResourceSummary,
  Identifier,
  MethodPayloadMap,
  MethodResultMap,
  ReceiptSummary,
  VaultEditableField,
  VaultPlanPreview,
  VaultReceiptSummary,
} from "../src/types";

declare const agentId: Identifier;

export const validUnboundAgentDetail: MethodPayloadMap["agent.detail"] = {
  agent_id: agentId,
};

export const validBoundAgentDetail: MethodPayloadMap["agent.detail"] = {
  agent_id: agentId,
  expected_pid: 4242,
  expected_process_instance_id: "c".repeat(64),
};

// @ts-expect-error A process identity binding is all-or-nothing.
export const invalidPidOnlyAgentDetail: MethodPayloadMap["agent.detail"] = {
  agent_id: agentId,
  expected_pid: 4242,
};

// @ts-expect-error A process identity binding is all-or-nothing.
export const invalidInstanceOnlyAgentDetail: MethodPayloadMap["agent.detail"] = {
  agent_id: agentId,
  expected_process_instance_id: "c".repeat(64),
};

export const invalidNullAgentDetail: MethodPayloadMap["agent.detail"] = {
  agent_id: agentId,
  // @ts-expect-error Explicit null is not an omitted process identity binding.
  expected_pid: null,
  // @ts-expect-error Explicit null is not an omitted process identity binding.
  expected_process_instance_id: null,
};

export const validPartialReceipt: ReceiptSummary = {
  receipt_id: agentId,
  plan_id: agentId,
  outcome: "completed",
  certainty: "verified",
  action_issued: true,
  partial_failures: ["Cleanup verification failed."],
  created_at: "2026-08-12T12:00:00Z",
};

// @ts-expect-error Partial failures are explicit even when the receipt has none.
export const invalidReceiptWithoutPartialFailures: ReceiptSummary = {
  receipt_id: agentId,
  plan_id: agentId,
  outcome: "completed",
  certainty: "verified",
  action_issued: true,
  created_at: "2026-08-12T12:00:00Z",
};

export const validEditableString: VaultEditableField = {
  field: "content",
  kind: "update_content",
  value_type: "string",
  value: "reviewed content",
};

// @ts-expect-error Scalar editor values must agree with their declared type.
export const invalidEditableString: VaultEditableField = {
  field: "content",
  kind: "update_content",
  value_type: "string",
  value: true,
};

export const validMemoryPlan: VaultPlanPreview = {
  plan_id: agentId,
  digest: "a".repeat(64),
  expires_at: "2026-10-02T12:00:30Z",
  consequences: ["Update a reviewed scalar."],
  warnings: [],
  source_id: agentId,
  record_id: agentId,
  snapshot_id: null,
  before_revision: "b".repeat(64),
  backup_verified: true,
  diff: [{
    field_name: "content",
    old_hash: "b".repeat(64),
    new_hash: "c".repeat(64),
    old_preview: "[REDACTED]",
    new_preview: "[REDACTED]",
  }],
  local_only_warning: "Changes affect only local user-controlled memory; they do not change provider safety, rate limits, account state, or guarantee continuation.",
};

export const validMemoryReceipt: VaultReceiptSummary = {
  ...validPartialReceipt,
  kind: "memory",
  source_id: agentId,
  record_id: agentId,
  snapshot_id: null,
  before_revision: "a".repeat(64),
  after_revision: "b".repeat(64),
  operation: "update_content",
  local_only_warning: validMemoryPlan.local_only_warning,
};

export const invalidReceiptKind: ReceiptSummary = {
  ...validPartialReceipt,
  // @ts-expect-error Receipt kinds are finite and non-null when supplied.
  kind: "arbitrary",
};

export const validCleanupPlanPayload: MethodPayloadMap["quarantine.plan"] = {
  agent_id: agentId,
  resource_index: 0,
  expected_declaration_digest: "b".repeat(64),
};

export const invalidCleanupPlanPayload: MethodPayloadMap["quarantine.plan"] = {
  agent_id: agentId,
  resource_index: 0,
  expected_declaration_digest: "b".repeat(64),
  // @ts-expect-error Cleanup targets declared resource indices, not arbitrary paths.
  path: "C:/private",
};

export const validCleanupResourceList: MethodResultMap["quarantine.resource-list"] = {
  agent_id: agentId,
  returned: 1,
  resources: [{
    resource_index: 0,
    kind: "temporary",
    resource_type: "file",
    cleanup_available: true,
    reason: "Explicitly declared resource.",
    declaration_digest: "b".repeat(64),
  }],
};

export const validCleanupExecute: MethodPayloadMap["quarantine.execute"] = {
  plan_id: agentId,
  digest: "a".repeat(64),
};

export const validBoundCleanupResourceRequest: MethodPayloadMap["quarantine.resource-list"] = {
  agent_id: agentId,
  expected_pid: 4242,
  expected_process_instance_id: "c".repeat(64),
};

export const validBoundCleanupPlan: MethodPayloadMap["quarantine.plan"] = {
  ...validBoundCleanupResourceRequest,
  resource_index: 0,
  expected_declaration_digest: "b".repeat(64),
};

// @ts-expect-error An index does not identify the exact declaration reviewed by the operator.
export const invalidCleanupPlanWithoutDeclarationDigest: MethodPayloadMap["quarantine.plan"] = {
  agent_id: agentId,
  resource_index: 0,
};

// @ts-expect-error Cleanup process bindings are complete or omitted, never half-present.
export const invalidCleanupResourcePidOnly: MethodPayloadMap["quarantine.resource-list"] = {
  agent_id: agentId,
  expected_pid: 4242,
};

// @ts-expect-error Cleanup plan process bindings are complete or omitted, never half-present.
export const invalidCleanupPlanInstanceOnly: MethodPayloadMap["quarantine.plan"] = {
  agent_id: agentId,
  resource_index: 0,
  expected_declaration_digest: "b".repeat(64),
  expected_process_instance_id: "c".repeat(64),
};

export const invalidCleanupResourceNullBinding: MethodPayloadMap["quarantine.resource-list"] = {
  agent_id: agentId,
  // @ts-expect-error Explicit null is not an omitted process identity binding.
  expected_pid: null,
  // @ts-expect-error Explicit null is not an omitted process identity binding.
  expected_process_instance_id: null,
};

export const validUnavailableCleanupResource: CleanupResourceSummary = {
  resource_index: 1,
  kind: "temporary",
  resource_type: "unknown",
  cleanup_available: false,
  reason: "Legacy declaration lacks cleanup authority.",
  declaration_digest: null,
};

// @ts-expect-error Every listed declaration carries a digest or explicit unavailability.
export const invalidCleanupResourceWithoutDigest: CleanupResourceSummary = {
  resource_index: 1,
  kind: "temporary",
  resource_type: "unknown",
  cleanup_available: false,
  reason: "Legacy declaration lacks cleanup authority.",
};
