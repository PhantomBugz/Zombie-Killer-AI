export const agentStates = [
  'healthy',
  'idle',
  'stale',
  'orphaned',
  'unresponsive',
  'unmanaged',
  'interrupted',
  'defunct',
  'completed',
  'failed',
  'cancelled',
  'unknown',
] as const

export type AgentState = (typeof agentStates)[number]
export type Confidence = 'high' | 'medium' | 'low'
export type EvidenceGrade = 'verified' | 'corroborated' | 'inferred' | 'unverified'
export type ActionKind = 'graceful-stop' | 'force-stop'
export type TransportMode = 'demo' | 'native'

export const MAX_PROCESS_ID = 4_294_967_295

export function isProcessId(value: unknown): value is number {
  return typeof value === 'number'
    && Number.isInteger(value)
    && value > 0
    && value <= MAX_PROCESS_ID
}

export interface TransportCapabilities {
  processActions: boolean
  processActionsUnavailableReason: string | null
  activity: boolean
  quarantineRestore: boolean
  vaultRead: boolean
  vaultMutation: boolean
  memoryHistory: boolean
  settingsUpdate: boolean
  diagnosticsExport: boolean
  sourceRegistration?: boolean
  resourceCleanup?: boolean
}

export interface EvidenceSignal {
  id: string
  label: string
  source: string
  observedAt: string
  grade: EvidenceGrade
  detail: string
}

export interface ResourcePoint {
  observedAt: string
  ramMb: number
  cpuPercent: number
}

export interface TimelineEvent {
  id: string
  at: string
  title: string
  detail: string
  kind: 'state' | 'heartbeat' | 'action' | 'artifact'
}

export type MemorySourceStatus = 'Healthy' | 'Read-only' | 'Backup missing' | 'Needs re-index' | 'Corrupt' | 'Unsupported'
export type MemoryOperation = 'update' | 'exclude' | 'quarantine' | 'restore'

export interface MemorySource {
  id: string
  name: string
  kind: 'JSON' | 'JSONL' | 'SQLite' | 'Chroma' | 'FAISS' | 'Unsupported'
  project: string | null
  revision: number | string
  revisionDigest?: string
  status: MemorySourceStatus
  capabilities: Array<'search' | 'edit' | 'snapshot' | 'restore'>
  detail: string
}

export interface MemoryRecord {
  id: string
  sourceId: string
  revision: number | string
  sourceRevisionDigest?: string
  title: string
  content: string
  tags: string[]
  collection: string
  agent: string | null
  writer: string | null
  updatedAt: string | null
  referencedSessions: string[] | null
  references: string[] | null
  embedding: 'Present' | 'Not present'
  excluded: boolean | null
  quarantined: boolean | null
  syntheticError?: string
  editableFields?: NativeScalarField[]
}

export interface MemorySearchRequest {
  query: string
  sourceId?: string
  tag?: string
  collection?: string
  agent?: string
  from?: string
  to?: string
  page: number
  pageSize: number
  cursor?: string | null
}

export interface MemorySearchResult {
  capturedAt: string | null
  page: number
  pageSize: number
  total: number
  records: MemoryRecord[]
  nextCursor: string | null
}

export type AgentIdentityBinding = Pick<AgentSummary, 'id' | 'revision' | 'pid' | 'processInstanceId'>

export interface MemoryChangeRequest {
  sourceId: string
  recordId: string
  operation: Exclude<MemoryOperation, 'restore'>
  expectedSourceRevision: number
  expectedRecordRevision: number
  changes: Partial<Pick<MemoryRecord, 'title' | 'content' | 'tags' | 'collection'>>
}

export interface FieldDiff { field: string; oldValue: unknown; newValue: unknown }
export interface MemorySnapshot { id: string; verified: true; recordId: string; sourceRevision: number; recordRevision: number }
export interface MemoryPlan {
  planId: string
  digest: string
  expiresAt: string
  operation: Exclude<MemoryOperation, 'restore'>
  sourceId: string
  recordId: string
  expectedSourceRevision: number
  expectedRecordRevision: number
  diff: FieldDiff[]
  snapshot: MemorySnapshot
}

export interface MemoryReceipt {
  receiptId: string
  correlationId: string
  planId: string
  sourceId: string
  recordId: string
  operation: MemoryOperation
  completedAt: string
  snapshotId: string
  beforeRevision: number
  afterRevision: number
  restoredFromReceiptId?: string
}

export interface MemoryHistoryEntry {
  id: string
  sourceId: string
  recordId: string
  revision: number
  at: string
  operation: MemoryOperation | 'created'
  actor: string
  summary: string
  receiptId?: string
  snapshotId?: string
  restorable: boolean
}

export interface RestorePlan {
  planId: string
  digest: string
  expiresAt: string
  receiptId: string
  snapshotId: string
  sourceId: string
  recordId: string
  expectedRecordRevision: number
  expectedSourceRevision: number
}

export interface RestorePlanRequest { receiptId: string; snapshotId: string; expectedRecordRevision: number }
export interface PlanExecutionRequest { planId: string; digest: string }

export interface ActivityEvent {
  id: string
  timestamp: string
  actor: string
  project: string | null
  target: string
  action: string
  result: 'Succeeded' | 'Partial' | 'Failed'
  correlationId: string
  detail: string
}

export interface QuarantineEntry {
  id: string
  agentId: string | null
  resourceType: string
  createdAt: string
  receiptId: string | null
  basename: string | null
  displayPath: string | null
  size: number | null
  hashPrefix: string | null
  digest: string | null
  retainedUntil: string | null
  state: 'Quarantined' | 'Restored' | 'Restoring' | 'Interrupted' | 'Partial'
  restorable: boolean | null
  revision: number | string
}

export interface GraveyardPlan { planId: string; digest: string; expiresAt: string; entryId: string; entryDigest: string | null; expectedRevision: number | string | null; consequences?: string[]; warnings?: string[] }
export interface GraveyardReceipt { receiptId: string; correlationId: string; entryId: string; result: 'Restored'; completedAt: string }

export type DetectionPreset = 'Conservative' | 'Balanced' | 'Aggressive'
export type ThemePreference = 'system' | 'light' | 'dark'
export type MotionPreference = 'system' | 'reduce' | 'full'
export interface AppSettings {
  revision: number
  detectionPreset: DetectionPreset | null
  theme: ThemePreference
  motion: MotionPreference
  denseMode: boolean | null
  autoRefreshSeconds: number
  quarantineRetentionDays: number
  heartbeatGraceSeconds?: number
  includeUnmanagedCandidates?: boolean
}

export interface AgentSummary {
  id: string
  revision: number | string
  role: string | null
  project: string | null
  provider: string | null
  runtime: string | null
  pid: number | null
  processInstanceId: string | null
  host: string | null
  processStartedAt: string | null
  executable: string | null
  state: AgentState
  confidence: Confidence
  evidenceGrade: EvidenceGrade
  diagnosis: string
  actionable: boolean
  actionReason: string
  heartbeatAt: string | null
  ramMb: number | null
  network: 'observed' | 'not-observed' | 'unknown'
  evidence: EvidenceSignal[]
}

export interface AgentDetail extends AgentSummary {
  currentTask: string | null
  processTree: Array<{ pid: number; name: string; relationship: 'target' | 'child'; status: 'running' | 'interrupted' | 'unknown' }>
  heartbeatHistory: Array<{ at: string; result: 'received' | 'missed' }>
  commandLine: string | null
  ports: Array<{ port: number; protocol: 'TCP' | 'UDP'; status: string }>
  fileWrites: Array<{ path: string; at: string; status: 'observed' | 'quarantined' }>
  resources: ResourcePoint[]
  timeline: TimelineEvent[]
  partialSections: string[]
}

export interface Coverage {
  completeness: 'complete' | 'partial'
  blindSpotCount: number
  observedProcessCount: number
  totalProcessCount: number | null
  blindSpots: string[]
}

export interface ScanResult {
  mode: TransportMode
  revision: string
  capturedAt: string
  coverage: Coverage
  agents: AgentSummary[]
  evidence: EvidenceSignal[]
  metrics: { active: number; needsAttention: number; unmanaged: number; reclaimableMb: number | null }
  usage: { requests: number | null; inputTokens: number | null; outputTokens: number | null; costUsd: number | null }
  resources: ResourcePoint[]
  timeline: TimelineEvent[]
  receipts: ContainmentReceipt[]
}

export interface ScanRequest {
  includeUnmanagedCandidates?: boolean
}

export interface ActionTarget {
  pid: number
  processInstanceId: string
}

export interface PlannedActionTarget extends ActionTarget {
  state: AgentState
}

export interface ActionPlan {
  planId: string
  agentId: string
  digest: string
  createdAt: string | null
  expiresAt: string
  kind: ActionKind
  engineMode: 'request_stop' | 'terminate' | 'kill'
  target: PlannedActionTarget
  strategy: string
  timeoutSeconds: number | null
  expectedPortsReleased: number[] | null
  eligibleQuarantineFiles: string[] | null
  memoryEffect: 'unchanged'
  irreversibleConsequences: string[]
}

export interface ContainmentReceipt {
  receiptId: string
  planId: string
  title: 'Containment complete' | 'Containment partially completed' | 'Containment issued' | 'Outcome uncertain' | 'Containment not issued'
  completedAt: string
  agentId: string | null
  processCount: number | null
  portCount: number | null
  fileCount: number | null
  memoryEffect: 'unchanged'
  diagnostics: string
  partialFailures: string[]
  outcome?: string
  certainty?: 'verified' | 'failed_before_issue' | 'uncertain'
  actionIssued?: boolean | null
}

export interface PlanRequest { agentId: string; kind: ActionKind; target: ActionTarget }
export interface ExecuteRequest { planId: string; digest: string }

export interface ActivityResult {
  localReceipts?: LocalWorkflowReceipt[]
  capturedAt: string | null
  events: ActivityEvent[]
  receipts: ContainmentReceipt[]
  memoryReceipts: MemoryReceipt[]
  quarantine: QuarantineEntry[]
  graveyardReceipts: GraveyardReceipt[]
  pagination: {
    activityTruncated: boolean
    quarantineTruncated: boolean
  }
}

export interface VaultResult {
  mode: TransportMode
  capturedAt: string | null
  sources: MemorySource[]
}

export type ScalarValue = string | number | boolean | null
export interface NativeScalarField {
  field: string
  kind: 'update_content' | 'update_field' | 'update_metadata'
  valueType: 'string' | 'number' | 'boolean' | 'null'
  value: ScalarValue
}
export interface LocalWorkflowPlan {
  planId: string
  digest: string
  expiresAt: string
  consequences: string[]
  warnings: string[]
  sourceId?: string
  recordId?: string
  snapshotId?: string
  beforeRevision?: string
  backupVerified?: boolean
  diff?: Array<{ field: string; oldHash: string; newHash: string; oldPreview: string; newPreview: string }>
}
export interface LocalWorkflowReceipt {
  receiptId: string
  planId: string
  outcome: string
  certainty: 'verified' | 'failed_before_issue' | 'uncertain'
  actionIssued: boolean | null
  partialFailures: string[]
  createdAt: string
  sourceId?: string
  recordId?: string
  snapshotId?: string
  beforeRevision?: string
  afterRevision?: string
  operation?: string
  kind?: 'process' | 'memory' | 'quarantine' | 'diagnostics'
}

const verifiedLocalSuccessOutcomes = new Set(['completed', 'quarantined', 'restored', 'already_restored', 'exported', 'already_exported'])
export function isVerifiedLocalSuccess(receipt: Pick<LocalWorkflowReceipt, 'outcome' | 'certainty' | 'partialFailures'>): boolean {
  return receipt.certainty === 'verified' && receipt.partialFailures.length === 0 && verifiedLocalSuccessOutcomes.has(receipt.outcome)
}
export interface NativeSnapshot {
  id: string
  sourceId: string
  sourceRevision: string
  digest: string
  size: number
  status: 'verified' | 'restored' | 'invalid'
  createdAt: string
}
export interface DeclaredResource {
  id: string
  resourceType: string
  label: string
  eligible: boolean
  reason: string | null
}

export interface EngineTransport {
  readonly mode: TransportMode
  readonly capabilities: TransportCapabilities
  scan(request?: ScanRequest): Promise<ScanResult>
  getAgentDetail(agentId: string, expected?: AgentIdentityBinding): Promise<AgentDetail>
  planAction(request: PlanRequest): Promise<ActionPlan>
  executeAction(request: ExecuteRequest): Promise<ContainmentReceipt>
  getActivity(): Promise<ActivityResult>
  getVault(): Promise<VaultResult>
  searchMemory(request: MemorySearchRequest): Promise<MemorySearchResult>
  getMemoryRecord(sourceId: string, recordId: string): Promise<MemoryRecord>
  getMemoryHistory(sourceId: string, recordId: string): Promise<MemoryHistoryEntry[]>
  planMemoryChange(request: MemoryChangeRequest): Promise<MemoryPlan>
  executeMemoryChange(request: PlanExecutionRequest): Promise<MemoryReceipt>
  planMemoryRestore(request: RestorePlanRequest): Promise<RestorePlan>
  executeMemoryRestore(request: PlanExecutionRequest): Promise<MemoryReceipt>
  planGraveyardRestore(entryId: string): Promise<GraveyardPlan>
  executeGraveyardRestore(request: PlanExecutionRequest): Promise<GraveyardReceipt>
  getSettings(): Promise<AppSettings>
  updateSettings(request: { expectedRevision: number; changes: Partial<Omit<AppSettings, 'revision'>> }): Promise<AppSettings>
  resetSettings(expectedRevision: number): Promise<AppSettings>
  registerMemorySource?(path: string): Promise<void>
  getNativeSnapshots?(sourceId: string): Promise<NativeSnapshot[]>
  planNativeMemoryChange?(request: { sourceId: string; recordId: string; expectedRevision: string; field: NativeScalarField; value: ScalarValue }): Promise<LocalWorkflowPlan>
  executeNativeMemoryChange?(request: PlanExecutionRequest): Promise<LocalWorkflowReceipt>
  planNativeMemoryRestore?(request: { sourceId: string; snapshotId: string; snapshotDigest: string; expectedRevision: string }): Promise<LocalWorkflowPlan>
  executeNativeMemoryRestore?(request: PlanExecutionRequest): Promise<LocalWorkflowReceipt>
  executeNativeGraveyardRestore?(request: PlanExecutionRequest): Promise<LocalWorkflowReceipt>
  getDeclaredResources?(agentId: string, expected: AgentIdentityBinding): Promise<DeclaredResource[]>
  planResourceCleanup?(agentId: string, resourceId: string, expected: AgentIdentityBinding): Promise<LocalWorkflowPlan>
  executeResourceCleanup?(request: PlanExecutionRequest): Promise<LocalWorkflowReceipt>
  planDiagnosticsExport?(destination: string): Promise<LocalWorkflowPlan>
  executeDiagnosticsExport?(request: PlanExecutionRequest): Promise<LocalWorkflowReceipt>
}

export type TransportErrorCode =
  | 'invalid_request'
  | 'not_found'
  | 'not_actionable'
  | 'plan_changed'
  | 'plan_expired'
  | 'plan_replayed'
  | 'target_changed'
  | 'partial_failure'
  | 'source_changed'
  | 'schema_invalid'
  | 'conflict'
  | 'permission_denied'
  | 'expired'
  | 'unsupported'
  | 'partial'
  | 'engine_unavailable'
  | 'engine_timeout'
  | 'output_too_large'
  | 'protocol_violation'
  | 'outcome_uncertain'
  | 'internal'

export class TransportError extends Error {
  readonly code: TransportErrorCode
  readonly recoverable: boolean
  readonly details?: Record<string, unknown>

  constructor(code: TransportErrorCode, message: string, recoverable = true, details?: Record<string, unknown>) {
    super(message)
    this.name = 'TransportError'
    this.code = code
    this.recoverable = recoverable
    this.details = details
  }
}
