import type {
  ActionPlan,
  AgentIdentityBinding,
  ActivityResult,
  AgentDetail,
  AgentSummary,
  ContainmentReceipt,
  EngineTransport,
  FieldDiff,
  ExecuteRequest,
  PlanRequest,
  ScanResult,
  VaultResult,
  ActivityEvent,
  AppSettings,
  DetectionPreset,
  GraveyardPlan,
  GraveyardReceipt,
  MemoryChangeRequest,
  MemoryHistoryEntry,
  MemoryPlan,
  MemoryReceipt,
  MemoryRecord,
  MemorySearchRequest,
  MemorySnapshot,
  MemorySource,
  PlanExecutionRequest,
  QuarantineEntry,
  RestorePlan,
  RestorePlanRequest,
  ScanRequest,
  TransportCapabilities,
} from './types'
import { TransportError, isProcessId } from './types'

export interface DemoTransportOptions {
  latencyMs?: number
  now?: () => Date
  id?: (prefix: string) => string
}

const fixtureCapturedAt = '2026-08-12T16:00:00.000Z'

type DemoMemorySource = MemorySource & { project: string; revision: number }
type DemoMemoryRecord = MemoryRecord & {
  revision: number
  agent: string
  writer: string
  updatedAt: string
  excluded: boolean
  quarantined: boolean
}
type DemoSettings = AppSettings & {
  revision: number
  detectionPreset: DetectionPreset
  denseMode: boolean
}
type DemoQuarantineEntry = QuarantineEntry & {
  basename: string
  digest: string
  revision: number
}
type DemoActionPlan = ActionPlan & {
  createdAt: string
  timeoutSeconds: number
  expectedPortsReleased: number[]
  eligibleQuarantineFiles: string[]
}

interface DemoPlanIdentity {
  revision: number | string
  processStartedAt: string
  executable: string
  childCount: number
}

const memorySources: DemoMemorySource[] = [
  { id: 'mtga-json', name: 'MTGA JSON memory', kind: 'JSON', project: 'MTGA Cardbot', revision: 4, status: 'Healthy', capabilities: ['search', 'edit', 'snapshot', 'restore'], detail: 'Synthetic local demo records with verified snapshot support.' },
  { id: 'mev-sqlite', name: 'Mev BOT SQLite memory', kind: 'SQLite', project: 'Mev BOT', revision: 2, status: 'Backup missing', capabilities: ['search'], detail: 'Read-only because the required local backup is missing.' },
]

const memoryRecords: DemoMemoryRecord[] = [
  { id: 'card-0001', sourceId: 'mtga-json', revision: 2, title: 'Lightning Drake', content: 'Synthetic card-search result: flying creature with a safe demo note.', tags: ['card', 'flying', 'blue'], collection: 'card-search', agent: 'mtga-search', writer: 'Search Bot', updatedAt: '2026-08-12T15:42:00.000Z', referencedSessions: ['demo-session-17'], references: ['catalog:lightning-drake'], embedding: 'Present', excluded: false, quarantined: false },
  { id: 'card-0002', sourceId: 'mtga-json', revision: 1, title: 'Forest Guardian', content: 'Synthetic card-search result for a green defender.', tags: ['card', 'green'], collection: 'card-search', agent: 'mtga-search', writer: 'Search Bot', updatedAt: '2026-08-12T15:43:00.000Z', referencedSessions: [], references: ['catalog:forest-guardian'], embedding: 'Not present', excluded: false, quarantined: false },
  { id: 'card-0003', sourceId: 'mtga-json', revision: 3, title: 'Sky Archive', content: 'Synthetic flying card search retained for regression coverage.', tags: ['card', 'flying', 'artifact'], collection: 'card-search', agent: 'mtga-search', writer: 'Indexer', updatedAt: '2026-08-12T15:44:00.000Z', referencedSessions: ['demo-session-19'], references: ['catalog:sky-archive'], embedding: 'Present', excluded: false, quarantined: false },
  { id: 'stale-0001', sourceId: 'mtga-json', revision: 1, title: 'Synthetic stale error record', content: 'An intentionally stale demo record for honest recovery testing.', tags: ['error', 'stale'], collection: 'diagnostics', agent: 'mtga-search', writer: 'Demo fixture', updatedAt: '2026-08-12T15:45:00.000Z', referencedSessions: [], references: [], embedding: 'Not present', excluded: false, quarantined: false, syntheticError: 'Needs re-index: source revision changed during the synthetic write.' },
]

const defaultSettings: DemoSettings = { revision: 1, detectionPreset: 'Balanced', theme: 'system', motion: 'system', denseMode: false, autoRefreshSeconds: 30, quarantineRetentionDays: 30, heartbeatGraceSeconds: 120, includeUnmanagedCandidates: true }

function historicalReceipt(now: Date): ContainmentReceipt {
  return { receiptId: 'receipt-demo-existing', planId: 'plan-demo-existing', title: 'Containment complete', completedAt: new Date(now.getTime() - 3_600_000).toISOString(), agentId: 'mev-screenshot', processCount: 2, portCount: 1, fileCount: 1, memoryEffect: 'unchanged', diagnostics: 'Existing synthetic demo containment receipt; no OS mutation.', partialFailures: [] }
}
function historicalQuarantine(now: Date): DemoQuarantineEntry {
  return { id: 'quarantine-demo-existing', agentId: 'mev-screenshot', resourceType: 'file', createdAt: new Date(now.getTime() - 3_600_000).toISOString(), receiptId: 'receipt-demo-existing', basename: 'capture-old.png', displayPath: '[redacted]\\capture-old.png', size: 1536, hashPrefix: 'sha256:73ac140d22', digest: 'entry-digest-demo-existing', retainedUntil: new Date(now.getTime() + 30 * 86_400_000).toISOString(), state: 'Quarantined', restorable: true, revision: 1 }
}

const agentDetails: AgentDetail[] = [
  {
    id: 'mev-screenshot', revision: 0, role: 'ScreenShot Coordinator', project: 'Mev BOT', provider: 'OpenAI',
    runtime: 'Python 3.12', pid: 4188, processInstanceId: '1'.repeat(64), host: 'Local host', processStartedAt: '2026-08-12T14:07:11.000Z',
    executable: 'python.exe', state: 'orphaned', confidence: 'high', evidenceGrade: 'corroborated',
    diagnosis: 'The coordinator process is still running, but its owning session ended and three expected heartbeats were missed. This is an orphaned managed agent, not a POSIX defunct process.',
    actionable: true, actionReason: 'Process identity is verified by PID, start time, and executable.',
    heartbeatAt: '2026-08-12T15:56:42.000Z', ramMb: 684, network: 'observed',
    evidence: [
      { id: 'mev-own', label: 'Owner session ended', source: 'Session registry', observedAt: '2026-08-12T15:57:02.000Z', grade: 'verified', detail: 'Managed session zk-session-204 ended without a stop receipt.' },
      { id: 'mev-hb', label: '3 heartbeats missed', source: 'Heartbeat monitor', observedAt: '2026-08-12T16:00:00.000Z', grade: 'corroborated', detail: 'Last heartbeat was received 3m 18s ago.' },
      { id: 'mev-port', label: 'Port 4317 still open', source: 'Local socket table', observedAt: '2026-08-12T15:59:56.000Z', grade: 'verified', detail: 'TCP listener remains bound by the verified process identity.' },
    ],
    currentTask: 'Capture and coordinate synthetic opportunity screenshots',
    processTree: [{ pid: 4188, name: 'python.exe', relationship: 'target', status: 'running' }, { pid: 4204, name: 'chromium.exe', relationship: 'child', status: 'running' }],
    heartbeatHistory: [{ at: '2026-08-12T15:56:42.000Z', result: 'received' }, { at: '2026-08-12T15:57:42.000Z', result: 'missed' }, { at: '2026-08-12T15:58:42.000Z', result: 'missed' }, { at: '2026-08-12T15:59:42.000Z', result: 'missed' }],
    commandLine: 'python.exe -m screenshot_coordinator --token [REDACTED]',
    ports: [{ port: 4317, protocol: 'TCP', status: 'listening (local)' }],
    fileWrites: [{ path: 'C:\\Demo\\MevBOT\\captures\\frame-014.png', at: '2026-08-12T15:56:39.000Z', status: 'observed' }, { path: 'C:\\Demo\\MevBOT\\state\\coordinator.lock', at: '2026-08-12T15:56:41.000Z', status: 'observed' }],
    resources: [{ observedAt: '2026-08-12T15:58:00.000Z', ramMb: 671, cpuPercent: 2.4 }, { observedAt: '2026-08-12T16:00:00.000Z', ramMb: 684, cpuPercent: 1.8 }],
    timeline: [{ id: 'mev-t1', at: '2026-08-12T14:07:11.000Z', title: 'Agent started', detail: 'Managed process identity recorded.', kind: 'state' }, { id: 'mev-t2', at: '2026-08-12T15:57:42.000Z', title: 'Heartbeat missed', detail: 'First expected heartbeat did not arrive.', kind: 'heartbeat' }],
    partialSections: [],
  },
  {
    id: 'mtga-search', revision: 0, role: 'Search Bot', project: 'MTGA Cardbot', provider: 'Google Gemini',
    runtime: 'Node.js 24', pid: 7720, processInstanceId: '2'.repeat(64), host: 'Local host', processStartedAt: '2026-08-12T13:22:05.000Z',
    executable: 'node.exe', state: 'healthy', confidence: 'high', evidenceGrade: 'verified',
    diagnosis: 'The managed search agent is active and reporting normally.', actionable: true,
    actionReason: 'Process identity is verified by PID, start time, and executable.', heartbeatAt: '2026-08-12T15:59:54.000Z',
    ramMb: 238, network: 'observed',
    evidence: [
      { id: 'mtga-hb', label: 'Heartbeat current', source: 'Heartbeat monitor', observedAt: '2026-08-12T15:59:54.000Z', grade: 'verified', detail: 'Heartbeat arrived within the expected interval.' },
      { id: 'mtga-task', label: 'Task lease active', source: 'Agent registry', observedAt: '2026-08-12T15:59:50.000Z', grade: 'verified', detail: 'Search task lease is valid.' },
    ],
    currentTask: 'Index the synthetic MTGA card catalog', processTree: [{ pid: 7720, name: 'node.exe', relationship: 'target', status: 'running' }],
    heartbeatHistory: [{ at: '2026-08-12T15:59:54.000Z', result: 'received' }], commandLine: 'node.exe card-search.js --api-key [REDACTED]',
    ports: [{ port: 5174, protocol: 'TCP', status: 'established (remote redacted)' }], fileWrites: [{ path: 'C:\\Demo\\MTGA\\index.json', at: '2026-08-12T15:59:47.000Z', status: 'observed' }],
    resources: [{ observedAt: fixtureCapturedAt, ramMb: 238, cpuPercent: 6.2 }], timeline: [{ id: 'mtga-t1', at: '2026-08-12T13:22:05.000Z', title: 'Agent started', detail: 'Managed process identity recorded.', kind: 'state' }], partialSections: [],
  },
  {
    id: 'unmanaged-8892', revision: 0, role: 'Unattributed Python process', project: 'Unmanaged detection', provider: 'Unknown',
    runtime: 'Python', pid: 8892, processInstanceId: null, host: 'Local host', processStartedAt: null, executable: 'python.exe', state: 'unmanaged',
    confidence: 'low', evidenceGrade: 'inferred', diagnosis: 'A process resembles an agent runtime, but no managed identity or ownership record was found.',
    actionable: false, actionReason: 'Unmanaged detections cannot be contained until identity and ownership are verified.', heartbeatAt: null, ramMb: 91, network: 'unknown',
    evidence: [{ id: 'u-cmd', label: 'Agent-like arguments', source: 'Process inventory', observedAt: fixtureCapturedAt, grade: 'inferred', detail: 'Arguments resemble an agent runner; ownership is unknown.' }],
    currentTask: null, processTree: [{ pid: 8892, name: 'python.exe', relationship: 'target', status: 'running' }], heartbeatHistory: [], commandLine: 'python.exe [REDACTED]', ports: [], fileWrites: [],
    resources: [{ observedAt: fixtureCapturedAt, ramMb: 91, cpuPercent: 0.2 }], timeline: [], partialSections: ['Ownership', 'Network attribution'],
  },
]

function clone<T>(value: T): T { return structuredClone(value) }
function createAgentDetails(baseline: Date): AgentDetail[] {
  const deltaMs = baseline.getTime() - Date.parse(fixtureCapturedAt)
  const rebase = (value: string) => new Date(Date.parse(value) + deltaMs).toISOString()
  return clone(agentDetails).map((agent) => ({
    ...agent,
    processStartedAt: agent.processStartedAt ? rebase(agent.processStartedAt) : null,
    heartbeatAt: agent.heartbeatAt ? rebase(agent.heartbeatAt) : null,
    evidence: agent.evidence.map((signal) => ({ ...signal, observedAt: rebase(signal.observedAt) })),
    heartbeatHistory: agent.heartbeatHistory.map((heartbeat) => ({ ...heartbeat, at: rebase(heartbeat.at) })),
    fileWrites: agent.fileWrites.map((file) => ({ ...file, at: rebase(file.at) })),
    resources: agent.resources.map((point) => ({ ...point, observedAt: rebase(point.observedAt) })),
    timeline: agent.timeline.map((event) => ({ ...event, at: rebase(event.at) })),
  }))
}
function summarize(agent: AgentDetail): AgentSummary {
  const { currentTask: _currentTask, processTree: _processTree, heartbeatHistory: _heartbeatHistory,
    commandLine: _commandLine, ports: _ports, fileWrites: _fileWrites, resources: _resources,
    timeline: _timeline, partialSections: _partialSections, ...summary } = agent
  return summary
}

function exactRecord(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) return false
  const actual = Object.keys(value).sort()
  return actual.length === keys.length && actual.every((key, index) => key === [...keys].sort()[index])
}

function validPlanRequest(value: unknown): value is PlanRequest {
  if (!exactRecord(value, ['agentId', 'kind', 'target']) || typeof value.agentId !== 'string' || value.agentId.length === 0 || (value.kind !== 'graceful-stop' && value.kind !== 'force-stop')) return false
  const target = value.target
  return exactRecord(target, ['pid', 'processInstanceId'])
    && isProcessId(target.pid)
    && typeof target.processInstanceId === 'string' && /^[a-f0-9]{64}$/.test(target.processInstanceId)
}

function validExecuteRequest(value: unknown): value is ExecuteRequest {
  return exactRecord(value, ['digest', 'planId']) && typeof value.planId === 'string' && value.planId.length > 0 && typeof value.digest === 'string' && value.digest.length > 0
}

function validMemorySearch(value: unknown): value is MemorySearchRequest {
  const allowed = ['agent', 'collection', 'cursor', 'from', 'page', 'pageSize', 'query', 'sourceId', 'tag', 'to']
  if (!exactRecord(value, allowed.filter((key) => Object.prototype.hasOwnProperty.call(value ?? {}, key)))) return false
  const request = value as Partial<MemorySearchRequest>
  const stringFilters = ['sourceId', 'tag', 'collection', 'agent'] as const
  if (stringFilters.some((key) => request[key] !== undefined && typeof request[key] !== 'string')) return false
  if (request.from !== undefined && (typeof request.from !== 'string' || !Number.isFinite(Date.parse(request.from)))) return false
  if (request.to !== undefined && (typeof request.to !== 'string' || !Number.isFinite(Date.parse(request.to)))) return false
  return typeof request.query === 'string' && Number.isInteger(request.page) && Number.isInteger(request.pageSize) && (request.page ?? 0) > 0 && (request.pageSize ?? 0) > 0 && (request.pageSize ?? 0) <= 100
}

function validMemoryChange(value: unknown): value is MemoryChangeRequest {
  if (!exactRecord(value, ['changes', 'expectedRecordRevision', 'expectedSourceRevision', 'operation', 'recordId', 'sourceId'])) return false
  const request = value as Partial<MemoryChangeRequest>
  if (typeof request.sourceId !== 'string' || typeof request.recordId !== 'string' || !['update', 'exclude', 'quarantine'].includes(String(request.operation)) || !Number.isInteger(request.expectedSourceRevision) || !Number.isInteger(request.expectedRecordRevision)) return false
  if (typeof request.changes !== 'object' || request.changes === null || Array.isArray(request.changes)) return false
  const keys = Object.keys(request.changes)
  if (keys.some((key) => !['title', 'content', 'tags', 'collection'].includes(key))) return false
  const changes = request.changes as Record<string, unknown>
  if (request.operation !== 'update' && keys.length > 0) return false
  if (request.operation === 'update' && keys.length === 0) return false
  return (!('title' in changes) || (typeof changes.title === 'string' && changes.title.trim().length > 0 && changes.title.length <= 200))
    && (!('content' in changes) || (typeof changes.content === 'string' && changes.content.length <= 8192))
    && (!('collection' in changes) || (typeof changes.collection === 'string' && changes.collection.trim().length > 0 && changes.collection.length <= 128))
    && (!('tags' in changes) || (Array.isArray(changes.tags) && changes.tags.length <= 20 && changes.tags.every((tag) => typeof tag === 'string' && tag.length > 0 && tag.length <= 64)))
}

function validPlanExecution(value: unknown): value is PlanExecutionRequest {
  return exactRecord(value, ['digest', 'planId']) && typeof value.planId === 'string' && value.planId.length > 0 && typeof value.digest === 'string' && value.digest.length > 0
}

function memoryHaystack(record: MemoryRecord) {
  return [record.id, record.title, record.content, record.tags.join(' '), record.collection, record.sourceId, record.agent, record.writer, record.updatedAt].join(' ').toLowerCase()
}

export class DemoTransport implements EngineTransport {
  readonly mode = 'demo' as const
  readonly capabilities: TransportCapabilities = {
    processActions: true,
    processActionsUnavailableReason: null,
    activity: true,
    quarantineRestore: true,
    vaultRead: true,
    vaultMutation: true,
    memoryHistory: true,
    settingsUpdate: true,
    diagnosticsExport: true,
  }
  private readonly latencyMs: number
  private readonly clock: () => Date
  private readonly fixtureBaseline: Date
  private readonly makeId: (prefix: string) => string
  private details: AgentDetail[]
  private plans = new Map<string, { plan: DemoActionPlan; identity: DemoPlanIdentity; used: boolean; invalidated: boolean }>()
  private receipts: ContainmentReceipt[] = []
  private stateRevision = 0
  private sources = clone(memorySources)
  private memory = clone(memoryRecords)
  private memoryPlans = new Map<string, { plan: MemoryPlan; request: MemoryChangeRequest; used: boolean; invalidated: boolean }>()
  private restorePlans = new Map<string, { plan: RestorePlan; used: boolean; snapshot: MemoryRecord }>()
  private snapshots = new Map<string, MemoryRecord>()
  private memoryReceipts: MemoryReceipt[] = []
  private quarantine: DemoQuarantineEntry[] = []
  private graveyardPlans = new Map<string, { plan: GraveyardPlan; used: boolean }>()
  private graveyardReceipts: GraveyardReceipt[] = []
  private settings = clone(defaultSettings)

  constructor(options: DemoTransportOptions = {}) {
    this.latencyMs = options.latencyMs ?? 80
    this.clock = options.now ?? (() => new Date())
    this.fixtureBaseline = new Date(this.clock().getTime())
    this.makeId = options.id ?? ((prefix) => `${prefix}-${crypto.randomUUID()}`)
    this.details = createAgentDetails(this.fixtureBaseline)
    this.receipts = [historicalReceipt(this.fixtureBaseline)]
    this.quarantine = [historicalQuarantine(this.fixtureBaseline)]
  }

  reset() { this.details = createAgentDetails(this.fixtureBaseline); this.plans.clear(); this.receipts = [historicalReceipt(this.fixtureBaseline)]; this.stateRevision = 0; this.sources = clone(memorySources); this.memory = clone(memoryRecords); this.memoryPlans.clear(); this.restorePlans.clear(); this.snapshots.clear(); this.memoryReceipts = []; this.quarantine = [historicalQuarantine(this.fixtureBaseline)]; this.graveyardPlans.clear(); this.graveyardReceipts = []; this.settings = clone(defaultSettings) }
  private async wait() { if (this.latencyMs > 0) await new Promise((resolve) => window.setTimeout(resolve, this.latencyMs)) }

  async scan(request: ScanRequest = {}): Promise<ScanResult> {
    await this.wait()
    const agents = this.details.filter((agent) => request.includeUnmanagedCandidates !== false || agent.state !== 'unmanaged').map(summarize)
    const scannedAt = this.clock().toISOString()
    return clone({
      mode: 'demo' as const, revision: `demo-rev-${this.stateRevision}`, capturedAt: scannedAt,
      coverage: { completeness: 'partial' as const, blindSpotCount: 2, observedProcessCount: 3, totalProcessCount: null, blindSpots: ['Processes elevated above the current user', 'Containers and remote hosts'] },
      agents,
      evidence: agents.flatMap((agent) => agent.evidence),
      metrics: { active: agents.filter((a) => ['healthy', 'idle'].includes(a.state)).length, needsAttention: agents.filter((a) => ['stale', 'orphaned', 'unresponsive', 'interrupted', 'defunct'].includes(a.state)).length, unmanaged: agents.filter((a) => ['unmanaged', 'unknown'].includes(a.state)).length, reclaimableMb: agents.filter((a) => ['stale', 'orphaned', 'unresponsive', 'interrupted', 'defunct'].includes(a.state)).reduce((sum, a) => sum + (a.ramMb ?? 0), 0) },
      usage: { requests: null, inputTokens: null, outputTokens: null, costUsd: null },
      resources: this.details.flatMap((agent) => agent.resources), timeline: this.details.flatMap((agent) => agent.timeline), receipts: this.receipts,
    })
  }

  async getAgentDetail(agentId: string, expected?: AgentIdentityBinding) {
    await this.wait(); const detail = this.details.find((agent) => agent.id === agentId)
    if (!detail) throw new TransportError('not_found', 'Agent was not found.')
    if (expected && (detail.id !== expected.id || detail.revision !== expected.revision || detail.pid !== expected.pid || detail.processInstanceId !== expected.processInstanceId)) {
      throw new TransportError('target_changed', 'The agent changed while reconciliation was loading; detail no longer matches the scanned process instance.', true, { reason: 'agent_identity_changed' })
    }
    return clone(detail)
  }

  async planAction(request: PlanRequest): Promise<ActionPlan> {
    await this.wait()
    if (!validPlanRequest(request)) throw new TransportError('invalid_request', 'Action plan request must contain one exact process instance target.', false)
    const target = this.details.find((agent) => agent.id === request.agentId)
    if (!target) throw new TransportError('not_found', 'Agent was not found.')
    if (!target.actionable || target.pid === null || !target.processInstanceId || !target.processStartedAt || !target.executable) throw new TransportError('not_actionable', target.actionReason, false)
    if (target.pid !== request.target.pid || target.processInstanceId !== request.target.processInstanceId) throw new TransportError('target_changed', 'The requested process instance is no longer current. Refresh before reviewing an action.', true, { reason: 'process_instance_changed' })
    const planId = this.makeId('plan')
    const createdAt = this.clock()
    const digest = this.makeId('digest')
    const force = request.kind === 'force-stop'
    const plan: DemoActionPlan = {
      planId, digest, createdAt: createdAt.toISOString(), expiresAt: new Date(createdAt.getTime() + 30_000).toISOString(), kind: request.kind,
      agentId: target.id, engineMode: force ? 'kill' : 'request_stop',
      target: { state: target.state, pid: target.pid, processInstanceId: target.processInstanceId },
      strategy: force ? 'Windows TerminateProcess; this is not a graceful shutdown.' : 'Request application shutdown, wait, then report if the process remains.',
      timeoutSeconds: force ? 0 : 10, expectedPortsReleased: target.ports.map((p) => p.port),
      eligibleQuarantineFiles: target.fileWrites.filter((f) => f.status === 'observed').map((f) => f.path), memoryEffect: 'unchanged',
      irreversibleConsequences: force
        ? ['The target and child processes will terminate without cleanup handlers.', 'Observed ports are expected to release.', 'Eligible files will move to the local quarantine.', 'The current task will be cleared.', 'Demo status, actionability, diagnosis, network observation, resource history, evidence, and activity timeline will be updated to reflect containment.', 'Memory unchanged; no memory snapshot will be edited.']
        : ['The running task will stop and the current task will be cleared.', 'Observed ports are expected to release.', 'Eligible files will move to the local quarantine.', 'Demo status, actionability, diagnosis, network observation, resource history, evidence, and activity timeline will be updated to reflect containment.', 'Memory unchanged; no memory snapshot will be edited.'],
    }
    const identity: DemoPlanIdentity = { revision: target.revision, processStartedAt: target.processStartedAt, executable: target.executable, childCount: target.processTree.filter((p) => p.relationship === 'child').length }
    this.plans.set(planId, { plan: clone(plan), identity, used: false, invalidated: false }); return clone(plan)
  }

  async executeAction(request: ExecuteRequest) {
    await this.wait()
    if (!validExecuteRequest(request)) throw new TransportError('invalid_request', 'Execute request must contain only a non-empty planId and digest.', false)
    const record = this.plans.get(request.planId)
    if (!record) throw new TransportError('plan_changed', 'This action plan is not recognized. Review a new plan.')
    if (record.used) throw new TransportError('plan_replayed', 'This action plan was already used. Review a new plan.')
    if (record.plan.digest !== request.digest) throw new TransportError('plan_changed', 'The plan digest changed. Nothing was executed.')
    if (this.clock().getTime() >= Date.parse(record.plan.expiresAt)) throw new TransportError('plan_expired', 'This action plan expired. Review a fresh plan.')
    const target = this.details.find((agent) => agent.id === record.plan.agentId)
    if (record.invalidated || !target || !target.actionable || target.revision !== record.identity.revision || target.state !== record.plan.target.state || target.pid !== record.plan.target.pid || target.processInstanceId !== record.plan.target.processInstanceId || target.processStartedAt !== record.identity.processStartedAt || target.executable !== record.identity.executable) throw new TransportError('target_changed', 'The target identity or state changed. Nothing was executed.')
    record.used = true
    target.fileWrites = target.fileWrites.map((file) => record.plan.eligibleQuarantineFiles.includes(file.path) ? { ...file, status: 'quarantined' } : file)
    target.currentTask = null
    target.state = 'interrupted'; target.revision = incrementDemoRevision(target.revision); this.stateRevision += 1; target.actionable = false; target.actionReason = 'The demo containment plan completed; this process is no longer running.'; target.diagnosis = 'Demo containment completed. No operating-system process was changed.'; target.ramMb = 0; target.network = 'not-observed'
    target.processTree = target.processTree.map((process) => ({ ...process, status: 'interrupted' }))
    target.ports = target.ports.map((port) => ({ ...port, status: 'released' }))
    target.resources.push({ observedAt: this.clock().toISOString(), ramMb: 0, cpuPercent: 0 })
    target.evidence = target.evidence.map((signal) => signal.id === 'mev-port' ? { ...signal, label: 'Port 4317 released', observedAt: this.clock().toISOString(), detail: 'The synthetic TCP listener is recorded as released by the completed plan.' } : signal)
    target.evidence.unshift({ id: this.makeId('evidence'), label: 'Demo containment receipt recorded', source: 'Action ledger', observedAt: this.clock().toISOString(), grade: 'verified', detail: 'The immutable demo plan completed without mutating the operating system.' })
    target.timeline.unshift({ id: this.makeId('timeline'), at: this.clock().toISOString(), title: 'Containment complete', detail: 'Demo state changed to interrupted; memory was unchanged.', kind: 'action' })
    for (const sibling of this.plans.values()) if (!sibling.used && sibling.plan.agentId === target.id) sibling.invalidated = true
    const receipt: ContainmentReceipt = { receiptId: this.makeId('receipt'), planId: record.plan.planId, title: 'Containment complete', completedAt: this.clock().toISOString(), agentId: target.id, processCount: 1 + record.identity.childCount, portCount: record.plan.expectedPortsReleased.length, fileCount: record.plan.eligibleQuarantineFiles.length, memoryEffect: 'unchanged', diagnostics: `Demo receipt for PID ${record.plan.target.pid}; plan ${record.plan.planId}; no OS mutation.`, partialFailures: [] }
    for (const [index, path] of record.plan.eligibleQuarantineFiles.entries()) {
      const basename = path.split(/[\\/]/).at(-1) ?? 'redacted-entry'
      this.quarantine.unshift({ id: this.makeId('quarantine'), agentId: target.id, resourceType: 'file', createdAt: this.clock().toISOString(), receiptId: receipt.receiptId, basename, displayPath: `[redacted]\\${basename}`, size: 2048 + index * 512, hashPrefix: `sha256:${this.makeId('hash').replace(/[^a-f0-9]/gi, '').slice(0, 10).padEnd(10, '0')}`, digest: this.makeId('entry-digest'), retainedUntil: new Date(this.clock().getTime() + this.settings.quarantineRetentionDays * 86_400_000).toISOString(), state: 'Quarantined', restorable: true, revision: 1 })
    }
    this.receipts.unshift(receipt); return clone(receipt)
  }

  async getActivity(): Promise<ActivityResult> {
    await this.wait()
    const events: ActivityEvent[] = this.details.flatMap((agent) => agent.timeline.map((event) => ({ id: event.id, timestamp: event.at, actor: 'Local demo engine', project: agent.project, target: agent.id, action: event.title, result: 'Succeeded' as const, correlationId: `event-${event.id}`, detail: event.detail })))
    for (const receipt of this.receipts) events.unshift({ id: `event-${receipt.receiptId}`, timestamp: receipt.completedAt, actor: 'Local user', project: this.details.find((agent) => agent.id === receipt.agentId)?.project ?? 'Demo project', target: receipt.agentId ?? 'Target unavailable', action: receipt.title, result: 'Succeeded', correlationId: receipt.receiptId, detail: receipt.diagnostics })
    for (const receipt of this.memoryReceipts) {
      const source = this.sources.find((item) => item.id === receipt.sourceId)
      events.unshift({ id: `event-${receipt.receiptId}`, timestamp: receipt.completedAt, actor: 'Local user', project: source?.project ?? 'Memory Vault', target: receipt.recordId, action: `Memory ${receipt.operation}`, result: 'Succeeded', correlationId: receipt.correlationId, detail: `Audit receipt ${receipt.receiptId}; snapshot ${receipt.snapshotId}.` })
    }
    for (const receipt of this.graveyardReceipts) {
      const entry = this.quarantine.find((item) => item.id === receipt.entryId)
      events.unshift({ id: `event-${receipt.receiptId}`, timestamp: receipt.completedAt, actor: 'Local user', project: 'Local recovery', target: entry?.basename ?? receipt.entryId, action: 'Quarantine restore', result: 'Succeeded', correlationId: receipt.correlationId, detail: 'Exact quarantined entry restored without overwrite.' })
    }
    return clone({ capturedAt: this.clock().toISOString(), events, receipts: this.receipts, memoryReceipts: this.memoryReceipts, quarantine: this.quarantine, graveyardReceipts: this.graveyardReceipts, pagination: { activityTruncated: false, quarantineTruncated: false } })
  }

  async getVault(): Promise<VaultResult> { await this.wait(); return clone({ mode: 'demo' as const, capturedAt: this.clock().toISOString(), sources: this.sources }) }

  async searchMemory(request: MemorySearchRequest) {
    await this.wait()
    if (!validMemorySearch(request)) throw new TransportError('invalid_request', 'Memory search is invalid or outside bounded pagination.', false)
    if (request.sourceId && !this.sources.some((source) => source.id === request.sourceId)) throw new TransportError('invalid_request', 'Memory source filter is not registered.', false)
    const query = request.query.trim().toLowerCase()
    const records = this.memory
      .filter((record) => !request.sourceId || record.sourceId === request.sourceId)
      .filter((record) => !request.tag || record.tags.includes(request.tag))
      .filter((record) => !request.collection || record.collection === request.collection)
      .filter((record) => !request.agent || record.agent === request.agent)
      .filter((record) => !request.from || record.updatedAt >= request.from)
      .filter((record) => !request.to || record.updatedAt <= request.to)
      .filter((record) => !query || memoryHaystack(record).includes(query))
      .sort((left, right) => left.id.localeCompare(right.id))
    const start = (request.page - 1) * request.pageSize
    return clone({ capturedAt: this.clock().toISOString(), page: request.page, pageSize: request.pageSize, total: records.length, records: records.slice(start, start + request.pageSize), nextCursor: start + request.pageSize < records.length ? String(start + request.pageSize) : null })
  }

  async getMemoryRecord(sourceId: string, recordId: string): Promise<MemoryRecord> {
    await this.wait()
    const record = this.memory.find((item) => item.sourceId === sourceId && item.id === recordId)
    if (!record) throw new TransportError('not_found', 'Memory record was not found.')
    return clone(record)
  }

  async getMemoryHistory(sourceId: string, recordId: string): Promise<MemoryHistoryEntry[]> {
    await this.wait()
    if (typeof sourceId !== 'string' || typeof recordId !== 'string') throw new TransportError('invalid_request', 'Memory history target is invalid.', false)
    const initial = memoryRecords.find((record) => record.sourceId === sourceId && record.id === recordId)
    const current = this.memory.find((record) => record.sourceId === sourceId && record.id === recordId)
    if (!initial || !current) throw new TransportError('not_found', 'Memory history target was not found.')
    const changes: MemoryHistoryEntry[] = this.memoryReceipts
      .filter((receipt) => receipt.sourceId === sourceId && receipt.recordId === recordId)
      .map((receipt) => ({
        id: `history-${receipt.receiptId}`, sourceId, recordId, revision: receipt.afterRevision,
        at: receipt.completedAt, operation: receipt.operation, actor: 'Local user',
        summary: receipt.operation === 'restore' ? `Restored verified snapshot ${receipt.snapshotId}.` : `Applied ${receipt.operation} with verified snapshot.`,
        receiptId: receipt.receiptId, snapshotId: receipt.snapshotId,
        restorable: receipt.operation !== 'restore' && this.snapshots.has(receipt.snapshotId),
      }))
    changes.push({ id: `history-created-${recordId}`, sourceId, recordId, revision: initial.revision, at: initial.updatedAt, operation: 'created', actor: initial.writer, summary: 'Initial synthetic demo record version.', restorable: false })
    return clone(changes.sort((left, right) => right.revision - left.revision))
  }

  async planMemoryChange(request: MemoryChangeRequest): Promise<MemoryPlan> {
    await this.wait()
    if (!validMemoryChange(request)) throw new TransportError('schema_invalid', 'Memory draft failed strict schema validation.', false)
    const source = this.sources.find((item) => item.id === request.sourceId)
    const record = this.memory.find((item) => item.id === request.recordId && item.sourceId === request.sourceId)
    if (!source || !record) throw new TransportError('not_found', 'Memory source or record was not found.')
    if (!source.capabilities.includes('edit')) throw new TransportError('not_actionable', 'This source is read-only because a verified backup is unavailable.', false)
    if (source.revision !== request.expectedSourceRevision || record.revision !== request.expectedRecordRevision) throw new TransportError('source_changed', 'Source changed while this draft was open. Refresh and create a new draft.', true, { sourceRevision: source.revision, recordRevision: record.revision })
    const diff: FieldDiff[] = Object.entries(request.changes).filter(([field, value]) => JSON.stringify(record[field as keyof MemoryRecord]) !== JSON.stringify(value)).map(([field, value]) => ({ field, oldValue: clone(record[field as keyof MemoryRecord]), newValue: clone(value) }))
    if (request.operation === 'exclude' && !record.excluded) diff.push({ field: 'excluded', oldValue: false, newValue: true })
    if (request.operation === 'quarantine' && !record.quarantined) diff.push({ field: 'quarantined', oldValue: false, newValue: true })
    if (diff.length === 0) throw new TransportError('schema_invalid', 'The draft contains no change.', false)
    const snapshotId = this.makeId('snapshot')
    const snapshot: MemorySnapshot = { id: snapshotId, verified: true, recordId: record.id, sourceRevision: source.revision, recordRevision: record.revision }
    this.snapshots.set(snapshotId, clone(record))
    const createdAt = this.clock()
    const plan: MemoryPlan = { planId: this.makeId('memory-plan'), digest: this.makeId('memory-digest'), expiresAt: new Date(createdAt.getTime() + 30_000).toISOString(), operation: request.operation, sourceId: source.id, recordId: record.id, expectedSourceRevision: source.revision, expectedRecordRevision: record.revision, diff, snapshot }
    this.memoryPlans.set(plan.planId, { plan: clone(plan), request: clone(request), used: false, invalidated: false })
    return clone(plan)
  }

  async executeMemoryChange(request: PlanExecutionRequest): Promise<MemoryReceipt> {
    await this.wait()
    if (!validPlanExecution(request)) throw new TransportError('invalid_request', 'Memory execution request is invalid.', false)
    const stored = this.memoryPlans.get(request.planId)
    if (!stored) throw new TransportError('plan_changed', 'Memory plan is not recognized. Review a new plan.')
    if (stored.used) throw new TransportError('plan_replayed', 'Memory plan was already used. Review a new plan.')
    if (stored.plan.digest !== request.digest) throw new TransportError('plan_changed', 'Memory plan digest changed. Nothing was applied.')
    if (this.clock().getTime() >= Date.parse(stored.plan.expiresAt)) throw new TransportError('plan_expired', 'Memory plan expired. Review a fresh plan.')
    const source = this.sources.find((item) => item.id === stored.plan.sourceId)
    const target = this.memory.find((item) => item.id === stored.plan.recordId)
    if (stored.invalidated || !source || !target || source.revision !== stored.plan.expectedSourceRevision || target.revision !== stored.plan.expectedRecordRevision) throw new TransportError('target_changed', 'Source or record changed. Nothing was applied; refresh and create a new draft.')
    const stillChanges = stored.plan.diff.some((change) => JSON.stringify(target[change.field as keyof MemoryRecord]) !== JSON.stringify(change.newValue))
    if (!stillChanges) throw new TransportError('target_changed', 'The reviewed memory operation is now a no-op. No revision or receipt was created.')
    stored.used = true
    Object.assign(target, clone(stored.request.changes))
    if (stored.plan.operation === 'exclude') target.excluded = true
    if (stored.plan.operation === 'quarantine') target.quarantined = true
    target.revision += 1; source.revision += 1; target.updatedAt = this.clock().toISOString()
    for (const sibling of this.memoryPlans.values()) if (!sibling.used && sibling.plan.recordId === target.id) sibling.invalidated = true
    const receipt: MemoryReceipt = { receiptId: this.makeId('memory-receipt'), correlationId: this.makeId('correlation'), planId: stored.plan.planId, sourceId: source.id, recordId: target.id, operation: stored.plan.operation, completedAt: this.clock().toISOString(), snapshotId: stored.plan.snapshot.id, beforeRevision: stored.plan.expectedRecordRevision, afterRevision: target.revision }
    this.memoryReceipts.unshift(receipt)
    return clone(receipt)
  }

  async planMemoryRestore(request: RestorePlanRequest): Promise<RestorePlan> {
    await this.wait()
    if (!exactRecord(request, ['expectedRecordRevision', 'receiptId', 'snapshotId']) || typeof request.receiptId !== 'string' || typeof request.snapshotId !== 'string' || !Number.isInteger(request.expectedRecordRevision)) throw new TransportError('invalid_request', 'Restore request is invalid.', false)
    const receipt = this.memoryReceipts.find((item) => item.receiptId === request.receiptId && item.snapshotId === request.snapshotId)
    const snapshot = this.snapshots.get(request.snapshotId)
    const target = receipt && this.memory.find((item) => item.id === receipt.recordId)
    if (!receipt || !snapshot || !target) throw new TransportError('not_found', 'Exact snapshot and receipt pair was not found.')
    if (target.revision !== request.expectedRecordRevision) throw new TransportError('conflict', 'Record changed after this receipt. Restore will not overwrite it.')
    const createdAt = this.clock()
    const source = this.sources.find((item) => item.id === target.sourceId)
    if (!source) throw new TransportError('not_found', 'Restore source was not found.')
    const plan: RestorePlan = { planId: this.makeId('restore-plan'), digest: this.makeId('restore-digest'), expiresAt: new Date(createdAt.getTime() + 30_000).toISOString(), receiptId: receipt.receiptId, snapshotId: request.snapshotId, sourceId: source.id, recordId: target.id, expectedRecordRevision: target.revision, expectedSourceRevision: source.revision }
    this.restorePlans.set(plan.planId, { plan: clone(plan), used: false, snapshot: clone(snapshot) })
    return clone(plan)
  }

  async executeMemoryRestore(request: PlanExecutionRequest): Promise<MemoryReceipt> {
    await this.wait()
    if (!validPlanExecution(request)) throw new TransportError('invalid_request', 'Restore execution request is invalid.', false)
    const stored = this.restorePlans.get(request.planId)
    if (!stored) throw new TransportError('plan_changed', 'Restore plan is not recognized.')
    if (stored.used) throw new TransportError('plan_replayed', 'Restore plan was already used.')
    if (stored.plan.digest !== request.digest) throw new TransportError('plan_changed', 'Restore plan digest changed. Nothing was restored.')
    if (this.clock().getTime() >= Date.parse(stored.plan.expiresAt)) throw new TransportError('plan_expired', 'Restore plan expired. Review a fresh restore.')
    const target = this.memory.find((item) => item.id === stored.plan.recordId)
    const source = target && this.sources.find((item) => item.id === target.sourceId)
    if (!target || !source || target.revision !== stored.plan.expectedRecordRevision || source.revision !== stored.plan.expectedSourceRevision) throw new TransportError('conflict', 'Source or record changed after review. Restore will not overwrite it.')
    stored.used = true
    const beforeRevision = target.revision
    Object.assign(target, clone(stored.snapshot), { revision: target.revision + 1, updatedAt: this.clock().toISOString() })
    source.revision += 1
    const receipt: MemoryReceipt = { receiptId: this.makeId('restore-receipt'), correlationId: this.makeId('correlation'), planId: stored.plan.planId, sourceId: source.id, recordId: target.id, operation: 'restore', completedAt: this.clock().toISOString(), snapshotId: stored.plan.snapshotId, beforeRevision, afterRevision: target.revision, restoredFromReceiptId: stored.plan.receiptId }
    this.memoryReceipts.unshift(receipt)
    return clone(receipt)
  }

  async planGraveyardRestore(entryId: string): Promise<GraveyardPlan> {
    await this.wait()
    const entry = this.quarantine.find((item) => item.id === entryId)
    if (!entry || entry.state !== 'Quarantined') throw new TransportError('not_actionable', 'The exact quarantine entry is not available for restore.')
    const createdAt = this.clock()
    const plan: GraveyardPlan = { planId: this.makeId('graveyard-plan'), digest: this.makeId('graveyard-digest'), expiresAt: new Date(createdAt.getTime() + 30_000).toISOString(), entryId: entry.id, entryDigest: entry.digest, expectedRevision: entry.revision }
    this.graveyardPlans.set(plan.planId, { plan: clone(plan), used: false })
    return clone(plan)
  }

  async executeGraveyardRestore(request: PlanExecutionRequest): Promise<GraveyardReceipt> {
    await this.wait()
    if (!validPlanExecution(request)) throw new TransportError('invalid_request', 'Graveyard execution request is invalid.', false)
    const stored = this.graveyardPlans.get(request.planId)
    if (!stored) throw new TransportError('plan_changed', 'Restore plan is not recognized.')
    if (stored.used) throw new TransportError('plan_replayed', 'Restore plan was already used.')
    if (stored.plan.digest !== request.digest) throw new TransportError('plan_changed', 'Restore plan digest changed. Nothing was restored.')
    if (this.clock().getTime() >= Date.parse(stored.plan.expiresAt)) throw new TransportError('plan_expired', 'Quarantine restore plan expired. Review a fresh restore.')
    const entry = this.quarantine.find((item) => item.id === stored.plan.entryId)
    if (!entry || entry.digest !== stored.plan.entryDigest || entry.revision !== stored.plan.expectedRevision || entry.state !== 'Quarantined') throw new TransportError('conflict', 'Entry changed or the original location is occupied. Nothing was overwritten.')
    stored.used = true; entry.state = 'Restored'; entry.restorable = false; entry.revision += 1
    const receipt: GraveyardReceipt = { receiptId: this.makeId('graveyard-receipt'), correlationId: this.makeId('correlation'), entryId: entry.id, result: 'Restored', completedAt: this.clock().toISOString() }
    this.graveyardReceipts.unshift(receipt)
    return clone(receipt)
  }

  async getSettings() { await this.wait(); return clone(this.settings) }
  async updateSettings(request: { expectedRevision: number; changes: Partial<Omit<AppSettings, 'revision'>> }) {
    await this.wait()
    if (!exactRecord(request, ['changes', 'expectedRevision']) || !Number.isInteger(request.expectedRevision)) throw new TransportError('schema_invalid', 'Settings update request is invalid.', false)
    if (request.expectedRevision !== this.settings.revision) throw new TransportError('conflict', 'Settings changed in another view. Refresh before retrying.')
    if (typeof request.changes !== 'object' || request.changes === null || Array.isArray(request.changes)) throw new TransportError('schema_invalid', 'Settings changes must be a plain object.', false)
    const prototype = Object.getPrototypeOf(request.changes)
    if (prototype !== Object.prototype && prototype !== null) throw new TransportError('schema_invalid', 'Settings changes must be a plain object.', false)
    const allowed = ['detectionPreset', 'theme', 'motion', 'denseMode', 'autoRefreshSeconds', 'quarantineRetentionDays', 'heartbeatGraceSeconds', 'includeUnmanagedCandidates']
    const keys = Object.keys(request.changes)
    if (keys.length === 0 || keys.some((key) => !allowed.includes(key))) throw new TransportError('schema_invalid', 'Settings changes must contain at least one known setting.', false)
    const next: AppSettings = { ...this.settings, ...clone(request.changes), revision: this.settings.revision + 1 }
    if (typeof next.detectionPreset !== 'string' || !['Conservative', 'Balanced', 'Aggressive'].includes(next.detectionPreset) || !['system', 'light', 'dark'].includes(next.theme) || !['system', 'reduce', 'full'].includes(next.motion) || typeof next.denseMode !== 'boolean' || ![0, 15, 30, 60].includes(next.autoRefreshSeconds) || ![7, 14, 30, 90].includes(next.quarantineRetentionDays) || (next.heartbeatGraceSeconds !== undefined && (!Number.isInteger(next.heartbeatGraceSeconds) || next.heartbeatGraceSeconds < 1)) || (next.includeUnmanagedCandidates !== undefined && typeof next.includeUnmanagedCandidates !== 'boolean')) throw new TransportError('schema_invalid', 'Setting is outside its bounded values.', false)
    if (keys.every((key) => Object.is(this.settings[key as keyof AppSettings], request.changes[key as keyof typeof request.changes]))) throw new TransportError('schema_invalid', 'Settings update contains no effective change.', false)
    this.settings = next as DemoSettings; return clone(this.settings)
  }
  async resetSettings(expectedRevision: number) { await this.wait(); if (expectedRevision !== this.settings.revision) throw new TransportError('conflict', 'Settings changed in another view.'); this.settings = { ...clone(defaultSettings), revision: this.settings.revision + 1 }; return clone(this.settings) }
}

function incrementDemoRevision(revision: number | string): number {
  if (typeof revision !== 'number') throw new TransportError('protocol_violation', 'Demo revision is not numeric.', false)
  return revision + 1
}
