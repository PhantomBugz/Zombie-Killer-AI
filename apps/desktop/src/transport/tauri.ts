import { invoke as tauriInvoke } from '@tauri-apps/api/core'

import type {
  ActionPlan,
  AgentIdentityBinding,
  ActivityResult,
  AgentDetail,
  AgentState,
  AgentSummary,
  AppSettings,
  ContainmentReceipt,
  EngineTransport,
  ExecuteRequest,
  GraveyardPlan,
  GraveyardReceipt,
  MemoryChangeRequest,
  MemoryHistoryEntry,
  MemoryPlan,
  MemoryReceipt,
  MemoryRecord,
  MemorySearchRequest,
  MemorySearchResult,
  MemorySource,
  PlanExecutionRequest,
  PlanRequest,
  QuarantineEntry,
  RestorePlan,
  RestorePlanRequest,
  ScanRequest,
  ScanResult,
  TransportCapabilities,
  TransportErrorCode,
  VaultResult,
  NativeScalarField,
  ScalarValue,
  NativeSnapshot,
  LocalWorkflowPlan,
  LocalWorkflowReceipt,
  DeclaredResource,
} from './types'
import { TransportError, agentStates, isProcessId } from './types'

export type NativeInvoke = (command: string, arguments_?: Record<string, unknown>) => Promise<unknown>

interface NativeReply {
  requestId: string
  method: string
  result: Record<string, unknown>
  revision?: string
}

const processActionsUnavailableReason = 'Process actions are unavailable because the local engine did not confirm a kernel-stable process binding on this platform.'

function nativeCapabilities(): TransportCapabilities {
  return {
    processActions: false,
    processActionsUnavailableReason,
    activity: true,
    quarantineRestore: false,
    vaultRead: true,
    vaultMutation: false,
    memoryHistory: false,
    settingsUpdate: false,
    diagnosticsExport: false,
    sourceRegistration: false,
    resourceCleanup: false,
  }
}

const nativeErrorCodes = new Set<TransportErrorCode>([
  'invalid_request', 'not_found', 'conflict', 'target_changed', 'permission_denied', 'expired',
  'unsupported', 'partial', 'engine_unavailable', 'engine_timeout', 'output_too_large',
  'protocol_violation', 'outcome_uncertain', 'internal',
])

function record(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw schemaError(`${label} is not an object.`)
  return value as Record<string, unknown>
}

function array(value: unknown, label: string): unknown[] {
  if (!Array.isArray(value)) throw schemaError(`${label} is not an array.`)
  return value
}

function string(value: unknown, label: string, nullable = false): string | null {
  if (nullable && value === null) return null
  if (typeof value !== 'string' || value.length === 0) throw schemaError(`${label} is not a string.`)
  return value
}

function number(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) throw schemaError(`${label} is not a finite number.`)
  return value
}

function boolean(value: unknown, label: string): boolean {
  if (typeof value !== 'boolean') throw schemaError(`${label} is not a boolean.`)
  return value
}

function processInstanceId(value: unknown, label: string, nullable = false): string | null {
  const mapped = string(value, label, nullable)
  if (mapped !== null && !/^[a-f0-9]{64}$/.test(mapped)) throw schemaError(`${label} is not a stable process instance digest.`)
  return mapped
}

function schemaError(message: string) {
  return new TransportError('schema_invalid', `Native response validation failed. ${message}`, false)
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[], label: string) {
  const keys = Object.keys(value).sort()
  const wanted = [...expected].sort()
  if (keys.length !== wanted.length || keys.some((key, index) => key !== wanted[index])) {
    throw schemaError(`${label} has unexpected fields.`)
  }
}

function mapNativeError(reason: unknown): TransportError {
  if (reason instanceof TransportError) return reason
  const value = reason && typeof reason === 'object' ? reason as Record<string, unknown> : {}
  const codeValue = typeof value.code === 'string' && nativeErrorCodes.has(value.code as TransportErrorCode)
    ? value.code as TransportErrorCode
    : 'engine_unavailable'
  const message = typeof value.message === 'string' && value.message.length <= 512
    ? value.message
    : 'The local engine is unavailable.'
  const recoverable = !['invalid_request', 'schema_invalid', 'permission_denied', 'unsupported', 'protocol_violation'].includes(codeValue)
  const nativeDetails = value.details && typeof value.details === 'object' && !Array.isArray(value.details)
    ? value.details as Record<string, unknown>
    : {}
  return new TransportError(codeValue, message, recoverable, {
    correlationId: typeof value.correlationId === 'string' ? value.correlationId : undefined,
    reason: typeof nativeDetails.reason === 'string' ? nativeDetails.reason : typeof value.reason === 'string' ? value.reason : undefined,
    reconcileRequired: value.reconcileRequired === true || nativeDetails.reconcileRequired === true,
  })
}

function mapEvidenceGrade(value: unknown): AgentSummary['evidenceGrade'] {
  if (value === 'confirmed') return 'verified'
  if (value === 'strong') return 'corroborated'
  if (value === 'partial' || value === 'signature_only') return 'inferred'
  if (value === 'insufficient') return 'unverified'
  throw schemaError('agent evidence grade is unknown.')
}

function mapConfidence(value: unknown): AgentSummary['confidence'] {
  const confidence = number(value, 'agent confidence')
  if (confidence < 0 || confidence > 1) throw schemaError('agent confidence is out of range.')
  return confidence >= 0.8 ? 'high' : confidence >= 0.5 ? 'medium' : 'low'
}

function mapState(value: unknown): AgentState {
  if (typeof value !== 'string' || !agentStates.includes(value as AgentState)) throw schemaError('agent state is unknown.')
  return value as AgentState
}

function mapEvidence(value: unknown, index: number): AgentSummary['evidence'][number] {
  const raw = record(value, `evidence ${index}`)
  const code = string(raw.code, 'evidence code') as string
  const grade = mapEvidenceGrade(raw.grade)
  return {
    id: `${code}:${index}`,
    label: code,
    source: 'Local engine',
    observedAt: string(raw.observed_at, 'evidence timestamp') as string,
    grade,
    detail: string(raw.detail, 'evidence detail') as string,
  }
}

interface MappedAgent { summary: AgentSummary; rawAgentId: string | null }

function agentSnapshotKey(agent: Pick<AgentSummary, 'id' | 'revision' | 'pid' | 'processInstanceId'>): string {
  return JSON.stringify([agent.id, agent.revision, agent.pid, agent.processInstanceId])
}

function mapAgent(value: unknown, capturedAt: string, index: number): MappedAgent {
  const raw = record(value, `agent ${index}`)
  const rawAgentId = string(raw.agent_id, 'agent ID', true)
  const pid = raw.pid === null ? null : number(raw.pid, 'agent PID')
  if (pid !== null && (!Number.isInteger(pid) || pid < 1)) throw schemaError('agent PID is invalid.')
  const state = mapState(raw.state)
  const instanceId = processInstanceId(raw.process_instance_id, 'agent process instance ID', true)
  const evidence = array(raw.evidence, 'agent evidence').map(mapEvidence)
  const managed = boolean(raw.managed, 'managed flag')
  const actionableEvidence = boolean(raw.actionable, 'actionable flag')
  const actionable = actionableEvidence && managed && rawAgentId !== null && pid !== null && instanceId !== null
  const processName = string(raw.process_name, 'process name', true)
  const explanation = string(raw.explanation, 'agent explanation') as string
  const id = rawAgentId ?? `unmanaged:${pid ?? `${processName ?? 'unknown'}:${index}`}`
  return {
    rawAgentId,
    summary: {
      id,
      revision: capturedAt,
      role: string(raw.role, 'agent role', true),
      project: string(raw.project, 'agent project', true),
      provider: string(raw.provider, 'agent provider', true),
      runtime: processName,
      pid,
      processInstanceId: instanceId,
      host: null,
      processStartedAt: null,
      executable: null,
      state,
      confidence: mapConfidence(raw.confidence),
      evidenceGrade: mapEvidenceGrade(raw.evidence_grade),
      diagnosis: explanation,
      actionable,
      actionReason: actionable
        ? 'The local engine has a managed action target. Exact process identity is revalidated at execution.'
        : rawAgentId === null || !managed
          ? 'No managed agent identity is available; this detection is non-actionable.'
          : explanation,
      heartbeatAt: null,
      ramMb: null,
      network: 'unknown',
      evidence,
    },
  }
}

function detailFromSummary(summary: AgentSummary): AgentDetail {
  return {
    ...summary,
    currentTask: null,
    processTree: [],
    heartbeatHistory: [],
    commandLine: null,
    ports: [],
    fileWrites: [],
    resources: [],
    timeline: [],
    partialSections: ['Process start time', 'Executable path', 'Process tree', 'Command line', 'Ports', 'File writes', 'RAM and CPU', 'Heartbeat history'],
  }
}

export class TauriTransport implements EngineTransport {
  readonly mode = 'native' as const
  readonly capabilities = nativeCapabilities()
  private readonly invoke: NativeInvoke
  private capabilitiesKnown = false
  private capabilityProbe: Promise<void> | null = null
  private readonly agents = new Map<string, { summary: AgentSummary; rawAgentId: string | null }>()
  private readonly agentSnapshots = new Map<string, { summary: AgentSummary; rawAgentId: string | null }>()
  private scanGeneration = 0
  private readonly memoryCursors = new Map<string, {
    nextByPage: Map<number, string | null>
    total?: number
    sourceRevision?: string
  }>()
  private readonly actionPlans = new Map<string, { agentId: string; kind: PlanRequest['kind']; target: PlanRequest['target'] }>()
  private readonly localPlans = new Map<string, { executeMethod: string; digest: string; pending: boolean; sourceId?: string; recordId?: string; expectedRevision?: string; snapshotId?: string }>()
  private readonly graveyardPlans = new Map<string, string>()

  constructor(invoke: NativeInvoke = tauriInvoke) {
    this.invoke = invoke
  }

  private async ensureCapabilities(): Promise<void> {
    if (this.capabilitiesKnown) return
    if (!this.capabilityProbe) {
      this.capabilityProbe = this.probeCapabilities()
        .finally(() => { this.capabilityProbe = null })
    }
    await this.capabilityProbe
  }

  private async probeCapabilities(): Promise<void> {
    try {
      const reply = await this.call('doctor', {})
      exactKeys(reply.result, ['checks', 'healthy', 'warnings'], 'doctor result')
      boolean(reply.result.healthy, 'doctor health')
      array(reply.result.warnings, 'doctor warnings').forEach((warning) => string(warning, 'doctor warning'))
      const checks = array(reply.result.checks, 'doctor checks').map((value, index) => {
        const check = record(value, `doctor check ${index}`)
        exactKeys(check, ['name', 'ok'], `doctor check ${index}`)
        return { name: string(check.name, 'doctor check name'), ok: boolean(check.ok, 'doctor check result') }
      })
      const planChecks = checks.filter((check) => check.name === 'method:action.plan')
      const executeChecks = checks.filter((check) => check.name === 'method:action.execute')
      const available = planChecks.length === 1 && planChecks[0]?.ok === true
        && executeChecks.length === 1 && executeChecks[0]?.ok === true
      this.capabilities.processActions = available
      this.capabilities.processActionsUnavailableReason = available ? null : processActionsUnavailableReason
      const supports = (...methods: string[]) => methods.every((method) => {
        const matches = checks.filter((check) => check.name === `method:${method}`)
        return matches.length === 1 && matches[0]?.ok === true
      })
      this.capabilities.activity = supports('activity.list', 'quarantine.list')
      this.capabilities.vaultRead = supports('vault.list', 'vault.query', 'vault.get')
      this.capabilities.sourceRegistration = supports('vault.register')
      this.capabilities.vaultMutation = supports('vault.mutation.plan', 'vault.mutation.execute')
      this.capabilities.memoryHistory = supports('vault.snapshot.list', 'vault.restore.plan', 'vault.restore.execute')
      this.capabilities.quarantineRestore = supports('quarantine.restore-plan', 'quarantine.restore-execute')
      this.capabilities.resourceCleanup = supports('quarantine.resource-list', 'quarantine.plan', 'quarantine.execute')
      this.capabilities.settingsUpdate = supports('settings.update')
      this.capabilities.diagnosticsExport = supports('diagnostics.export-plan', 'diagnostics.export-execute')
      this.capabilitiesKnown = true
    } catch {
      // Invocation/schema failures stay fail-closed but retry on the next scan or plan.
      // A valid negative doctor result is cached above because it is authoritative.
      this.capabilities.processActions = false
      this.capabilities.processActionsUnavailableReason = processActionsUnavailableReason
    }
  }

  private async call(method: string, payload: Record<string, unknown>): Promise<NativeReply> {
    let raw: unknown
    try { raw = await this.invoke('engine_request', { request: { method, payload } }) }
    catch (reason) { throw mapNativeError(reason) }
    const reply = record(raw, 'native reply')
    if (typeof reply.requestId !== 'string' || reply.method !== method) throw schemaError('native reply correlation is invalid.')
    return { requestId: reply.requestId, method, result: record(reply.result, 'native result'), revision: typeof reply.revision === 'string' ? reply.revision : undefined }
  }

  async scan(request: ScanRequest = {}): Promise<ScanResult> {
    await this.ensureCapabilities()
    const generation = ++this.scanGeneration
    const reply = await this.call('scan.list', { includeUnmanaged: request.includeUnmanagedCandidates !== false, limit: 500 })
    exactKeys(reply.result, ['agents', 'coverage', 'returned', 'total'], 'scan result')
    const coverage = record(reply.result.coverage, 'scan coverage')
    const capturedAt = string(coverage.captured_at, 'scan capture time') as string
    const mapped = array(reply.result.agents, 'scan agents').map((agent, index) => mapAgent(agent, capturedAt, index))
    const returned = number(reply.result.returned, 'returned agent count')
    const total = number(reply.result.total, 'total agent count')
    if (!Number.isSafeInteger(returned) || returned !== mapped.length || returned > 500 || !Number.isSafeInteger(total) || total < returned) {
      throw schemaError('scan agent counts are inconsistent.')
    }
    if (new Set(mapped.map((agent) => agent.summary.id)).size !== mapped.length) throw schemaError('scan agent identities are not unique.')
    for (const agent of mapped) {
      this.agentSnapshots.set(agentSnapshotKey(agent.summary), agent)
    }
    if (generation === this.scanGeneration) {
      this.agents.clear()
      for (const agent of mapped) this.agents.set(agent.summary.id, agent)
    }
    while (this.agentSnapshots.size > 256) this.agentSnapshots.delete(this.agentSnapshots.keys().next().value as string)
    const agents = mapped.map((item) => item.summary)
    const warnings = array(coverage.warnings, 'coverage warnings').map((warning, index) => record(warning, `coverage warning ${index}`))
    const warningMessages = warnings.map((warning) => string(warning.message, 'coverage warning message') as string)
    // The engine total includes intentionally excluded unmanaged detections.
    // Only an inclusive scan proves exactly how many results were omitted.
    const omitted = request.includeUnmanagedCandidates !== false ? total - returned : 0
    if (omitted > 0 && !warnings.some((warning) => warning.code === 'SCAN_RESULT_TRUNCATED')) {
      warningMessages.push(`${returned} of ${total} detected agents are shown; ${omitted} detections were omitted from the bounded view.`)
    }
    const complete = boolean(coverage.complete, 'coverage completeness') && omitted === 0
    const blindSpotCount = ['denied_count', 'vanished_count', 'malformed_lease_count', 'skipped_lease_count', 'other_user_count', 'unknown_owner_count', 'identity_denied_count']
      .reduce((count, field) => count + number(coverage[field], field), omitted)
    const activeStates: AgentState[] = ['healthy', 'idle']
    const attentionStates: AgentState[] = ['stale', 'orphaned', 'unresponsive', 'interrupted', 'defunct', 'failed']
    return {
      mode: 'native',
      revision: capturedAt,
      capturedAt,
      coverage: {
        completeness: complete ? 'complete' : 'partial',
        blindSpotCount,
        observedProcessCount: number(coverage.inspected_count, 'inspected process count'),
        totalProcessCount: null,
        blindSpots: complete ? warningMessages : ['Current-user process visibility is partial.', ...warningMessages],
      },
      agents,
      evidence: agents.flatMap((agent) => agent.evidence),
      metrics: {
        active: agents.filter((agent) => activeStates.includes(agent.state)).length,
        needsAttention: agents.filter((agent) => attentionStates.includes(agent.state)).length,
        unmanaged: agents.filter((agent) => agent.state === 'unmanaged').length,
        reclaimableMb: null,
      },
      usage: { requests: null, inputTokens: null, outputTokens: null, costUsd: null },
      resources: [],
      timeline: [],
      receipts: [],
    }
  }

  async getAgentDetail(agentId: string, expected?: AgentIdentityBinding): Promise<AgentDetail> {
    if (expected && expected.id !== agentId) {
      throw new TransportError('target_changed', 'The requested agent no longer matches the displayed process identity.', true, { reason: 'agent_identity_changed' })
    }
    const latest = this.agents.get(agentId)
    const cached = expected ? this.agentSnapshots.get(agentSnapshotKey(expected)) ?? latest : latest
    if (!cached) throw new TransportError('not_found', 'The agent is not present in the latest native scan.')
    const binding = expected ?? cached.summary
    if (cached.summary.id !== binding.id || cached.summary.revision !== binding.revision || cached.summary.pid !== binding.pid || cached.summary.processInstanceId !== binding.processInstanceId) {
      throw new TransportError('target_changed', 'The agent changed while reconciliation was loading; native detail no longer matches the scanned process instance.', true, { reason: 'agent_identity_changed' })
    }
    if (!cached.rawAgentId || binding.pid === null || binding.processInstanceId === null) return detailFromSummary(cached.summary)
    const reply = await this.call('agent.detail', {
      agentId: cached.rawAgentId,
      expectedPid: binding.pid,
      expectedProcessInstanceId: binding.processInstanceId,
    })
    const mappedAgent = mapAgent(reply.result, String(cached.summary.revision), 0)
    const mapped = mappedAgent.summary
    if (mappedAgent.rawAgentId !== cached.rawAgentId || mapped.id !== binding.id || mapped.revision !== binding.revision || mapped.pid !== binding.pid || mapped.processInstanceId !== binding.processInstanceId) {
      throw new TransportError('target_changed', 'The agent changed while reconciliation was loading; native detail no longer matches the scanned process instance.', true, { reason: 'agent_identity_changed' })
    }
    return detailFromSummary({ ...mapped, id: cached.summary.id, revision: cached.summary.revision })
  }

  async planAction(request: PlanRequest): Promise<ActionPlan> {
    if (request.kind !== 'graceful-stop' && request.kind !== 'force-stop') {
      throw new TransportError('invalid_request', 'The requested action kind is not supported.', false)
    }
    if (!isProcessId(request.target.pid)) {
      throw new TransportError('invalid_request', 'The action target PID is outside the supported range.', false)
    }
    await this.ensureCapabilities()
    if (!this.capabilities.processActions) {
      throw new TransportError('unsupported', processActionsUnavailableReason, false)
    }
    const cached = this.agents.get(request.agentId)
    if (!cached?.summary.actionable || !cached.rawAgentId || cached.summary.pid === null || !cached.summary.processInstanceId) {
      throw new TransportError('not_actionable', cached?.summary.actionReason ?? 'A fresh native scan is required before review.', false)
    }
    if (request.target.pid !== cached.summary.pid || request.target.processInstanceId !== cached.summary.processInstanceId) {
      throw new TransportError('target_changed', 'The requested process instance is no longer present in the latest scan.', true, { reason: 'process_instance_changed' })
    }
    const engineMode = request.kind === 'graceful-stop' ? 'request_stop' : 'kill'
    const reply = await this.call('action.plan', { agentId: cached.rawAgentId, mode: engineMode, target: request.target })
    exactKeys(reply.result, ['plan_id', 'digest', 'expires_at', 'consequences', 'warnings', 'target'], 'action plan')
    const planId = string(reply.result.plan_id, 'plan ID') as string
    const consequences = array(reply.result.consequences, 'plan consequences').map((item) => string(item, 'plan consequence') as string)
    const warnings = array(reply.result.warnings, 'plan warnings').map((item) => string(item, 'plan warning') as string)
    const rawTarget = record(reply.result.target, 'action plan target')
    exactKeys(rawTarget, ['pid', 'process_instance_id', 'state'], 'action plan target')
    const target = {
      pid: number(rawTarget.pid, 'action plan target PID'),
      processInstanceId: processInstanceId(rawTarget.process_instance_id, 'action plan process instance ID') as string,
      state: mapState(rawTarget.state),
    }
    if (!isProcessId(target.pid)) throw schemaError('action plan target PID is invalid.')
    if (target.pid !== request.target.pid || target.processInstanceId !== request.target.processInstanceId) {
      throw new TransportError('target_changed', 'The engine plan target does not match the requested process instance. Nothing can be executed.', true, { reason: 'process_instance_changed' })
    }
    const plan: ActionPlan = {
      planId,
      agentId: cached.summary.id,
      digest: string(reply.result.digest, 'plan digest') as string,
      createdAt: null,
      expiresAt: string(reply.result.expires_at, 'plan expiry') as string,
      kind: request.kind,
      engineMode,
      target,
      strategy: engineMode === 'request_stop'
        ? 'Request cooperative cancellation and re-check the exact managed target.'
        : 'Force-stop the exact managed target after identity revalidation.',
      timeoutSeconds: null,
      expectedPortsReleased: null,
      eligibleQuarantineFiles: null,
      memoryEffect: 'unchanged',
      irreversibleConsequences: [...consequences, ...warnings.map((warning) => `Warning: ${warning}`)],
    }
    this.actionPlans.set(planId, { agentId: cached.summary.id, kind: request.kind, target: request.target })
    return plan
  }

  async executeAction(request: ExecuteRequest): Promise<ContainmentReceipt> {
    const plan = this.actionPlans.get(request.planId)
    if (!plan) throw new TransportError('plan_changed', 'The action plan is not bound to this renderer session. Review a fresh plan.', false)
    try {
      const reply = await this.call('action.execute', { planId: request.planId, digest: request.digest })
      this.actionPlans.delete(request.planId)
      const receipt = mapReceipt(reply.result, plan.agentId)
      if (receipt.planId !== request.planId) {
        throw new TransportError('outcome_uncertain', 'The engine receipt did not match the executed plan. Do not repeat the action; reconcile local state.', true, {
          reconcileRequired: true,
          expectedPlanId: request.planId,
          receivedPlanId: receipt.planId,
        })
      }
      return receipt
    } catch (reason) {
      if (reason instanceof TransportError && (reason.code === 'outcome_uncertain' || reason.details?.reconcileRequired === true)) this.actionPlans.delete(request.planId)
      throw reason
    }
  }

  async getActivity(): Promise<ActivityResult> {
    await this.ensureCapabilities()
    const activityPages = await this.collectPages('activity.list', 'receipts', 'activity result')
    const quarantinePages = await this.collectPages('quarantine.list', 'entries', 'quarantine result')
    const rawReceipts = activityPages.items.map((receipt) => record(receipt, 'activity receipt'))
    const receipts = rawReceipts.filter((receipt) => receipt.kind === undefined || receipt.kind === 'process').map((receipt) => mapReceipt(receipt, null))
    const localReceipts = rawReceipts.filter((receipt) => receipt.kind !== undefined && receipt.kind !== 'process').map(mapLocalReceipt)
    const quarantine: QuarantineEntry[] = quarantinePages.items.map((entryValue) => {
      const entry = record(entryValue, 'quarantine entry')
      const state = string(entry.state, 'quarantine state') as string
      if (!['quarantined', 'restored', 'restoring', 'interrupted', 'partial'].includes(state)) throw schemaError('quarantine state is invalid.')
      const mappedState = state === 'restored' ? 'Restored' as const
        : state === 'restoring' ? 'Restoring' as const
          : state === 'interrupted' ? 'Interrupted' as const
            : state === 'partial' ? 'Partial' as const : 'Quarantined' as const
      return {
        id: string(entry.entry_id, 'quarantine entry ID') as string,
        agentId: string(entry.agent_id, 'quarantine agent ID', true),
        resourceType: string(entry.resource_type, 'quarantine resource type') as string,
        createdAt: string(entry.created_at, 'quarantine creation time') as string,
        receiptId: null,
        basename: null,
        displayPath: null,
        size: null,
        hashPrefix: null,
        digest: null,
        retainedUntil: null,
        state: mappedState,
        restorable: mappedState === 'Partial' || mappedState === 'Interrupted' ? false : boolean(entry.restorable, 'quarantine restorable'),
        revision: string(entry.updated_at, 'quarantine update time') as string,
      }
    })
    return {
      capturedAt: null, events: [], receipts, localReceipts, memoryReceipts: [], quarantine, graveyardReceipts: [],
      pagination: { activityTruncated: activityPages.truncated, quarantineTruncated: quarantinePages.truncated },
    }
  }

  private async collectPages(method: 'activity.list' | 'quarantine.list', key: 'receipts' | 'entries', label: string) {
    const items: unknown[] = []
    const seen = new Set<string>()
    let cursor: string | null = null
    for (let page = 0; page < 20; page += 1) {
      const reply = await this.call(method, cursor ? { limit: 500, cursor } : { limit: 500 })
      exactKeys(reply.result, [key, 'next_cursor'], label)
      items.push(...array(reply.result[key], `${label} ${key}`))
      const nextCursor = reply.result.next_cursor === null ? null : string(reply.result.next_cursor, `${label} next cursor`) as string
      if (!nextCursor) return { items, truncated: false }
      if (seen.has(nextCursor)) return { items, truncated: true }
      seen.add(nextCursor)
      cursor = nextCursor
    }
    return { items, truncated: cursor !== null }
  }

  async getVault(): Promise<VaultResult> {
    await this.ensureCapabilities()
    const sources: unknown[] = []
    const seen = new Set<string>()
    let cursor: string | null = null
    let complete = false
    for (let page = 0; page < 20; page += 1) {
      const reply = await this.call('vault.list', cursor ? { limit: 500, cursor } : { limit: 500 })
      exactKeys(reply.result, ['sources', 'next_cursor', 'local_only_warning'], 'vault result')
      sources.push(...array(reply.result.sources, 'vault sources'))
      const nextCursor = reply.result.next_cursor === null ? null : string(reply.result.next_cursor, 'vault next cursor') as string
      if (!nextCursor) { complete = true; break }
      if (seen.has(nextCursor)) throw new TransportError('protocol_violation', 'The native Vault source cursor repeated; source inventory was not shown.', false)
      seen.add(nextCursor)
      cursor = nextCursor
    }
    if (!complete) throw new TransportError('protocol_violation', 'The native Vault source inventory exceeded its bounded page limit and was not shown.', false)
    return {
      mode: 'native',
      capturedAt: null,
      sources: sources.map((sourceValue) => {
        const source = record(sourceValue, 'vault source')
        const capabilities = record(source.capabilities, 'vault capabilities')
        const format = string(source.format, 'vault format') as string
        return {
          id: string(source.source_id, 'vault source ID') as string,
          name: string(source.source_id, 'vault source ID') as string,
          kind: mapVaultFormat(format),
          project: null,
          revision: string(source.revision, 'vault revision') as string,
          revisionDigest: string(source.revision, 'vault revision') as string,
          status: boolean(capabilities.editable, 'vault edit capability') && this.capabilities.vaultMutation ? 'Healthy' as const : boolean(capabilities.queryable, 'vault query capability') ? 'Read-only' as const : 'Unsupported' as const,
          capabilities: [
            ...(boolean(capabilities.queryable, 'vault query capability') ? ['search' as const] : []),
            ...(boolean(capabilities.editable, 'vault edit capability') && this.capabilities.vaultMutation ? ['edit' as const] : []),
            ...(boolean(capabilities.snapshot, 'vault snapshot capability') && this.capabilities.memoryHistory ? ['snapshot' as const] : []),
            ...(boolean(capabilities.restore, 'vault restore capability') && this.capabilities.memoryHistory ? ['restore' as const] : []),
          ],
          detail: (string(capabilities.reason, 'vault capability reason', true) ?? 'Explicitly registered local source. Adapter and engine capabilities determine available operations.'),
        }
      }),
    }
  }

  async searchMemory(request: MemorySearchRequest): Promise<MemorySearchResult> {
    if (!request.sourceId) throw new TransportError('invalid_request', 'Select one native vault source before searching.', false)
    if (!Number.isInteger(request.page) || request.page < 1 || !Number.isInteger(request.pageSize) || request.pageSize < 1 || request.pageSize > 500 || (request.page === 1 && request.cursor) || (request.page > 1 && !request.cursor) || request.tag || request.agent || request.from || request.to) {
      throw unsupported('Native Vault search supports bounded cursor pages with text, source, and collection filters only.')
    }
    const sourceId = request.sourceId
    const cursorKey = JSON.stringify([sourceId, request.collection ?? null, request.query, request.pageSize])
    if (request.page === 1) this.memoryCursors.set(cursorKey, { nextByPage: new Map([[1, null]]) })
    const ledger = this.memoryCursors.get(cursorKey) ?? { nextByPage: new Map<number, string | null>() }
    const expectedCursor = ledger.nextByPage.get(request.page)
    if (request.page > 1 && (expectedCursor === undefined || request.cursor !== expectedCursor || !request.cursor)) {
      throw new TransportError('invalid_request', 'The memory page cursor is stale; return to page 1 and search again.', false)
    }
    this.memoryCursors.set(cursorKey, ledger)
    while (this.memoryCursors.size > 32) this.memoryCursors.delete(this.memoryCursors.keys().next().value as string)
    const queryPayload: Record<string, unknown> = {
      sourceId,
      namespace: request.collection ?? null,
      text: request.query || null,
      limit: request.pageSize,
    }
    if (request.cursor) queryPayload.cursor = request.cursor
    let reply: NativeReply
    try { reply = await this.call('vault.query', queryPayload) }
    catch (reason) {
      if (this.memoryCursors.get(cursorKey) === ledger) this.memoryCursors.delete(cursorKey)
      throw reason
    }
    exactKeys(reply.result, ['records', 'next_cursor', 'total', 'local_only_warning'], 'vault query')
    const capturedAt = null
    const records = array(reply.result.records, 'vault records').map((value) => mapMemoryRecord(value, sourceId))
    const nextCursor = reply.result.next_cursor === null ? null : string(reply.result.next_cursor, 'vault next cursor') as string
    const total = number(reply.result.total, 'vault total')
    const pageRevisions = new Set(records.map((record) => record.sourceRevisionDigest as string))
    const existingNext = ledger.nextByPage.get(request.page + 1)
    const cyclesToEarlierPage = nextCursor !== null && [...ledger.nextByPage.entries()]
      .some(([page, cursor]) => page !== request.page + 1 && cursor === nextCursor)
    const cursorChanged = existingNext !== undefined && existingNext !== nextCursor
    const totalChanged = ledger.total !== undefined && ledger.total !== total
    const pageRevision = pageRevisions.size === 1 ? pageRevisions.values().next().value : undefined
    const revisionChanged = pageRevisions.size > 1 || (ledger.sourceRevision !== undefined && pageRevision !== undefined && ledger.sourceRevision !== pageRevision)
    if (cursorChanged || totalChanged || revisionChanged || (nextCursor !== null && (nextCursor === request.cursor || cyclesToEarlierPage))) {
      if (this.memoryCursors.get(cursorKey) === ledger) this.memoryCursors.delete(cursorKey)
      throw new TransportError('protocol_violation', 'The native memory cursor chain changed; return to page 1 and search again.', false)
    }
    ledger.total ??= total
    if (pageRevision !== undefined) ledger.sourceRevision ??= pageRevision
    ledger.nextByPage.set(request.page + 1, nextCursor)
    return { capturedAt, page: request.page, pageSize: request.pageSize, total, records, nextCursor }
  }

  async getMemoryRecord(sourceId: string, recordId: string): Promise<MemoryRecord> {
    const reply = await this.call('vault.get', { sourceId, recordId })
    exactKeys(reply.result, ['record', 'local_only_warning'], 'vault record result')
    return mapMemoryRecord(reply.result.record, sourceId)
  }

  async getMemoryHistory(_sourceId: string, _recordId: string): Promise<MemoryHistoryEntry[]> {
    throw unsupported('Native history uses source snapshots rather than synthetic demo record receipts.')
  }

  async planMemoryChange(_request: MemoryChangeRequest): Promise<MemoryPlan> { throw unsupported('Numeric demo plans cannot address a native source digest. Use the native scalar workflow.') }
  async executeMemoryChange(_request: PlanExecutionRequest): Promise<MemoryReceipt> { throw unsupported('Use the native scalar workflow to execute a reviewed native memory plan.') }
  async planMemoryRestore(_request: RestorePlanRequest): Promise<RestorePlan> { throw unsupported('Native restore requires a source digest and verified source snapshot, not a numeric demo record revision.') }
  async executeMemoryRestore(_request: PlanExecutionRequest): Promise<MemoryReceipt> { throw unsupported('Use the native snapshot workflow to execute a reviewed source restore.') }
  async planGraveyardRestore(entryId: string): Promise<GraveyardPlan> {
    await this.requireCapability('quarantineRestore')
    const plan = await this.localPlan('quarantine.restore-plan', { entryId }, 'quarantine.restore-execute')
    this.graveyardPlans.set(plan.planId, entryId)
    return { ...plan, entryId, entryDigest: null, expectedRevision: null }
  }

  async executeGraveyardRestore(request: PlanExecutionRequest): Promise<GraveyardReceipt> {
    const entryId = this.graveyardPlans.get(request.planId)
    if (!entryId) throw unsupported('Review the exact quarantine entry before restoring it.')
    const receipt = await this.localExecute('quarantine.restore-execute', request)
    this.graveyardPlans.delete(request.planId)
    if (receipt.certainty !== 'verified' || receipt.partialFailures.length > 0 || !['completed', 'restored', 'already_restored'].includes(receipt.outcome)) {
      throw new TransportError('outcome_uncertain', 'Restore did not confirm completion. Refresh the Graveyard before reviewing another restore.', true, { reconcileRequired: true })
    }
    return { receiptId: receipt.receiptId, correlationId: receipt.receiptId, entryId, result: 'Restored', completedAt: receipt.createdAt }
  }

  async executeNativeGraveyardRestore(request: PlanExecutionRequest): Promise<LocalWorkflowReceipt> {
    if (!this.graveyardPlans.has(request.planId)) throw unsupported('Review the exact quarantine entry before restoring it.')
    const receipt = await this.localExecute('quarantine.restore-execute', request)
    this.graveyardPlans.delete(request.planId)
    return receipt
  }

  private async requireCapability(key: keyof TransportCapabilities) {
    await this.ensureCapabilities()
    if (this.capabilities[key] !== true) throw unsupported('The local engine did not confirm this workflow. Retry loading its capabilities.')
  }

  private async localPlan(method: string, payload: Record<string, unknown>, executeMethod: string, context: { sourceId?: string; recordId?: string; expectedRevision?: string; snapshotId?: string } = {}): Promise<LocalWorkflowPlan> {
    const reply = await this.call(method, payload)
    const plan = mapLocalPlan(reply.result)
    if ((context.sourceId && plan.sourceId !== context.sourceId) || (context.recordId && plan.recordId !== context.recordId) || (context.expectedRevision && plan.beforeRevision !== context.expectedRevision) || (context.snapshotId && plan.snapshotId !== context.snapshotId)) {
      throw new TransportError('protocol_violation', 'The returned plan does not match the selected source, record, snapshot, or revision. No action was issued.', false)
    }
    this.localPlans.set(plan.planId, { executeMethod, digest: plan.digest, pending: false, ...context })
    while (this.localPlans.size > 128) this.localPlans.delete(this.localPlans.keys().next().value as string)
    return plan
  }

  private async localExecute(method: string, request: PlanExecutionRequest): Promise<LocalWorkflowReceipt> {
    const binding = this.localPlans.get(request.planId)
    if (!binding || binding.executeMethod !== method) throw new TransportError('plan_changed', 'This local plan is not bound to the reviewed operation. Review again.', false)
    if (binding.digest !== request.digest) throw new TransportError('plan_changed', 'The submitted digest does not match the reviewed local plan.', false)
    if (binding.pending) throw new TransportError('plan_replayed', 'This reviewed operation is already pending. Do not submit it again.', false)
    binding.pending = true
    try {
      const reply = await this.call(method, { planId: request.planId, digest: request.digest })
      this.localPlans.delete(request.planId)
      let receipt: LocalWorkflowReceipt
      try { receipt = mapLocalReceipt(reply.result) }
      catch { throw new TransportError('outcome_uncertain', 'Execution returned an invalid receipt. Refresh local state before another operation.', true, { reconcileRequired: true }) }
      const issued = receipt.certainty !== 'failed_before_issue' || receipt.actionIssued !== false
      if (receipt.planId !== request.planId || (issued && ((binding.sourceId && receipt.sourceId !== binding.sourceId) || (binding.recordId && receipt.recordId !== binding.recordId) || (binding.expectedRevision && receipt.beforeRevision !== binding.expectedRevision) || (binding.snapshotId && receipt.snapshotId !== binding.snapshotId)))) {
        throw new TransportError('outcome_uncertain', 'Execution receipt did not match the reviewed local target. Refresh local state before another operation.', true, { reconcileRequired: true })
      }
      if (issued && binding.sourceId && receipt.certainty === 'verified' && receipt.outcome === 'completed' && (!receipt.snapshotId || !receipt.afterRevision)) throw new TransportError('outcome_uncertain', 'The memory receipt did not identify its verified snapshot and resulting revision. Refresh local state.', true, { reconcileRequired: true })
      return receipt
    } catch (reason) {
      if (reason instanceof TransportError && (reason.code === 'outcome_uncertain' || reason.details?.reconcileRequired)) this.localPlans.delete(request.planId)
      throw reason
    } finally { binding.pending = false }
  }

  async registerMemorySource(path: string): Promise<void> {
    await this.requireCapability('sourceRegistration')
    const reply = await this.call('vault.register', { path })
    if (reply.result.selected_locally !== true || reply.result.read_only !== true) throw schemaError('registration did not confirm a locally selected read-only source.')
  }

  async getNativeSnapshots(sourceId: string): Promise<NativeSnapshot[]> {
    await this.requireCapability('memoryHistory')
    const reply = await this.call('vault.snapshot.list', { sourceId, limit: 500 })
    return array(reply.result.snapshots, 'vault snapshots').map((value) => {
      const item = record(value, 'vault snapshot')
      const status = string(item.status, 'snapshot status')
      if (!['verified', 'restored', 'invalid'].includes(status as string) || item.source_id !== sourceId) throw schemaError('snapshot source or status is invalid.')
      return { id: string(item.snapshot_id, 'snapshot ID') as string, sourceId, sourceRevision: digestString(item.source_revision, 'snapshot revision'), digest: digestString(item.digest, 'snapshot digest'), size: number(item.size, 'snapshot size'), status: status as NativeSnapshot['status'], createdAt: string(item.created_at, 'snapshot timestamp') as string }
    })
  }

  async planNativeMemoryChange(request: { sourceId: string; recordId: string; expectedRevision: string; field: NativeScalarField; value: ScalarValue }): Promise<LocalWorkflowPlan> {
    await this.requireCapability('vaultMutation')
    digestString(request.expectedRevision, 'expected source revision')
    const payload: Record<string, unknown> = { sourceId: request.sourceId, recordId: request.recordId, expectedRevision: request.expectedRevision, operation: request.field.kind, value: request.value }
    if (request.field.kind === 'update_field') payload.field = request.field.field
    if (request.field.kind === 'update_metadata') payload.metadataKey = request.field.field
    return this.localPlan('vault.mutation.plan', payload, 'vault.mutation.execute', { sourceId: request.sourceId, recordId: request.recordId, expectedRevision: request.expectedRevision })
  }

  async executeNativeMemoryChange(request: PlanExecutionRequest) { return this.localExecute('vault.mutation.execute', request) }
  async planNativeMemoryRestore(request: { sourceId: string; snapshotId: string; snapshotDigest: string; expectedRevision: string }) {
    await this.requireCapability('memoryHistory')
    return this.localPlan('vault.restore.plan', request, 'vault.restore.execute', { sourceId: request.sourceId, snapshotId: request.snapshotId, expectedRevision: request.expectedRevision })
  }
  async executeNativeMemoryRestore(request: PlanExecutionRequest) { return this.localExecute('vault.restore.execute', request) }

  async getDeclaredResources(agentId: string, expected: AgentIdentityBinding): Promise<DeclaredResource[]> {
    const binding = declaredResourceBinding(agentId, expected)
    await this.requireCapability('resourceCleanup')
    const reply = await this.call('quarantine.resource-list', { agentId, ...binding })
    if (reply.result.agent_id !== agentId) throw schemaError('declared resources belong to a different agent.')
    const values = array(reply.result.resources, 'declared resources')
    if (values.length > 64 || reply.result.returned !== values.length) throw schemaError('declared resource counts are inconsistent.')
    const indices = new Set<number>()
    return values.map((value) => {
      const item = record(value, 'declared resource')
      const index = number(item.resource_index, 'declared resource index')
      if (!Number.isInteger(index) || index < 0 || index > 63 || indices.has(index)) throw schemaError('declared resource index is invalid.')
      indices.add(index)
      const resourceType = string(item.resource_type, 'resource type') as string
      if (item.kind !== 'temporary' || !['file', 'directory', 'unknown'].includes(resourceType)) throw schemaError('declared resource type is invalid.')
      const eligible = boolean(item.cleanup_available, 'cleanup eligibility')
      const declarationDigest = item.declaration_digest === null ? null : digestString(item.declaration_digest, 'declared resource digest')
      if (eligible && declarationDigest === null) throw schemaError('eligible declared resource has no declaration digest.')
      return { id: eligible ? `${index}:${declarationDigest}` : String(index), resourceType, label: `Declared temporary ${resourceType} #${index + 1}`, eligible, reason: string(item.reason, 'cleanup reason') }
    })
  }
  async planResourceCleanup(agentId: string, resourceId: string, expected: AgentIdentityBinding) {
    const binding = declaredResourceBinding(agentId, expected)
    await this.requireCapability('resourceCleanup')
    const opaqueId = /^(0|[1-9][0-9]?):([a-f0-9]{64})$/.exec(resourceId)
    const resourceIndex = opaqueId ? Number(opaqueId[1]) : -1
    if (!opaqueId || resourceIndex > 63) throw unsupported('Select an eligible engine-listed declared resource with its exact declaration digest.')
    return this.localPlan('quarantine.plan', { agentId, resourceIndex, expectedDeclarationDigest: opaqueId[2], ...binding }, 'quarantine.execute')
  }
  async executeResourceCleanup(request: PlanExecutionRequest) { return this.localExecute('quarantine.execute', request) }
  async planDiagnosticsExport(destination: string) {
    await this.requireCapability('diagnosticsExport')
    return this.localPlan('diagnostics.export-plan', { destination, includeReceipts: true, includeSettings: true }, 'diagnostics.export-execute')
  }
  async executeDiagnosticsExport(request: PlanExecutionRequest) { return this.localExecute('diagnostics.export-execute', request) }

  async getSettings(): Promise<AppSettings> {
    await this.ensureCapabilities()
    const reply = await this.call('settings.get', {})
    return mapSettings(reply)
  }

  async updateSettings(request: { expectedRevision: number; changes: Partial<Omit<AppSettings, 'revision'>> }): Promise<AppSettings> {
    await this.requireCapability('settingsUpdate')
    if (!Number.isInteger(request.expectedRevision) || request.expectedRevision < 0) throw new TransportError('conflict', 'Reload native settings before applying this change.')
    const changes: Record<string, unknown> = {}
    if (request.changes.theme !== undefined) changes.appearance = request.changes.theme
    if (request.changes.motion !== undefined) {
      if (request.changes.motion === 'system') throw unsupported('The native engine stores an explicit reduced-motion value; system-following is a browser preference.')
      changes.reducedMotion = request.changes.motion === 'reduce'
    }
    if (request.changes.autoRefreshSeconds !== undefined) {
      if (request.changes.autoRefreshSeconds < 5) throw unsupported('Native scan intervals cannot be paused through the engine setting.')
      changes.scanIntervalSeconds = request.changes.autoRefreshSeconds
    }
    if (request.changes.quarantineRetentionDays !== undefined) changes.retentionDays = request.changes.quarantineRetentionDays
    if (request.changes.heartbeatGraceSeconds !== undefined) changes.heartbeatGraceSeconds = request.changes.heartbeatGraceSeconds
    if (request.changes.includeUnmanagedCandidates !== undefined) changes.includeUnmanagedCandidates = request.changes.includeUnmanagedCandidates
    if (request.changes.detectionPreset !== undefined || request.changes.denseMode !== undefined) throw unsupported('That preference is available only in Demo lab mode.')
    if (Object.keys(changes).length === 0) throw new TransportError('invalid_request', 'No supported native setting changed.', false)
    const reply = await this.call('settings.update', { expectedRevision: request.expectedRevision, changes })
    return mapSettings(reply)
  }

  async resetSettings(expectedRevision: number): Promise<AppSettings> {
    return this.updateSettings({
      expectedRevision,
      changes: { theme: 'system', motion: 'full', autoRefreshSeconds: 30, quarantineRetentionDays: 30, heartbeatGraceSeconds: 120, includeUnmanagedCandidates: true },
    })
  }
}

function mapReceipt(value: Record<string, unknown>, agentId: string | null): ContainmentReceipt {
  exactKeys(value, ['receipt_id', 'plan_id', 'outcome', 'certainty', 'action_issued', 'partial_failures', 'created_at', ...(value.kind === undefined ? [] : ['kind'])], 'action receipt')
  if (value.kind !== undefined && mapReceiptKind(value.kind) !== 'process') throw schemaError('process receipt kind is invalid.')
  const certaintyValue = string(value.certainty, 'receipt certainty')
  if (!['verified', 'failed_before_issue', 'uncertain'].includes(certaintyValue as string)) throw schemaError('receipt certainty is invalid.')
  const certainty = certaintyValue as 'verified' | 'failed_before_issue' | 'uncertain'
  const actionIssued = value.action_issued === null ? null : boolean(value.action_issued, 'action issuance')
  const outcome = string(value.outcome, 'receipt outcome') as string
  if (!['requested', 'pending', 'completed', 'disappeared', 'access_denied', 'identity_mismatch', 'interrupted', 'failed'].includes(outcome)) {
    throw schemaError('receipt outcome is invalid.')
  }
  const failureValues = array(value.partial_failures, 'receipt partial failures')
  if (failureValues.length > 64) throw schemaError('receipt has too many partial failures.')
  const partialFailures = failureValues.map((failure) => {
    if (typeof failure !== 'string' || failure.trim().length === 0 || failure.length > 2_048) {
      throw schemaError('receipt partial failure is invalid.')
    }
    return failure
  })
  const title = certainty === 'uncertain' ? 'Outcome uncertain' as const
    : certainty === 'failed_before_issue' ? 'Containment not issued' as const
      : partialFailures.length > 0 ? 'Containment partially completed' as const
        : outcome === 'completed' ? 'Containment complete' as const : 'Containment issued' as const
  const receiptId = string(value.receipt_id, 'receipt ID') as string
  const partialSummary = partialFailures.length > 0 ? ` ${partialFailures.length} partial follow-up failure${partialFailures.length === 1 ? '' : 's'}; see structured receipt details.` : ''
  return {
    receiptId,
    planId: string(value.plan_id, 'receipt plan ID') as string,
    title,
    completedAt: string(value.created_at, 'receipt timestamp') as string,
    agentId,
    processCount: null,
    portCount: null,
    fileCount: null,
    memoryEffect: 'unchanged',
    diagnostics: `Receipt ${receiptId}; outcome ${outcome}; certainty ${certainty}.${partialSummary}`,
    partialFailures,
    outcome,
    certainty,
    actionIssued,
  }
}

function metadataString(metadata: Record<string, unknown>, key: string): string | null {
  return typeof metadata[key] === 'string' ? metadata[key] as string : null
}

function mapVaultFormat(format: string): MemorySource['kind'] {
  if (format === 'json') return 'JSON'
  if (format === 'jsonl') return 'JSONL'
  if (format === 'sqlite') return 'SQLite'
  if (format === 'chroma') return 'Chroma'
  if (format === 'faiss') return 'FAISS'
  if (format === 'unsupported') return 'Unsupported'
  throw schemaError('vault source format is invalid.')
}

function mapMemoryRecord(value: unknown, sourceId: string): MemoryRecord {
  const raw = record(value, 'vault record')
  const metadata = record(raw.metadata, 'vault record metadata')
  const recordId = string(raw.record_id, 'vault record ID') as string
  const metadataTags = metadata.tags
  return {
    id: recordId,
    sourceId,
    revision: string(raw.source_revision, 'vault record source revision') as string,
    sourceRevisionDigest: string(raw.source_revision, 'vault record source revision') as string,
    title: metadataString(metadata, 'title') ?? recordId,
    content: typeof raw.content === 'string' ? raw.content : (() => { throw schemaError('vault record content is invalid.') })(),
    tags: Array.isArray(metadataTags) ? metadataTags.filter((tag): tag is string => typeof tag === 'string') : [],
    collection: string(raw.namespace, 'vault record namespace') as string,
    agent: metadataString(metadata, 'agent'),
    writer: metadataString(metadata, 'writer'),
    updatedAt: metadataString(metadata, 'updated_at'),
    referencedSessions: null,
    references: null,
    embedding: boolean(raw.embedding_present, 'embedding presence') ? 'Present' : 'Not present',
    excluded: null,
    quarantined: null,
    editableFields: raw.editable_fields === undefined ? [] : array(raw.editable_fields, 'editable scalar fields').map(mapScalarField),
  }
}

function mapSettings(reply: NativeReply): AppSettings {
  exactKeys(reply.result, ['settings', 'revision'], 'settings result')
  const value = record(reply.result.settings, 'settings values')
  exactKeys(value, ['scan_interval_seconds', 'heartbeat_grace_seconds', 'retention_days', 'include_unmanaged_candidates', 'appearance', 'reduced_motion'], 'settings result')
  const revision = number(reply.result.revision, 'settings revision')
  if (!Number.isInteger(revision) || revision < 0) throw schemaError('settings revision is invalid.')
  const appearance = string(value.appearance, 'settings appearance')
  if (!['system', 'light', 'dark'].includes(appearance as string)) throw schemaError('settings appearance is invalid.')
  return {
    revision,
    detectionPreset: null,
    theme: appearance as AppSettings['theme'],
    motion: boolean(value.reduced_motion, 'reduced motion') ? 'reduce' : 'full',
    denseMode: null,
    autoRefreshSeconds: number(value.scan_interval_seconds, 'scan interval'),
    quarantineRetentionDays: number(value.retention_days, 'retention days'),
    heartbeatGraceSeconds: number(value.heartbeat_grace_seconds, 'heartbeat grace'),
    includeUnmanagedCandidates: boolean(value.include_unmanaged_candidates, 'include unmanaged candidates'),
  }
}

function unsupported(message: string) {
  return new TransportError('unsupported', message, false)
}

function digestString(value: unknown, label: string): string {
  const result = string(value, label) as string
  if (!/^[a-f0-9]{64}$/.test(result)) throw schemaError(`${label} is not a digest.`)
  return result
}

function declaredResourceBinding(agentId: string, expected: AgentIdentityBinding): { expectedPid: number; expectedProcessInstanceId: string } {
  if (expected.id !== agentId || !isProcessId(expected.pid) || typeof expected.processInstanceId !== 'string' || !/^[a-f0-9]{64}$/.test(expected.processInstanceId)) {
    throw new TransportError('target_changed', 'Cleanup requires the selected lease owner PID and stable process instance. Refresh its details before review.', false)
  }
  return { expectedPid: expected.pid, expectedProcessInstanceId: expected.processInstanceId }
}

function mapScalarField(value: unknown): NativeScalarField {
  const item = record(value, 'editable scalar field')
  const kind = string(item.kind, 'scalar operation')
  const valueType = string(item.value_type, 'scalar value type')
  if (!['update_content', 'update_field', 'update_metadata'].includes(kind as string) || !['string', 'number', 'boolean', 'null'].includes(valueType as string)) throw schemaError('editable scalar field is invalid.')
  if ((item.value === null ? 'null' : typeof item.value) !== valueType || (typeof item.value === 'number' && !Number.isFinite(item.value))) throw schemaError('editable scalar value is invalid.')
  return { field: string(item.field, 'editable field name') as string, kind: kind as NativeScalarField['kind'], valueType: valueType as NativeScalarField['valueType'], value: item.value as ScalarValue }
}

function mapLocalPlan(value: Record<string, unknown>): LocalWorkflowPlan {
  return {
    planId: string(value.plan_id, 'local plan ID') as string,
    digest: digestString(value.digest, 'local plan digest'),
    expiresAt: string(value.expires_at, 'local plan expiry') as string,
    consequences: array(value.consequences, 'plan consequences').map((item) => string(item, 'plan consequence') as string),
    warnings: array(value.warnings, 'plan warnings').map((item) => string(item, 'plan warning') as string),
    ...(value.source_id == null ? {} : { sourceId: string(value.source_id, 'plan source') as string }),
    ...(value.record_id == null ? {} : { recordId: string(value.record_id, 'plan record') as string }),
    ...(value.snapshot_id == null ? {} : { snapshotId: string(value.snapshot_id, 'plan snapshot') as string }),
    ...(value.before_revision == null ? {} : { beforeRevision: digestString(value.before_revision, 'plan source revision') }),
    ...(value.backup_verified === undefined ? {} : { backupVerified: boolean(value.backup_verified, 'plan backup verification') }),
    ...(value.diff === undefined ? {} : { diff: array(value.diff, 'memory plan diff').map((value) => {
      const item = record(value, 'field diff')
      if (typeof item.old_preview !== 'string' || typeof item.new_preview !== 'string') throw schemaError('memory diff preview is not text.')
      return { field: string(item.field_name, 'diff field') as string, oldHash: digestString(item.old_hash, 'old field hash'), newHash: digestString(item.new_hash, 'new field hash'), oldPreview: item.old_preview, newPreview: item.new_preview }
    }) }),
  }
}

function mapLocalReceipt(value: Record<string, unknown>): LocalWorkflowReceipt {
  const certainty = string(value.certainty, 'receipt certainty')
  if (!['verified', 'failed_before_issue', 'uncertain'].includes(certainty as string)) throw schemaError('local receipt certainty is invalid.')
  return {
    receiptId: string(value.receipt_id, 'receipt ID') as string,
    planId: string(value.plan_id, 'receipt plan ID') as string,
    outcome: string(value.outcome, 'receipt outcome') as string,
    certainty: certainty as LocalWorkflowReceipt['certainty'],
    actionIssued: value.action_issued === null ? null : boolean(value.action_issued, 'action issuance'),
    partialFailures: array(value.partial_failures, 'partial failures').map((item) => string(item, 'partial failure') as string),
    createdAt: string(value.created_at, 'receipt timestamp') as string,
    ...(value.source_id == null ? {} : { sourceId: string(value.source_id, 'receipt source') as string }),
    ...(value.record_id == null ? {} : { recordId: string(value.record_id, 'receipt record') as string }),
    ...(value.snapshot_id == null ? {} : { snapshotId: string(value.snapshot_id, 'receipt snapshot') as string }),
    ...(value.before_revision == null ? {} : { beforeRevision: digestString(value.before_revision, 'before revision') }),
    ...(value.after_revision == null ? {} : { afterRevision: digestString(value.after_revision, 'after revision') }),
    ...(value.operation == null ? {} : { operation: string(value.operation, 'receipt operation') as string }),
    ...(value.kind === undefined ? {} : { kind: mapReceiptKind(value.kind) }),
  }
}

function mapReceiptKind(value: unknown): NonNullable<LocalWorkflowReceipt['kind']> {
  if (value !== 'process' && value !== 'memory' && value !== 'quarantine' && value !== 'diagnostics') throw schemaError('receipt workflow kind is invalid.')
  return value
}
