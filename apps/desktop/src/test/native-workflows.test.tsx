import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import { MemoryPage } from '../features/memory/MemoryPage'
import { SettingsPage } from '../features/settings/SettingsPage'
import { AgentDetails } from '../features/swarm/AgentDetails'
import { ActivityPage } from '../features/activity/ActivityPage'
import { TauriTransport } from '../transport/tauri'
import App from '../App'
import { LocalWorkflowReview } from '../components/LocalWorkflowReview'
import { NativeSnapshotHistory } from '../features/memory/NativeSnapshotHistory'

const revision = 'a'.repeat(64)
const nextRevision = 'b'.repeat(64)
const digest = 'c'.repeat(64)
const methods = ['action.plan', 'action.execute', 'activity.list', 'quarantine.list', 'quarantine.restore-plan', 'quarantine.restore-execute', 'vault.list', 'vault.query', 'vault.get', 'vault.register', 'vault.mutation.plan', 'vault.mutation.execute', 'vault.snapshot.list', 'vault.restore.plan', 'vault.restore.execute', 'settings.get', 'settings.update', 'diagnostics.export-plan', 'diagnostics.export-execute', 'quarantine.resource-list', 'quarantine.plan', 'quarantine.execute']
const capabilities = { readable: true, queryable: true, editable: true, snapshot: true, restore: true, reason: null }
const source = { source_id: 'local-json', format: 'json', capabilities, revision }
const record = { record_id: 'record-1', namespace: 'default', content: 'Original local text', metadata: {}, embedding_present: false, source_revision: revision, editable_fields: [{ field: 'content', kind: 'update_content', value_type: 'string', value: 'Original local text' }] }
const plan = { plan_id: 'local-plan', digest, expires_at: new Date(Date.now() + 30_000).toISOString(), consequences: ['A verified snapshot is created before the source is changed.'], warnings: [], local_only_warning: 'Local only.' }
const rawAgent = { agent_id: 'local-agent', process_instance_id: revision, provider: null, project: 'Fixture', role: 'Worker', state: 'defunct', evidence_grade: 'confirmed', confidence: 0.95, reason_codes: [], explanation: 'Fixture lease owner exited.', evidence: [], actionable: false, managed: true, pid: 4112, process_name: 'python', os_status: 'missing', usage_cost: { availability: 'unknown', amount_usd: null, note: 'Unknown.' } }
const coverage = { inspected_count: 1, denied_count: 0, vanished_count: 0, malformed_lease_count: 0, lease_file_count: 1, skipped_lease_count: 0, other_user_count: 0, unknown_owner_count: 0, identity_denied_count: 0, complete: true, captured_at: '2026-10-02T12:00:00Z', current_boot_id: 'boot', warnings: [] }
const localReceipt = { receipt_id: 'cleanup-receipt', plan_id: 'local-plan', outcome: 'completed', certainty: 'verified', action_issued: true, partial_failures: [], created_at: '2026-10-02T12:00:00Z' }
function reply(method: string, result: unknown) { return { requestId: '11111111-1111-4111-8111-111111111111', method, result } }

function nativeFixture(overrides: Record<string, (payload: Record<string, unknown>) => unknown> = {}) {
  let registered = false
  let changed = false
  let settingsRevision = 0
  let settings = { scan_interval_seconds: 30, heartbeat_grace_seconds: 120, retention_days: 30, include_unmanaged_candidates: true, appearance: 'system', reduced_motion: false }
  const payloads: Array<{ method: string; payload: Record<string, unknown> }> = []
  const invoke = vi.fn(async (_command: string, arguments_: unknown) => {
    const request = (arguments_ as { request: { method: string; payload: Record<string, unknown> } }).request
    payloads.push(request)
    if (overrides[request.method]) return reply(request.method, await overrides[request.method](request.payload))
    switch (request.method) {
      case 'doctor': return reply(request.method, { healthy: true, checks: methods.map((method) => ({ name: `method:${method}`, ok: true })), warnings: [] })
      case 'scan.list': return reply(request.method, { agents: [rawAgent], coverage, returned: 1, total: 1 })
      case 'agent.detail': return reply(request.method, rawAgent)
      case 'activity.list': return reply(request.method, { receipts: [], next_cursor: null })
      case 'quarantine.list': return reply(request.method, { entries: [{ entry_id: 'entry-1', agent_id: 'local-agent', resource_type: 'file', state: 'quarantined', restorable: true, created_at: '2026-10-02T12:00:00Z', updated_at: '2026-10-02T12:00:00Z' }], next_cursor: null })
      case 'quarantine.resource-list': return reply(request.method, { agent_id: 'local-agent', resources: [{ resource_index: 0, kind: 'temporary', resource_type: 'file', declaration_digest: digest, cleanup_available: true, reason: 'Verified temporary resource after owner exit.' }, { resource_index: 1, kind: 'temporary', resource_type: 'directory', declaration_digest: null, cleanup_available: false, reason: 'Current owner still running.' }], returned: 2 })
      case 'quarantine.plan': return reply(request.method, plan)
      case 'quarantine.execute': return reply(request.method, localReceipt)
      case 'quarantine.restore-plan': return reply(request.method, plan)
      case 'quarantine.restore-execute': return reply(request.method, { ...localReceipt, receipt_id: 'graveyard-receipt' })
      case 'settings.get': return reply(request.method, { settings, revision: settingsRevision })
      case 'settings.update': {
        if (request.payload.expectedRevision !== settingsRevision) throw { code: 'conflict', message: 'Fixture settings revision changed.' }
        const changes = request.payload.changes as Record<string, unknown>
        settings = { scan_interval_seconds: changes.scanIntervalSeconds as number ?? settings.scan_interval_seconds, heartbeat_grace_seconds: changes.heartbeatGraceSeconds as number ?? settings.heartbeat_grace_seconds, retention_days: changes.retentionDays as number ?? settings.retention_days, include_unmanaged_candidates: changes.includeUnmanagedCandidates as boolean ?? settings.include_unmanaged_candidates, appearance: changes.appearance as string ?? settings.appearance, reduced_motion: changes.reducedMotion as boolean ?? settings.reduced_motion }
        settingsRevision += 1
        return reply(request.method, { settings, revision: settingsRevision })
      }
      case 'vault.register': registered = true; return reply(request.method, { format: 'json', recognized: true, capabilities, reason: null, read_only: true, selected_locally: true, local_only_warning: 'Local only.' })
      case 'vault.list': return reply(request.method, { sources: registered ? [{ ...source, revision: changed ? nextRevision : revision }] : [], next_cursor: null, local_only_warning: 'Local only.' })
      case 'vault.query': return reply(request.method, { records: [{ ...record, content: changed ? 'Repaired local text' : record.content, source_revision: changed ? nextRevision : revision }], total: 1, next_cursor: null, local_only_warning: 'Local only.' })
      case 'vault.mutation.plan': return reply(request.method, { ...plan, source_id: 'local-json', record_id: 'record-1', snapshot_id: null, before_revision: revision, backup_verified: false, diff: [{ field_name: 'content', old_hash: revision, new_hash: nextRevision, old_preview: 'Original local text', new_preview: 'Repaired local text' }] })
      case 'vault.mutation.execute': changed = true; return reply(request.method, { receipt_id: 'repair-receipt', plan_id: 'local-plan', outcome: 'completed', certainty: 'verified', action_issued: true, partial_failures: [], created_at: '2026-10-02T12:00:00Z', local_only_warning: 'Local only.', source_id: 'local-json', record_id: 'record-1', snapshot_id: 'snapshot-1', before_revision: revision, after_revision: nextRevision, operation: 'update_content' })
      case 'vault.snapshot.list': return reply(request.method, { snapshots: changed ? [{ snapshot_id: 'snapshot-1', source_id: 'local-json', source_revision: revision, digest, size: 100, status: 'verified', created_at: '2026-10-02T12:00:00Z' }] : [], local_only_warning: 'Local only.' })
      case 'vault.restore.plan': return reply(request.method, { ...plan, plan_id: 'restore-plan', source_id: 'local-json', record_id: null, snapshot_id: 'snapshot-1', before_revision: nextRevision, backup_verified: true, diff: [] })
      case 'vault.restore.execute': changed = false; return reply(request.method, { receipt_id: 'restore-receipt', plan_id: 'restore-plan', outcome: 'completed', certainty: 'verified', action_issued: true, partial_failures: [], created_at: '2026-10-02T12:01:00Z', local_only_warning: 'Local only.', source_id: 'local-json', snapshot_id: 'snapshot-1', before_revision: nextRevision, after_revision: revision, operation: 'restore' })
      case 'diagnostics.export-plan': return reply(request.method, { ...plan, excluded_by_default: ['command_lines', 'memory_contents', 'paths', 'secrets'] })
      case 'diagnostics.export-execute': return reply(request.method, { receipt_id: 'diagnostics-receipt', plan_id: 'local-plan', outcome: 'completed', certainty: 'verified', action_issued: true, partial_failures: [], created_at: '2026-10-02T12:00:00Z' })
      default: throw new Error(`Unexpected local method ${request.method}`)
    }
  })
  return { transport: new TauriTransport(invoke), payloads }
}

describe('native local workflows', () => {
  it('probes finite local workflow capabilities without assuming unsupported mutations', async () => {
    const fixture = nativeFixture()
    expect(fixture.transport.capabilities.vaultMutation).toBe(false)
    await fixture.transport.getSettings()
    expect(fixture.transport.capabilities.vaultMutation).toBe(true)
    expect(fixture.transport.capabilities.memoryHistory).toBe(true)
    expect(fixture.transport.capabilities.quarantineRestore).toBe(true)
    expect(fixture.transport.capabilities.diagnosticsExport).toBe(true)
  })

  it('registers an explicit local source, repairs a scalar with its digest, and restores its verified snapshot', async () => {
    const fixture = nativeFixture()
    const user = userEvent.setup()
    render(<MemoryPage transport={fixture.transport} />)
    await user.type(await screen.findByRole('textbox', { name: 'Local source path' }), 'C:\\fixture\\memory.json')
    await user.click(screen.getByRole('button', { name: 'Register local source' }))
    await screen.findByText('Original local text')
    expect(fixture.payloads.find((item) => item.method === 'vault.register')?.payload).toEqual({ path: 'C:\\fixture\\memory.json' })

    await user.click(screen.getByRole('button', { name: 'Edit draft' }))
    const draft = await screen.findByRole('textbox', { name: 'Scalar value' })
    await user.clear(draft)
    await user.type(draft, 'Repaired local text')
    await user.click(screen.getByRole('button', { name: 'Review local repair' }))
    const apply = await screen.findByRole('button', { name: 'Apply local repair' })
    expect(screen.getByText('Repaired local text')).not.toBeNull()
    expect(fixture.payloads.find((item) => item.method === 'vault.mutation.plan')?.payload).toMatchObject({ sourceId: 'local-json', recordId: 'record-1', expectedRevision: revision, operation: 'update_content', value: 'Repaired local text' })
    await user.click(apply)
    await screen.findByText('repair-receipt')
    await user.click(screen.getByRole('button', { name: 'Close review' }))
    await user.click(screen.getByRole('tab', { name: 'History' }))
    await user.click(await screen.findByRole('button', { name: 'Review snapshot restore' }))
    await user.click(await screen.findByRole('button', { name: 'Restore verified snapshot' }))
    await screen.findByText('restore-receipt')
    expect(fixture.payloads.find((item) => item.method === 'vault.restore.plan')?.payload).toEqual({ sourceId: 'local-json', snapshotId: 'snapshot-1', snapshotDigest: digest, expectedRevision: nextRevision })
  })

  it('requires a destination and explicit review before writing local diagnostics', async () => {
    const fixture = nativeFixture()
    const user = userEvent.setup()
    render(<SettingsPage transport={fixture.transport} />)
    const input = await screen.findByRole('textbox', { name: 'Diagnostics destination' })
    await user.type(input, 'C:\\fixture\\diagnostics.json')
    await user.click(screen.getByRole('button', { name: 'Review diagnostics export' }))
    expect(fixture.payloads.some((item) => item.method === 'diagnostics.export-execute')).toBe(false)
    await user.click(await screen.findByRole('button', { name: 'Export local diagnostics' }))
    await waitFor(() => expect(screen.getByText('diagnostics-receipt')).not.toBeNull())
    expect(fixture.payloads.find((item) => item.method === 'diagnostics.export-plan')?.payload).toMatchObject({ destination: 'C:\\fixture\\diagnostics.json' })
  })

  it('reviews only engine-listed declared resources and records verified cleanup without renderer paths', async () => {
    const fixture = nativeFixture()
    const [agent] = (await fixture.transport.scan()).agents
    const user = userEvent.setup()
    render(<AgentDetails agent={agent} transport={fixture.transport} onClose={() => undefined} onReview={() => undefined} />)
    await screen.findAllByText('Fixture lease owner exited.')
    await user.click(screen.getByRole('tab', { name: 'Artifacts' }))
    await screen.findByText('Current owner still running.')
    const buttons = screen.getAllByRole('button', { name: 'Review resource cleanup' })
    expect(buttons[1].hasAttribute('disabled')).toBe(true)
    await user.click(buttons[0])
    expect(fixture.payloads.find((item) => item.method === 'quarantine.resource-list')?.payload).toEqual({ agentId: 'local-agent', expectedPid: 4112, expectedProcessInstanceId: revision })
    expect(fixture.payloads.find((item) => item.method === 'quarantine.plan')?.payload).toEqual({ agentId: 'local-agent', resourceIndex: 0, expectedDeclarationDigest: digest, expectedPid: 4112, expectedProcessInstanceId: revision })
    expect(fixture.payloads.some((item) => item.method === 'quarantine.execute')).toBe(false)
    await user.click(await screen.findByRole('button', { name: 'Quarantine declared resource' }))
    await screen.findByText('cleanup-receipt')
  })

  it('restores a native Graveyard entry only after its exact reviewed plan', async () => {
    const fixture = nativeFixture()
    const user = userEvent.setup()
    render(<ActivityPage transport={fixture.transport} />)
    await user.click(await screen.findByRole('tab', { name: 'Quarantine' }))
    await user.click(await screen.findByRole('button', { name: 'Review restore' }))
    expect(fixture.payloads.some((item) => item.method === 'quarantine.restore-execute')).toBe(false)
    await user.click(await screen.findByRole('button', { name: 'Restore exact entry' }))
    await screen.findByText('graveyard-receipt')
    await waitFor(() => expect(fixture.payloads.some((item) => item.method === 'quarantine.restore-execute')).toBe(true))
    expect(fixture.payloads.find((item) => item.method === 'quarantine.restore-plan')?.payload).toEqual({ entryId: 'entry-1' })
  })

  it.each(['restored', 'already_restored'])('accepts the native %s outcome through the required Graveyard transport method', async (outcome) => {
    const fixture = nativeFixture({ 'quarantine.restore-execute': () => ({ ...localReceipt, receipt_id: 'legacy-restore-receipt', outcome, action_issued: outcome === 'restored' }) })
    const reviewed = await fixture.transport.planGraveyardRestore('entry-1')
    const receipt = await fixture.transport.executeGraveyardRestore({ planId: reviewed.planId, digest: reviewed.digest })
    expect(receipt).toMatchObject({ receiptId: 'legacy-restore-receipt', entryId: 'entry-1', result: 'Restored' })
    expect(fixture.payloads.filter((item) => item.method === 'quarantine.restore-execute')).toHaveLength(1)
  })

  it('keeps unconfirmed mutation methods unavailable and never invokes a missing execute method', async () => {
    const fixture = nativeFixture({ doctor: () => ({ healthy: true, checks: methods.map((method) => ({ name: `method:${method}`, ok: method !== 'vault.mutation.execute' })), warnings: [] }) })
    await fixture.transport.getSettings()
    expect(fixture.transport.capabilities.vaultMutation).toBe(false)
    await expect(fixture.transport.planNativeMemoryChange({ sourceId: 'local-json', recordId: 'record-1', expectedRevision: revision, field: { field: 'content', kind: 'update_content', valueType: 'string', value: 'old' }, value: 'new' })).rejects.toMatchObject({ code: 'unsupported' })
    expect(fixture.payloads.some((item) => item.method === 'vault.mutation.plan')).toBe(false)
  })

  it('does not write settings unless the engine confirms settings.update', async () => {
    const fixture = nativeFixture({ doctor: () => ({ healthy: true, checks: methods.map((method) => ({ name: `method:${method}`, ok: method !== 'settings.update' })), warnings: [] }) })
    await fixture.transport.getSettings()
    await expect(fixture.transport.updateSettings({ expectedRevision: 0, changes: { theme: 'dark' } })).rejects.toMatchObject({ code: 'unsupported' })
    expect(fixture.payloads.some((item) => item.method === 'settings.update')).toBe(false)
    render(<SettingsPage transport={fixture.transport} />)
    expect((await screen.findByLabelText('Theme')).hasAttribute('disabled')).toBe(true)
  })

  it('rejects a changed digest before issuing a reviewed native operation', async () => {
    const fixture = nativeFixture()
    const reviewed = await fixture.transport.planDiagnosticsExport('C:\\fixture\\diagnostics.json')
    await expect(fixture.transport.executeDiagnosticsExport({ planId: reviewed.planId, digest: revision })).rejects.toMatchObject({ code: 'plan_changed' })
    expect(fixture.payloads.some((item) => item.method === 'diagnostics.export-execute')).toBe(false)
  })

  it('issues a pending native plan only once even if a caller submits it twice', async () => {
    let release!: (value: unknown) => void
    const execution = new Promise((resolve) => { release = resolve })
    const fixture = nativeFixture({ 'diagnostics.export-execute': () => execution })
    const reviewed = await fixture.transport.planDiagnosticsExport('C:\\fixture\\diagnostics.json')
    const first = fixture.transport.executeDiagnosticsExport({ planId: reviewed.planId, digest: reviewed.digest })
    const second = fixture.transport.executeDiagnosticsExport({ planId: reviewed.planId, digest: reviewed.digest })
    const secondCheck = expect(second).rejects.toMatchObject({ code: 'plan_replayed' })
    release(localReceipt)
    await first
    await secondCheck
    expect(fixture.payloads.filter((item) => item.method === 'diagnostics.export-execute')).toHaveLength(1)
  })

  it('renders durable nonprocess receipts with their reported workflow kind and certainty', async () => {
    const fixture = nativeFixture({ 'activity.list': () => ({ receipts: [{ ...localReceipt, kind: 'memory' }, { ...localReceipt, receipt_id: 'export-partial', kind: 'diagnostics', certainty: 'uncertain', action_issued: null, partial_failures: ['Export completion could not be verified.'] }], next_cursor: null }) })
    const user = userEvent.setup()
    render(<ActivityPage transport={fixture.transport} />)
    await user.click(await screen.findByRole('tab', { name: 'Receipts' }))
    await screen.findByText('Memory operation')
    await screen.findByText('Diagnostics export')
    expect(screen.getByText('Export completion could not be verified.')).not.toBeNull()
    expect(screen.queryByText('Containment complete')).toBeNull()
  })

  it('does not retry uncertain native repair and keeps review open until local state refresh succeeds', async () => {
    let reads = 0
    let refreshAvailable = false
    const fixture = nativeFixture({
      'vault.list': () => { reads += 1; if (reads > 1 && !refreshAvailable) throw { code: 'engine_unavailable', message: 'Local state could not be refreshed.' }; return { sources: [source], next_cursor: null, local_only_warning: 'Local only.' } },
      'vault.mutation.execute': () => { throw { code: 'outcome_uncertain', message: 'Repair may have completed.', reconcileRequired: true } },
    })
    const user = userEvent.setup()
    render(<MemoryPage transport={fixture.transport} />)
    await screen.findByText('Original local text')
    await user.click(screen.getByRole('button', { name: 'Edit draft' }))
    await user.click(await screen.findByRole('button', { name: 'Review local repair' }))
    await user.click(await screen.findByRole('button', { name: 'Apply local repair' }))
    await screen.findByText('Repair may have completed.')
    expect(screen.queryByRole('button', { name: 'Apply local repair' })).toBeNull()
    await user.click(screen.getByRole('button', { name: 'Close review' }))
    await screen.findAllByText('Local state could not be refreshed.')
    expect(screen.getByRole('dialog')).not.toBeNull()
    expect(fixture.payloads.filter((item) => item.method === 'vault.mutation.execute')).toHaveLength(1)
    refreshAvailable = true
    await user.click(screen.getByRole('button', { name: 'Refresh local state' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  })

  it('accepts honest failed-before-issue memory receipts with nullable recovery metadata', async () => {
    const fixture = nativeFixture({ 'vault.mutation.execute': () => ({ ...localReceipt, certainty: 'failed_before_issue', action_issued: false, outcome: 'failed', source_id: null, record_id: null, snapshot_id: null, before_revision: null, after_revision: null, operation: null, local_only_warning: 'Local only.' }) })
    const reviewed = await fixture.transport.planNativeMemoryChange({ sourceId: 'local-json', recordId: 'record-1', expectedRevision: revision, field: { field: 'content', kind: 'update_content', valueType: 'string', value: 'old' }, value: 'new' })
    const receipt = await fixture.transport.executeNativeMemoryChange({ planId: reviewed.planId, digest: reviewed.digest })
    expect(receipt).toMatchObject({ certainty: 'failed_before_issue', actionIssued: false })
    expect(receipt.afterRevision).toBeUndefined()
  })

  it('rejects a memory plan for a different record before making execution available', async () => {
    const fixture = nativeFixture({ 'vault.mutation.plan': () => ({ ...plan, source_id: 'local-json', record_id: 'wrong-record', before_revision: revision, snapshot_id: null, backup_verified: false, diff: [] }) })
    await expect(fixture.transport.planNativeMemoryChange({ sourceId: 'local-json', recordId: 'record-1', expectedRevision: revision, field: { field: 'content', kind: 'update_content', valueType: 'string', value: 'old' }, value: 'new' })).rejects.toMatchObject({ code: 'protocol_violation' })
    expect(fixture.payloads.some((item) => item.method === 'vault.mutation.execute')).toBe(false)
  })

  it('persists native detection and cadence controls against successive durable settings revisions', async () => {
    const fixture = nativeFixture()
    const user = userEvent.setup()
    render(<SettingsPage transport={fixture.transport} />)
    await user.click(await screen.findByRole('checkbox', { name: 'Include unmanaged detections' }))
    await screen.findByText('All local settings saved.')
    await user.selectOptions(screen.getByLabelText('Heartbeat grace (seconds)'), '60')
    await waitFor(() => expect(fixture.payloads.filter((item) => item.method === 'settings.update')).toHaveLength(2))
    await user.selectOptions(screen.getByLabelText('Stored engine scan interval'), '15')
    await waitFor(() => expect(fixture.payloads.filter((item) => item.method === 'settings.update')).toHaveLength(3))
    expect(fixture.payloads.filter((item) => item.method === 'settings.update').map((item) => item.payload)).toEqual([{ expectedRevision: 0, changes: { includeUnmanagedCandidates: false } }, { expectedRevision: 1, changes: { heartbeatGraceSeconds: 60 } }, { expectedRevision: 2, changes: { scanIntervalSeconds: 15 } }])
  })

  it('applies the persisted unmanaged setting to the mounted native Swarm scan', async () => {
    const fixture = nativeFixture()
    const user = userEvent.setup()
    render(<App transport={fixture.transport} />)
    await user.click(await screen.findByRole('link', { name: 'Settings' }))
    await user.click(await screen.findByRole('checkbox', { name: 'Include unmanaged detections' }))
    await screen.findByText('All local settings saved.')
    await user.click(screen.getByRole('link', { name: 'Swarm' }))
    await waitFor(() => expect(fixture.payloads.filter((item) => item.method === 'scan.list').at(-1)?.payload.includeUnmanaged).toBe(false))
  })

  it('binds opaque declared-resource IDs to the listed declaration rather than a reusable index', async () => {
    const fixture = nativeFixture()
    const expected = { id: 'local-agent', revision: coverage.captured_at, pid: 4112, processInstanceId: revision }
    const resources = await fixture.transport.getDeclaredResources('local-agent', expected)
    expect(resources[0].id).toBe(`0:${digest}`)
    await fixture.transport.planResourceCleanup('local-agent', resources[0].id, expected)
    expect(fixture.payloads.find((item) => item.method === 'quarantine.plan')?.payload).toEqual({ agentId: 'local-agent', resourceIndex: 0, expectedDeclarationDigest: digest, expectedPid: 4112, expectedProcessInstanceId: revision })
    expect(JSON.stringify(fixture.payloads.filter((item) => item.method.startsWith('quarantine.')))).not.toMatch(/"path"/)
    await expect(fixture.transport.planResourceCleanup('local-agent', resources[1].id, expected)).rejects.toMatchObject({ code: 'unsupported' })
  })

  it('sends the selected process binding so a new lease owner cannot replace the resource list target', async () => {
    const fixture = nativeFixture({ 'quarantine.resource-list': (payload) => {
      if (payload.expectedPid === 4112 && payload.expectedProcessInstanceId === revision) throw { code: 'target_changed', message: 'The lease owner changed.' }
      return { agent_id: 'local-agent', resources: [], returned: 0 }
    } })
    await expect(fixture.transport.getDeclaredResources('local-agent', { id: 'local-agent', revision: coverage.captured_at, pid: 4112, processInstanceId: revision })).rejects.toMatchObject({ code: 'target_changed' })
  })

  it('keeps the old declaration digest and process binding when the same resource index is replaced before review', async () => {
    let currentDigest = digest
    let currentInstance = revision
    const fixture = nativeFixture({ 'quarantine.plan': (payload) => {
      if (payload.expectedDeclarationDigest !== currentDigest || payload.expectedProcessInstanceId !== currentInstance) throw { code: 'target_changed', message: 'The declared resource or owner changed.' }
      return plan
    } })
    const expected = { id: 'local-agent', revision: coverage.captured_at, pid: 4112, processInstanceId: revision }
    const [listed] = await fixture.transport.getDeclaredResources('local-agent', expected)
    currentDigest = nextRevision
    await expect(fixture.transport.planResourceCleanup('local-agent', listed.id, expected)).rejects.toMatchObject({ code: 'target_changed' })
    currentDigest = digest; currentInstance = nextRevision
    await expect(fixture.transport.planResourceCleanup('local-agent', listed.id, expected)).rejects.toMatchObject({ code: 'target_changed' })
    expect(fixture.payloads.filter((item) => item.method === 'quarantine.plan').map((item) => item.payload)).toEqual([0, 1].map(() => ({ agentId: 'local-agent', resourceIndex: 0, expectedDeclarationDigest: digest, expectedPid: 4112, expectedProcessInstanceId: revision })))
    expect(fixture.payloads.some((item) => item.method === 'quarantine.execute')).toBe(false)
  })

  it.each(['0', '00:' + digest, '64:' + digest, '1:' + digest.toUpperCase(), '1:' + digest + ':extra'])('rejects a malformed opaque cleanup ID %s before planning', async (resourceId) => {
    const fixture = nativeFixture()
    await expect(fixture.transport.planResourceCleanup('local-agent', resourceId, { id: 'local-agent', revision: coverage.captured_at, pid: 4112, processInstanceId: revision })).rejects.toMatchObject({ code: 'unsupported' })
    expect(fixture.payloads.some((item) => item.method === 'quarantine.plan')).toBe(false)
  })

  it.each([
    { outcome: 'quarantined', certainty: 'verified', actionIssued: true, title: 'Local operation completed', issuance: 'Yes' },
    { outcome: 'already_restored', certainty: 'verified', actionIssued: false, title: 'Local operation completed', issuance: 'No' },
    { outcome: 'restored', certainty: 'uncertain', actionIssued: null, title: 'Outcome uncertain', issuance: 'Unknown' },
    { outcome: 'arbitrary_unrecognized_success', certainty: 'verified', actionIssued: true, title: 'Local operation needs review', issuance: 'Yes' },
  ] as const)('reports $outcome / $certainty separately from action issuance', async ({ outcome, certainty, actionIssued, title, issuance }) => {
    const user = userEvent.setup()
    render(<LocalWorkflowReview title="Review fixture operation" confirmLabel="Apply reviewed operation" plan={{ planId: 'local-plan', digest, expiresAt: plan.expires_at, consequences: [], warnings: [] }} execute={async () => ({ receiptId: 'review-receipt', planId: 'local-plan', outcome, certainty, actionIssued, partialFailures: [], createdAt: localReceipt.created_at })} onClose={() => undefined} />)
    await user.click(screen.getByRole('button', { name: 'Apply reviewed operation' }))
    await screen.findByRole('heading', { name: title })
    expect(screen.getByText(issuance, { selector: 'dd' })).not.toBeNull()
  })

  it('discards an unexecuted snapshot review when the source or revision changes and does not revive it on return', async () => {
    const snapshot = { snapshot_id: 'snapshot-1', source_id: 'local-json', source_revision: revision, digest, size: 100, status: 'verified', created_at: localReceipt.created_at }
    const fixture = nativeFixture({
      'vault.snapshot.list': (payload) => ({ snapshots: [{ ...snapshot, source_id: payload.sourceId }], local_only_warning: 'Local only.' }),
      'vault.restore.plan': (payload) => ({ ...plan, source_id: payload.sourceId, record_id: null, snapshot_id: 'snapshot-1', before_revision: payload.expectedRevision, backup_verified: true, diff: [] }),
    })
    const user = userEvent.setup()
    const view = render(<NativeSnapshotHistory sourceId="local-json" revision={revision} transport={fixture.transport} onChanged={async () => undefined} />)
    await user.click(await screen.findByRole('button', { name: 'Review snapshot restore' }))
    await screen.findByRole('dialog', { name: 'Review source snapshot restore' })
    view.rerender(<NativeSnapshotHistory sourceId="other-source" revision={nextRevision} transport={fixture.transport} onChanged={async () => undefined} />)
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    view.rerender(<NativeSnapshotHistory sourceId="local-json" revision={revision} transport={fixture.transport} onChanged={async () => undefined} />)
    await screen.findByRole('button', { name: 'Review snapshot restore' })
    expect(screen.queryByRole('dialog')).toBeNull()
    await user.click(screen.getByRole('button', { name: 'Review snapshot restore' }))
    await screen.findByRole('dialog')
    view.rerender(<NativeSnapshotHistory sourceId="local-json" revision={nextRevision} transport={fixture.transport} onChanged={async () => undefined} />)
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(fixture.payloads.some((item) => item.method === 'vault.restore.execute')).toBe(false)
  })

  it('preserves the final snapshot receipt while the post-execution refresh changes the source revision', async () => {
    const snapshot = { snapshot_id: 'snapshot-1', source_id: 'local-json', source_revision: revision, digest, size: 100, status: 'verified', created_at: localReceipt.created_at }
    const fixture = nativeFixture({ 'vault.snapshot.list': () => ({ snapshots: [snapshot], local_only_warning: 'Local only.' }) })
    const user = userEvent.setup()
    const refresh = async () => view.rerender(<NativeSnapshotHistory sourceId="local-json" revision={revision} transport={fixture.transport} onChanged={refresh} />)
    const view = render(<NativeSnapshotHistory sourceId="local-json" revision={nextRevision} transport={fixture.transport} onChanged={refresh} />)
    await user.click(await screen.findByRole('button', { name: 'Review snapshot restore' }))
    await user.click(await screen.findByRole('button', { name: 'Restore verified snapshot' }))
    await screen.findByText('restore-receipt')
    await waitFor(() => expect(screen.getByRole('dialog', { name: 'Local operation receipt' })).not.toBeNull())
  })
})
