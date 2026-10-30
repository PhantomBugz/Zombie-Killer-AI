import axe from 'axe-core'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { groupForState } from '../features/swarm/grouping'
import { ContainmentDialog } from '../features/swarm/ContainmentDialog'
import { SwarmPage } from '../features/swarm/SwarmPage'
import { DemoTransport } from '../transport/demo'
import { TauriTransport } from '../transport/tauri'
import { TransportError } from '../transport/types'
import type { ActionPlan, EngineTransport, PlanRequest, ScanResult } from '../transport/types'

const NOW = new Date('2026-08-12T16:00:00.000Z')
const DEMO_PROCESS_INSTANCE_ID = '1'.repeat(64)

function demoActionRequest(kind: PlanRequest['kind']): PlanRequest {
  return { agentId: 'mev-screenshot', kind, target: { pid: 4188, processInstanceId: DEMO_PROCESS_INSTANCE_ID } }
}

function makeTransport() {
  let sequence = 0
  return new DemoTransport({
    latencyMs: 0,
    now: () => NOW,
    id: (prefix) => `${prefix}-${++sequence}`,
  })
}

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason?: unknown) => void
  const promise = new Promise<T>((resolvePromise, rejectPromise) => { resolve = resolvePromise; reject = rejectPromise })
  return { promise, reject, resolve }
}

describe('DemoTransport', () => {
  it('rebases fixture observations to its clock and never captures future evidence', async () => {
    let current = new Date('2030-03-04T12:00:00.000Z')
    const transport = new DemoTransport({ latencyMs: 0, now: () => current, id: (prefix) => prefix })
    const first = await transport.scan()
    const firstHeartbeat = first.agents.find((agent) => agent.id === 'mev-screenshot')?.heartbeatAt
    expect(first.capturedAt).toBe(current.toISOString())
    expect(Date.parse(first.capturedAt) - Date.parse(firstHeartbeat ?? '')).toBe(198_000)

    current = new Date('2030-03-04T12:00:10.000Z')
    const second = await transport.scan()
    expect(second.capturedAt).toBe(current.toISOString())
    expect(second.agents.find((agent) => agent.id === 'mev-screenshot')?.heartbeatAt).toBe(firstHeartbeat)

    const plan = await transport.planAction(demoActionRequest('graceful-stop'))
    current = new Date('2030-03-04T12:00:11.000Z')
    const receipt = await transport.executeAction({ planId: plan.planId, digest: plan.digest })
    current = new Date('2030-03-04T12:00:12.000Z')
    const after = await transport.scan()
    const observed = [
      ...after.agents.flatMap((agent) => [agent.processStartedAt, agent.heartbeatAt, ...agent.evidence.map((signal) => signal.observedAt)]),
      ...after.resources.map((point) => point.observedAt),
      ...after.timeline.map((event) => event.at),
      ...after.receipts.map((item) => item.completedAt),
    ].filter((value): value is string => value !== null)
    expect(receipt.completedAt).toBe('2030-03-04T12:00:11.000Z')
    expect(observed.every((value) => Date.parse(value) <= Date.parse(after.capturedAt))).toBe(true)
  })

  it('uses one live default clock for fixture, scan, and expiring action timestamps', async () => {
    vi.useFakeTimers()
    try {
      vi.setSystemTime('2026-08-12T18:00:00.000Z')
      const transport = new DemoTransport({ latencyMs: 0, id: (prefix) => prefix })
      const plan = await transport.planAction(demoActionRequest('graceful-stop'))
      const scan = await transport.scan()
      expect(scan.capturedAt).toBe('2026-08-12T18:00:00.000Z')
      expect(scan.agents.find((agent) => agent.id === 'mev-screenshot')?.heartbeatAt).toBe('2026-08-12T17:56:42.000Z')
      expect(plan.createdAt).toBe('2026-08-12T18:00:00.000Z')
      vi.setSystemTime('2026-08-12T18:00:30.000Z')
      await expect(transport.executeAction({ planId: plan.planId, digest: plan.digest })).rejects.toMatchObject({ code: 'plan_expired' })
    } finally { vi.useRealTimers() }
  })

  it('returns independent clones of the exact synthetic stories', async () => {
    const transport = makeTransport()
    const first = await transport.scan()
    const second = await transport.scan()

    expect(first.mode).toBe('demo')
    expect(first.coverage).toMatchObject({ completeness: 'partial', blindSpotCount: 2 })
    expect(first.agents.find((agent) => agent.role === 'ScreenShot Coordinator')).toMatchObject({
      project: 'Mev BOT',
      provider: 'OpenAI',
      state: 'orphaned',
      actionable: true,
    })
    expect(first.agents.find((agent) => agent.role === 'Search Bot')).toMatchObject({
      project: 'MTGA Cardbot',
      provider: 'Google Gemini',
      state: 'healthy',
    })
    expect(first.usage.costUsd).toBeNull()
    first.agents[0].role = 'changed locally'
    expect(second.agents[0].role).not.toBe('changed locally')
  })

  it('binds an expiring one-shot action plan to identity and digest', async () => {
    const transport = makeTransport()
    const plan = await transport.planAction(demoActionRequest('graceful-stop'))
    expect(plan.target).toEqual({ pid: 4188, processInstanceId: DEMO_PROCESS_INSTANCE_ID, state: 'orphaned' })
    expect(plan.memoryEffect).toBe('unchanged')

    await expect(transport.executeAction({ planId: plan.planId, digest: 'changed' })).rejects.toMatchObject({ code: 'plan_changed' })

    const receipt = await transport.executeAction({ planId: plan.planId, digest: plan.digest })
    expect(receipt.title).toBe('Containment complete')
    expect(receipt.memoryEffect).toBe('unchanged')
    await expect(
      transport.executeAction({ planId: plan.planId, digest: plan.digest }),
    ).rejects.toMatchObject({ code: 'plan_replayed' })
  })

  it('rejects expired plans with a typed transport error', async () => {
    let current = NOW
    const transport = new DemoTransport({ latencyMs: 0, now: () => current, id: (p) => p })
    const plan = await transport.planAction(demoActionRequest('force-stop'))
    current = new Date(NOW.getTime() + 30_000)
    await expect(
      transport.executeAction({ planId: plan.planId, digest: plan.digest }),
    ).rejects.toEqual(expect.objectContaining<Partial<TransportError>>({ code: 'plan_expired' }))
  })

  it('rejects unknown request keys, types, and action kinds at runtime', async () => {
    const transport = makeTransport()
    await expect(transport.planAction({ agentId: 'mev-screenshot', kind: 'bogus' } as never)).rejects.toMatchObject({ code: 'invalid_request' })
    await expect(transport.planAction({ agentId: 'mev-screenshot', kind: 'graceful-stop', extra: true } as never)).rejects.toMatchObject({ code: 'invalid_request' })
    await expect(transport.executeAction({ planId: 42, digest: 'x' } as never)).rejects.toMatchObject({ code: 'invalid_request' })
  })

  it('binds sibling plans to the same state revision and invalidates them after mutation', async () => {
    const transport = makeTransport()
    const first = await transport.planAction(demoActionRequest('graceful-stop'))
    const sibling = await transport.planAction(demoActionRequest('force-stop'))
    const before = await transport.scan()
    await transport.executeAction({ planId: first.planId, digest: first.digest })
    const after = await transport.scan()

    expect(after.revision).not.toBe(before.revision)
    expect(Number(after.agents.find((agent) => agent.id === 'mev-screenshot')?.revision)).toBeGreaterThan(
      Number(before.agents.find((agent) => agent.id === 'mev-screenshot')?.revision ?? 0),
    )
    await expect(transport.executeAction({ planId: sibling.planId, digest: sibling.digest })).rejects.toMatchObject({ code: 'target_changed' })
  })

  it('makes process, port, evidence, and resources consistent with the receipt', async () => {
    const transport = makeTransport()
    const plan = await transport.planAction(demoActionRequest('force-stop'))
    expect(plan.irreversibleConsequences.join(' ')).toMatch(/quarantine/i)
    expect(plan.irreversibleConsequences.join(' ')).toMatch(/memory unchanged/i)
    expect(plan.irreversibleConsequences.join(' ')).toMatch(/status.*actionability.*diagnosis.*network.*resource.*evidence.*activity/i)
    await transport.executeAction({ planId: plan.planId, digest: plan.digest })
    const detail = await transport.getAgentDetail('mev-screenshot')
    expect(detail.currentTask).toBeNull()
    expect(detail.processTree.every((process) => process.status === 'interrupted')).toBe(true)
    expect(detail.ports).toEqual([expect.objectContaining({ port: 4317, status: 'released' })])
    expect(detail.evidence.some((signal) => /still open/i.test(signal.label))).toBe(false)
    expect(detail.resources.at(-1)).toMatchObject({ ramMb: 0, cpuPercent: 0 })
  })
})

describe('state grouping', () => {
  it('maps every protocol state without allowing agents to disappear', () => {
    expect({
      healthy: groupForState('healthy'), idle: groupForState('idle'), stale: groupForState('stale'),
      orphaned: groupForState('orphaned'), unresponsive: groupForState('unresponsive'),
      unmanaged: groupForState('unmanaged'), interrupted: groupForState('interrupted'),
      defunct: groupForState('defunct'), unknown: groupForState('unknown'),
    }).toEqual({
      healthy: 'active', idle: 'active', stale: 'attention', orphaned: 'attention',
      unresponsive: 'attention', unmanaged: 'unmanaged', interrupted: 'attention',
      defunct: 'attention', unknown: 'unknown',
    })
  })
})

describe('Swarm radar', () => {
  beforeEach(() => vi.useRealTimers())

  it('renders partial coverage, compact counts, grouped stories, evidence, and honest cost', async () => {
    render(<SwarmPage transport={makeTransport()} />)
    expect(screen.getByLabelText('Loading swarm radar')).not.toBeNull()

    expect(await screen.findByText('2 coverage blind spots')).not.toBeNull()
    expect(screen.getByRole('list', { name: 'Swarm summary' })).not.toBeNull()
    expect(screen.getAllByText('Needs attention')).toHaveLength(2)
    expect(screen.getByText('Active and idle')).not.toBeNull()
    expect(screen.getByText('Unmanaged detections')).not.toBeNull()
    expect(screen.getByText('ScreenShot Coordinator')).not.toBeNull()
    expect(screen.getByText('Mev BOT')).not.toBeNull()
    expect(screen.getByText('Search Bot')).not.toBeNull()
    expect(screen.getByText('MTGA Cardbot')).not.toBeNull()
    expect(screen.getByText('Not available')).not.toBeNull()
    expect(document.body.textContent).not.toContain('$0')
    expect(screen.getAllByText(/confidence/i).length).toBeGreaterThan(1)
    expect(screen.getAllByText(/heartbeat/i).length).toBeGreaterThan(1)
  })

  it.each([true, false])('keeps enabled native workflows discoverable when process actions are %s', async (processActions) => {
    const transport = new TauriTransport(async (_command, arguments_) => {
      const { request } = arguments_ as { request: { method: string } }
      if (request.method === 'doctor') return {
        requestId: '11111111-1111-4111-8111-111111111111', method: request.method,
        result: {
          healthy: true,
          checks: [
            ...['action.plan', 'action.execute'].map((method) => ({ name: `method:${method}`, ok: processActions })),
            ...['vault.mutation.plan', 'vault.mutation.execute', 'quarantine.restore-plan', 'quarantine.restore-execute', 'diagnostics.export-plan', 'diagnostics.export-execute'].map((method) => ({ name: `method:${method}`, ok: true })),
          ],
          warnings: [],
        },
      }
      if (request.method === 'scan.list') return {
        requestId: '22222222-2222-4222-8222-222222222222', method: request.method,
        result: {
          agents: [], returned: 0, total: 0,
          coverage: {
            inspected_count: 0, denied_count: 0, vanished_count: 0, malformed_lease_count: 0,
            skipped_lease_count: 0, other_user_count: 0, unknown_owner_count: 0, identity_denied_count: 0,
            complete: true, captured_at: '2026-08-12T21:00:00Z', warnings: [],
          },
        },
      }
      throw new Error(`Unexpected native method: ${request.method}`)
    })
    render(<SwarmPage transport={transport} />)

    await screen.findByText('0 coverage blind spots')
    expect(screen.queryByText(/Memory mutation, quarantine restore, and diagnostics export are unavailable/i)).toBeNull()
    expect(screen.getByText(processActions
      ? /Process scanning and reviewed stop actions use the local engine\./i
      : /Process scanning uses the local engine\. Process actions are unavailable on this host\./i)).not.toBeNull()
  })

  it('keeps the mandatory 45-second reconciliation scan exclusive from timer and manual refreshes', async () => {
    vi.useFakeTimers()
    try {
      class SlowReconciliationTransport extends DemoTransport {
        scanCount = 0
        scanRequests: Array<Parameters<DemoTransport['scan']>[0]> = []
        detailBindings: Array<Parameters<DemoTransport['getAgentDetail']>[1]> = []

        override async scan(request?: Parameters<DemoTransport['scan']>[0]) {
          this.scanCount += 1
          this.scanRequests.push(request)
          if (this.scanCount === 2) await new Promise<void>((resolve) => window.setTimeout(resolve, 45_000))
          return super.scan(request)
        }

        override async getAgentDetail(agentId: string, expected?: Parameters<DemoTransport['getAgentDetail']>[1]) {
          this.detailBindings.push(expected)
          return super.getAgentDetail(agentId, expected)
        }
      }
      const transport = new SlowReconciliationTransport({ latencyMs: 0, now: () => NOW })
      let refresh: (() => Promise<void>) | null = null
      const view = render(<SwarmPage transport={transport} refreshIntervalMs={5_000} includeUnmanagedCandidates registerRefresh={(value) => { refresh = value }} />)
      await act(async () => { await Promise.resolve(); await Promise.resolve(); await Promise.resolve() })
      expect(screen.getByText('ScreenShot Coordinator')).not.toBeNull()
      fireEvent.click(screen.getByRole('button', { name: /inspect ScreenShot Coordinator/i }))
      await act(async () => { await Promise.resolve(); await Promise.resolve(); await Promise.resolve() })
      fireEvent.click(screen.getByRole('button', { name: 'Request graceful stop' }))
      await act(async () => { await Promise.resolve(); await Promise.resolve(); await Promise.resolve() })
      const dialog = screen.getByRole('dialog', { name: /review graceful stop/i })
      fireEvent.click(within(dialog).getByRole('checkbox', { name: /confirm this exact plan/i }))
      fireEvent.click(within(dialog).getByRole('button', { name: 'Execute graceful stop' }))
      await act(async () => { await Promise.resolve(); await Promise.resolve(); await Promise.resolve() })
      expect(transport.scanCount).toBe(2)
      expect(within(dialog).getByText('Reconciling the latest dashboard and inspector state…')).not.toBeNull()

      view.rerender(<SwarmPage transport={transport} refreshIntervalMs={5_000} includeUnmanagedCandidates={false} registerRefresh={(value) => { refresh = value }} />)
      await act(async () => { await Promise.resolve(); await Promise.resolve() })
      expect(transport.scanCount).toBe(2)

      await act(async () => { await refresh?.(); await refresh?.() })
      expect(transport.scanCount).toBe(2)
      await act(async () => { vi.advanceTimersByTime(44_999) })
      expect(transport.scanCount).toBe(2)
      await act(async () => { vi.advanceTimersByTime(1); await Promise.resolve(); await Promise.resolve(); await Promise.resolve() })
      expect(screen.getByText('Interrupted')).not.toBeNull()
      expect(transport.scanCount).toBe(2)
      expect(transport.detailBindings).toHaveLength(2)
      expect(transport.detailBindings.at(-1)).toEqual(expect.objectContaining({
        id: 'mev-screenshot',
        pid: 4188,
        processInstanceId: expect.any(String),
      }))
      fireEvent.click(within(dialog).getByRole('button', { name: 'Return to inspector' }))
      await act(async () => { await Promise.resolve(); await Promise.resolve() })
      expect(transport.scanCount).toBe(3)
      expect(transport.scanRequests.at(-1)).toEqual({ includeUnmanagedCandidates: false })
    } finally { vi.useRealTimers() }
  })

  it('filters without hiding the story metadata', async () => {
    const user = userEvent.setup()
    render(<SwarmPage transport={makeTransport()} />)
    await screen.findByText('ScreenShot Coordinator')
    await user.type(screen.getByRole('searchbox', { name: /search agents/i }), 'gemini')
    expect(screen.queryByText('ScreenShot Coordinator')).toBeNull()
    expect(screen.getByText('Search Bot')).not.toBeNull()
    expect(screen.getByText('Google Gemini')).not.toBeNull()
  })

  it('opens details, supports tab arrows, and restores focus on close', async () => {
    const user = userEvent.setup()
    render(<SwarmPage transport={makeTransport()} />)
    const inspect = await screen.findByRole('button', { name: /inspect ScreenShot Coordinator/i })
    await user.click(inspect)

    expect(screen.getByRole('dialog', { name: /ScreenShot Coordinator/i })).not.toBeNull()
    const overview = screen.getByRole('tab', { name: 'Overview' })
    expect(document.activeElement).toBe(overview)
    await user.keyboard('{ArrowRight}')
    expect(document.activeElement).toBe(screen.getByRole('tab', { name: 'Process' }))
    expect(screen.getAllByText(/python.exe/i)).toHaveLength(2)
    await user.keyboard('{End}')
    expect(document.activeElement).toBe(screen.getByRole('tab', { name: 'Activity' }))
    await user.keyboard('{Escape}')
    expect(document.activeElement).toBe(inspect)
  })

  it('reviews and executes a graceful stop by immutable plan, then shows a durable receipt', async () => {
    const user = userEvent.setup()
    render(<SwarmPage transport={makeTransport()} />)
    await user.click(await screen.findByRole('button', { name: /inspect ScreenShot Coordinator/i }))
    await user.click(screen.getByRole('button', { name: 'Request graceful stop' }))

    const dialog = await screen.findByRole('dialog', { name: /review graceful stop/i })
    expect(within(dialog).getByRole('group', { name: 'Containment method' })).not.toBeNull()
    expect(within(dialog).getByText('PID 4188')).not.toBeNull()
    expect(within(dialog).getByText(DEMO_PROCESS_INSTANCE_ID)).not.toBeNull()
    expect(within(dialog).getAllByText(/Memory unchanged/i).length).toBeGreaterThan(0)
    expect(within(dialog).getByText(/2 eligible quarantine files/i)).not.toBeNull()
    await user.click(within(dialog).getByRole('checkbox', { name: /confirm this exact plan/i }))
    await user.click(within(dialog).getByRole('button', { name: 'Execute graceful stop' }))

    expect(await within(dialog).findByText('Containment complete')).not.toBeNull()
    expect(within(dialog).getByText(/2 processes/i)).not.toBeNull()
    expect(within(dialog).getByText(/1 port/i)).not.toBeNull()
    expect(within(dialog).getByText(/2 files/i)).not.toBeNull()
    expect(within(dialog).getByText(/Memory unchanged/i)).not.toBeNull()
    expect(within(dialog).getByText(/audit receipt is available on the Activity page/i)).not.toBeNull()
    expect(within(dialog).getByRole('button', { name: 'Copy receipt summary' })).not.toBeNull()
    expect(within(dialog).getByText(/Restore files is available later in Activity/i)).not.toBeNull()
    const clipboardDescriptor = Object.getOwnPropertyDescriptor(navigator, 'clipboard')
    const execCommandDescriptor = Object.getOwnPropertyDescriptor(document, 'execCommand')
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: undefined })
    Object.defineProperty(document, 'execCommand', { configurable: true, value: vi.fn(() => false) })
    try {
      await user.click(within(dialog).getByRole('button', { name: 'Copy receipt summary' }))
      expect(within(dialog).getByRole('status').textContent).toMatch(/Copy unavailable/i)
    } finally {
      if (clipboardDescriptor) Object.defineProperty(navigator, 'clipboard', clipboardDescriptor)
      else Reflect.deleteProperty(navigator, 'clipboard')
      if (execCommandDescriptor) Object.defineProperty(document, 'execCommand', execCommandDescriptor)
      else Reflect.deleteProperty(document, 'execCommand')
    }
    expect(within(dialog).getByText(/audit receipt is available on the Activity page/i)).not.toBeNull()
  })

  it('requires the exact engine-bound PID and instance token before a force stop can execute', async () => {
    const user = userEvent.setup()
    render(<SwarmPage transport={makeTransport()} />)
    await user.click(await screen.findByRole('button', { name: /inspect ScreenShot Coordinator/i }))
    await user.click(screen.getByRole('button', { name: 'Review containment' }))
    await user.click(await screen.findByRole('button', { name: 'Choose force stop' }))
    expect(screen.getByText('C:\\Demo\\MevBOT\\captures\\frame-014.png')).not.toBeNull()
    expect(screen.getByText('C:\\Demo\\MevBOT\\state\\coordinator.lock')).not.toBeNull()
    expect(screen.getByText(/Demo status, actionability, diagnosis, network observation, resource history, evidence, and activity timeline/i)).not.toBeNull()
    const execute = screen.getByRole('button', { name: 'Execute force stop' })
    expect((execute as HTMLButtonElement).disabled).toBe(true)
    const confirmationToken = '4188:111111111111'
    expect(screen.getByText(DEMO_PROCESS_INSTANCE_ID)).not.toBeNull()
    await user.type(screen.getByLabelText(`Type ${confirmationToken} to confirm`), confirmationToken)
    expect((execute as HTMLButtonElement).disabled).toBe(false)
  })

  it('fails closed when the returned plan target differs from the reviewed process instance', async () => {
    class MismatchedPlanTransport extends DemoTransport {
      override async planAction(request: PlanRequest) {
        const plan = await super.planAction(request)
        return { ...plan, target: { ...plan.target, processInstanceId: 'f'.repeat(64) } }
      }
    }
    const user = userEvent.setup()
    render(<SwarmPage transport={new MismatchedPlanTransport({ latencyMs: 0, now: () => NOW })} />)
    await user.click(await screen.findByRole('button', { name: /inspect ScreenShot Coordinator/i }))
    await user.click(screen.getByRole('button', { name: 'Review containment' }))

    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toMatch(/process instance changed|target.*match/i)
    expect(screen.queryByRole('button', { name: 'Execute graceful stop' })).toBeNull()
    expect(screen.queryByText('f'.repeat(64))).toBeNull()
  })

  it('treats mismatched receipt attribution as uncertain and reconciles instead of showing success', async () => {
    class MismatchedReceiptTransport extends DemoTransport {
      scanCount = 0
      reconciliationDetailCount = 0
      executed = false
      override async scan() { this.scanCount += 1; return super.scan() }
      override async executeAction(request: Parameters<DemoTransport['executeAction']>[0]) {
        const receipt = await super.executeAction(request)
        this.executed = true
        return { ...receipt, planId: 'different-plan', agentId: 'different-agent' }
      }
      override async getAgentDetail(agentId: string) {
        if (this.executed) this.reconciliationDetailCount += 1
        return super.getAgentDetail(agentId)
      }
    }
    const transport = new MismatchedReceiptTransport({ latencyMs: 0, now: () => NOW })
    const user = userEvent.setup()
    const view = render(<SwarmPage transport={transport} />)
    await user.click(await screen.findByRole('button', { name: /inspect ScreenShot Coordinator/i }))
    await user.click(screen.getByRole('button', { name: 'Request graceful stop' }))
    const dialog = await screen.findByRole('dialog', { name: /review graceful stop/i })
    await user.click(within(dialog).getByRole('checkbox', { name: /confirm this exact plan.*engine-bound/i }))
    await user.click(within(dialog).getByRole('button', { name: 'Execute graceful stop' }))

    expect((await within(dialog).findByRole('alert')).textContent).toMatch(/receipt.*did not match|outcome uncertain/i)
    expect(within(dialog).queryByText('Containment complete')).toBeNull()
    await waitFor(() => expect(transport.scanCount).toBeGreaterThanOrEqual(2))
    await within(dialog).findByText('Latest swarm state refreshed. The original action remains locked and cannot be repeated.')
    expect(transport.reconciliationDetailCount).toBe(1)
    expect(screen.getByText('Interrupted')).not.toBeNull()
    expect(screen.queryByText('Orphaned')).toBeNull()
    expect(view.container.querySelector('.changed-banner')).toBeNull()
  })

  it('rejects a native detail mutation even when the transport stamps the scan id and revision', async () => {
    const initialInstance = 'a'.repeat(64)
    const changedInstance = 'b'.repeat(64)
    const rawAgent = (state: string, pid: number, processInstanceId: string) => ({
      agent_id: 'native-worker', process_instance_id: processInstanceId, provider: null, project: 'Local', role: 'Native Worker',
      state, evidence_grade: 'confirmed', confidence: 0.95, explanation: `Native worker is ${state}.`,
      evidence: [{ code: `state_${state}`, grade: 'confirmed', observed_at: '2026-08-12T21:00:00Z', detail: `Observed ${state}.` }],
      actionable: true, managed: true, pid, process_name: 'python',
    })
    const initialAgent = rawAgent('orphaned', 4112, initialInstance)
    const refreshedAgent = rawAgent('interrupted', 4112, initialInstance)
    const mismatchedDetail = rawAgent('healthy', 4999, changedInstance)
    let scanCount = 0
    let executed = false
    let reconciliationDetailCount = 0
    const reply = (method: string, result: Record<string, unknown>) => ({
      requestId: '11111111-1111-4111-8111-111111111111', method, result,
    })
    const scanReply = (agent: typeof initialAgent) => reply('scan.list', {
      agents: [agent],
      coverage: {
        inspected_count: 1, denied_count: 0, vanished_count: 0, malformed_lease_count: 0, skipped_lease_count: 0,
        other_user_count: 0, unknown_owner_count: 0, identity_denied_count: 0, complete: true,
        captured_at: `2026-08-12T21:0${scanCount}:00Z`, warnings: [],
      },
      returned: 1, total: 1,
    })
    const invoke = vi.fn(async (_command: string, arguments_: unknown) => {
      const request = (arguments_ as { request: { method: string } }).request
      if (request.method === 'doctor') return reply(request.method, {
        healthy: true,
        checks: [
          { name: 'method:action.plan', ok: true },
          { name: 'method:action.execute', ok: true },
        ],
        warnings: [],
      })
      if (request.method === 'scan.list') {
        scanCount += 1
        return scanReply(scanCount === 1 ? initialAgent : refreshedAgent)
      }
      if (request.method === 'agent.detail') {
        if (!executed) return reply(request.method, initialAgent)
        reconciliationDetailCount += 1
        return reply(request.method, reconciliationDetailCount === 1 ? mismatchedDetail : refreshedAgent)
      }
      if (request.method === 'action.plan') return reply(request.method, {
        plan_id: 'plan-native', digest: 'd'.repeat(64), expires_at: '2026-08-12T22:00:00Z', consequences: [], warnings: [],
        target: { pid: 4112, process_instance_id: initialInstance, state: 'orphaned' },
      })
      if (request.method === 'action.execute') {
        executed = true
        return reply(request.method, {
          receipt_id: 'receipt-native', plan_id: 'plan-native', outcome: 'completed', certainty: 'verified',
          action_issued: true, partial_failures: ['Cleanup verification failed.'], created_at: '2026-08-12T21:01:00Z',
        })
      }
      throw new Error(`Unexpected native method: ${request.method}`)
    })
    const user = userEvent.setup()
    const view = render(<SwarmPage transport={new TauriTransport(invoke)} />)
    await user.click(await screen.findByRole('button', { name: /inspect Native Worker/i }))
    await user.click(await screen.findByRole('button', { name: 'Request graceful stop' }))
    const dialog = await screen.findByRole('dialog', { name: /review graceful stop/i })
    await user.click(within(dialog).getByRole('checkbox', { name: /confirm this exact plan/i }))
    await user.click(within(dialog).getByRole('button', { name: 'Execute graceful stop' }))

    expect(await within(dialog).findByRole('heading', { name: 'Containment partially completed' })).not.toBeNull()
    expect(within(dialog).getByText('Cleanup verification failed.')).not.toBeNull()
    expect(within(dialog).queryByText('Containment complete')).toBeNull()
    const retry = await within(dialog).findByRole('button', { name: 'Retry reconciliation' })
    expect(within(dialog).getByRole('alert').textContent).toMatch(/agent changed while reconciliation was loading/i)
    expect(reconciliationDetailCount).toBe(1)
    expect(screen.getByText('Orphaned')).not.toBeNull()
    expect(screen.queryByText('Interrupted')).toBeNull()
    expect(view.container.querySelector('.changed-banner')).toBeNull()
    expect((within(dialog).getByRole('button', { name: 'Close Containment receipt' }) as HTMLButtonElement).disabled).toBe(true)

    await user.click(retry)
    const returnButton = within(dialog).getByRole('button', { name: 'Return to swarm' }) as HTMLButtonElement
    await waitFor(() => expect(returnButton.disabled).toBe(false))
    expect(reconciliationDetailCount).toBe(2)
    expect(screen.getByText('Interrupted')).not.toBeNull()
    expect(screen.queryByText('Orphaned')).toBeNull()
    expect(view.container.querySelector('.changed-banner')).toBeNull()
  })

  it('keeps mandatory reconciliation locked when refreshed detail verification fails, then retries without staging', async () => {
    class DetailVerificationTransport extends DemoTransport {
      executed = false
      verificationCount = 0

      override async executeAction(request: Parameters<DemoTransport['executeAction']>[0]) {
        const receipt = await super.executeAction(request)
        this.executed = true
        return { ...receipt, planId: 'different-plan', agentId: 'different-agent' }
      }

      override async getAgentDetail(agentId: string) {
        if (this.executed) {
          this.verificationCount += 1
          if (this.verificationCount === 1) throw new TransportError('partial_failure', 'Fresh agent detail is temporarily unavailable.')
        }
        return super.getAgentDetail(agentId)
      }
    }
    const transport = new DetailVerificationTransport({ latencyMs: 0, now: () => NOW })
    const user = userEvent.setup()
    const view = render(<SwarmPage transport={transport} />)
    await user.click(await screen.findByRole('button', { name: /inspect ScreenShot Coordinator/i }))
    await user.click(screen.getByRole('button', { name: 'Request graceful stop' }))
    const dialog = await screen.findByRole('dialog', { name: /review graceful stop/i })
    await user.click(within(dialog).getByRole('checkbox', { name: /confirm this exact plan/i }))
    await user.click(within(dialog).getByRole('button', { name: 'Execute graceful stop' }))

    const retry = await within(dialog).findByRole('button', { name: 'Retry swarm reconciliation' })
    expect(within(dialog).getByRole('alert').textContent).toMatch(/Fresh agent detail is temporarily unavailable/i)
    expect(transport.verificationCount).toBe(1)
    expect(screen.getByText('Orphaned')).not.toBeNull()
    expect(screen.queryByText('Interrupted')).toBeNull()
    expect(view.container.querySelector('.changed-banner')).toBeNull()
    expect((within(dialog).getByRole('button', { name: 'Close Review graceful stop' }) as HTMLButtonElement).disabled).toBe(true)

    await user.click(retry)
    const reconciled = await within(dialog).findByText('Latest swarm state refreshed. The original action remains locked and cannot be repeated.')
    await waitFor(() => expect(document.activeElement).toBe(reconciled))
    expect(transport.verificationCount).toBe(2)
    expect(screen.getByText('Interrupted')).not.toBeNull()
    expect(screen.queryByText('Orphaned')).toBeNull()
    expect(view.container.querySelector('.changed-banner')).toBeNull()
    expect((within(dialog).getByRole('button', { name: 'Close Review graceful stop' }) as HTMLButtonElement).disabled).toBe(false)
  })

  it('keeps mandatory reconciliation exclusive while generic refresh is suspended', async () => {
    const mandatoryGate = deferred<void>()
    class SupersededMandatoryTransport extends DemoTransport {
      scanCount = 0
      executed = false
      reconciliationDetailCount = 0

      override async scan() {
        this.scanCount += 1
        if (this.scanCount === 2) await mandatoryGate.promise
        return super.scan()
      }

      override async executeAction(request: Parameters<DemoTransport['executeAction']>[0]) {
        const receipt = await super.executeAction(request)
        this.executed = true
        return { ...receipt, planId: 'different-plan', agentId: 'different-agent' }
      }

      override async getAgentDetail(agentId: string) {
        if (this.executed) this.reconciliationDetailCount += 1
        return super.getAgentDetail(agentId)
      }
    }
    const transport = new SupersededMandatoryTransport({ latencyMs: 0, now: () => NOW })
    let refresh: (() => Promise<void>) | null = null
    const user = userEvent.setup()
    const view = render(<SwarmPage transport={transport} registerRefresh={(value) => { refresh = value }} />)
    await user.click(await screen.findByRole('button', { name: /inspect ScreenShot Coordinator/i }))
    await user.click(screen.getByRole('button', { name: 'Request graceful stop' }))
    const dialog = await screen.findByRole('dialog', { name: /review graceful stop/i })
    await user.click(within(dialog).getByRole('checkbox', { name: /confirm this exact plan/i }))
    await user.click(within(dialog).getByRole('button', { name: 'Execute graceful stop' }))
    await within(dialog).findByText('Refreshing the swarm before this dialog can close…')
    expect(transport.scanCount).toBe(2)

    const refreshNow = refresh as (() => Promise<void>) | null
    if (!refreshNow) throw new Error('Refresh callback was not registered')
    await act(async () => { await refreshNow() })
    expect(view.container.querySelector('.changed-banner')).toBeNull()
    await act(async () => mandatoryGate.resolve())

    await within(dialog).findByText('Latest swarm state refreshed. The original action remains locked and cannot be repeated.')
    expect(transport.reconciliationDetailCount).toBe(1)
    expect(screen.getByText('Interrupted')).not.toBeNull()
    expect(view.container.querySelector('.changed-banner')).toBeNull()
  })

  it('keeps detail verification exclusive while generic refresh is suspended', async () => {
    const detailGate = deferred<void>()
    class SupersededDetailTransport extends DemoTransport {
      scanCount = 0
      executed = false
      reconciliationDetailCount = 0

      override async scan() {
        this.scanCount += 1
        return super.scan()
      }

      override async executeAction(request: Parameters<DemoTransport['executeAction']>[0]) {
        const receipt = await super.executeAction(request)
        this.executed = true
        return { ...receipt, planId: 'different-plan', agentId: 'different-agent' }
      }

      override async getAgentDetail(agentId: string) {
        if (this.executed) {
          this.reconciliationDetailCount += 1
          if (this.reconciliationDetailCount === 1) await detailGate.promise
        }
        return super.getAgentDetail(agentId)
      }
    }
    const transport = new SupersededDetailTransport({ latencyMs: 0, now: () => NOW })
    let refresh: (() => Promise<void>) | null = null
    const user = userEvent.setup()
    const view = render(<SwarmPage transport={transport} registerRefresh={(value) => { refresh = value }} />)
    await user.click(await screen.findByRole('button', { name: /inspect ScreenShot Coordinator/i }))
    await user.click(screen.getByRole('button', { name: 'Request graceful stop' }))
    const dialog = await screen.findByRole('dialog', { name: /review graceful stop/i })
    await user.click(within(dialog).getByRole('checkbox', { name: /confirm this exact plan/i }))
    await user.click(within(dialog).getByRole('button', { name: 'Execute graceful stop' }))
    await waitFor(() => expect(transport.reconciliationDetailCount).toBe(1))

    const refreshNow = refresh as (() => Promise<void>) | null
    if (!refreshNow) throw new Error('Refresh callback was not registered')
    await act(async () => { await refreshNow() })
    expect(view.container.querySelector('.changed-banner')).toBeNull()
    await act(async () => detailGate.resolve())

    expect(screen.getByText('Interrupted')).not.toBeNull()
    expect(view.container.querySelector('.changed-banner')).toBeNull()
    await within(dialog).findByText('Latest swarm state refreshed. The original action remains locked and cannot be repeated.')
    expect(transport.reconciliationDetailCount).toBe(1)
    expect(screen.getByText('Interrupted')).not.toBeNull()
    expect(view.container.querySelector('.changed-banner')).toBeNull()
  })

  it('uses one modal at a time and restores the original Inspect focus after Escape', async () => {
    const user = userEvent.setup()
    render(<SwarmPage transport={makeTransport()} />)
    const inspect = await screen.findByRole('button', { name: /inspect ScreenShot Coordinator/i })
    await user.click(inspect)
    await user.click(screen.getByRole('button', { name: 'Review containment' }))

    expect(screen.getAllByRole('dialog')).toHaveLength(1)
    const containment = screen.getByRole('dialog', { name: /review graceful stop/i })
    expect(containment).not.toBeNull()
    expect(document.activeElement).toBe(within(containment).getByRole('heading', { name: /review graceful stop/i }))
    expect(document.querySelector('.swarm-header')?.hasAttribute('inert')).toBe(true)
    await user.keyboard('{Escape}')
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(document.activeElement).toBe(inspect)
  })

  it('ignores an inverted stale plan response and keeps method semantics selected', async () => {
    const graceful = deferred<ActionPlan>()
    class InvertedPlanTransport extends DemoTransport {
      override async planAction(request: PlanRequest) {
        if (request.kind === 'graceful-stop') return graceful.promise
        return super.planAction(request)
      }
    }
    const transport = new InvertedPlanTransport({ latencyMs: 0, now: () => NOW, id: (p) => `${p}-force` })
    const user = userEvent.setup()
    render(<SwarmPage transport={transport} />)
    await user.click(await screen.findByRole('button', { name: /inspect ScreenShot Coordinator/i }))
    await user.click(screen.getByRole('button', { name: 'Review containment' }))
    await user.click(screen.getByRole('button', { name: 'Choose force stop' }))
    expect(await screen.findByRole('button', { name: 'Execute force stop' })).not.toBeNull()
    const stale = await makeTransport().planAction(demoActionRequest('graceful-stop'))
    await act(async () => graceful.resolve(stale))
    expect(screen.getByRole('heading', { name: 'Review force stop' })).not.toBeNull()
    expect(screen.getByRole('button', { name: 'Execute force stop' })).not.toBeNull()
    expect(screen.getByRole('button', { name: 'Choose force stop' }).getAttribute('aria-pressed')).toBe('true')
  })

  it('refreshes dashboard and inspector state after success without stale actions', async () => {
    const user = userEvent.setup()
    render(<SwarmPage transport={makeTransport()} />)
    const inspect = await screen.findByRole('button', { name: /inspect ScreenShot Coordinator/i })
    await user.click(inspect)
    await user.click(screen.getByRole('button', { name: 'Request graceful stop' }))
    const dialog = await screen.findByRole('dialog', { name: /review graceful stop/i })
    await user.click(within(dialog).getByRole('checkbox', { name: /confirm this exact plan/i }))
    await user.click(within(dialog).getByRole('button', { name: 'Execute graceful stop' }))
    await within(dialog).findByText('Containment complete')
    await user.click(within(dialog).getByRole('button', { name: 'Return to inspector' }))

    const inspector = await screen.findByRole('dialog', { name: /ScreenShot Coordinator/i })
    expect(within(inspector).getByText('Interrupted')).not.toBeNull()
    expect(within(inspector).getByText(/Demo containment completed/i)).not.toBeNull()
    expect(screen.queryByRole('button', { name: 'Request graceful stop' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Force stop' })).toBeNull()
    expect(screen.getByText(/Containment unavailable/i)).not.toBeNull()
    await user.keyboard('{Escape}')
    expect(document.activeElement).toBe(inspect)
  })

  it('returns focus to the Swarm heading when reconciliation removes the original Inspect opener', async () => {
    class DisappearingAgentTransport extends DemoTransport {
      removeTarget = false
      reconciliationDetailCount = 0

      override async executeAction(request: Parameters<DemoTransport['executeAction']>[0]) {
        const receipt = await super.executeAction(request)
        this.removeTarget = true
        return receipt
      }

      override async scan() {
        const next = await super.scan()
        return this.removeTarget
          ? { ...next, agents: next.agents.filter((agent) => agent.id !== 'mev-screenshot') }
          : next
      }

      override async getAgentDetail(agentId: string) {
        if (this.removeTarget) this.reconciliationDetailCount += 1
        return super.getAgentDetail(agentId)
      }
    }
    const transport = new DisappearingAgentTransport({ latencyMs: 0, now: () => NOW })
    const user = userEvent.setup()
    render(<SwarmPage transport={transport} />)
    const inspect = await screen.findByRole('button', { name: /inspect ScreenShot Coordinator/i })
    await user.click(inspect)
    await user.click(screen.getByRole('button', { name: 'Request graceful stop' }))
    const dialog = await screen.findByRole('dialog', { name: /review graceful stop/i })
    await user.click(within(dialog).getByRole('checkbox', { name: /confirm this exact plan/i }))
    await user.click(within(dialog).getByRole('button', { name: 'Execute graceful stop' }))

    const returnButton = await within(dialog).findByRole('button', { name: 'Return to inspector' })
    await waitFor(() => expect((returnButton as HTMLButtonElement).disabled).toBe(false))
    expect(inspect.isConnected).toBe(false)
    expect(transport.reconciliationDetailCount).toBe(0)
    await user.click(returnButton)

    const heading = screen.getByRole('heading', { name: 'Swarm', level: 1 })
    expect(heading.tabIndex).toBe(-1)
    expect(document.activeElement).toBe(heading)
    expect(document.activeElement).not.toBe(document.body)
  })

  it('closes a native receipt back to Swarm instead of reopening the target inspector', async () => {
    const demo = makeTransport()
    await demo.scan()
    const agent = await demo.getAgentDetail('mev-screenshot')
    Object.defineProperty(demo, 'mode', { configurable: true, value: 'native' })
    const transport = demo as unknown as EngineTransport
    const onClose = vi.fn()
    const onReturn = vi.fn()
    const user = userEvent.setup()
    render(<ContainmentDialog agent={agent} transport={transport} initialKind="graceful-stop" onClose={onClose} onComplete={async () => undefined} onUncertain={async () => undefined} onReturn={onReturn} restoreFocusRef={{ current: null }} />)

    const dialog = await screen.findByRole('dialog', { name: /review graceful stop/i })
    await user.click(await within(dialog).findByRole('checkbox', { name: /confirm this exact plan/i }))
    await user.click(within(dialog).getByRole('button', { name: 'Execute graceful stop' }))
    const returnButton = await within(dialog).findByRole('button', { name: 'Return to swarm' })
    await waitFor(() => expect((returnButton as HTMLButtonElement).disabled).toBe(false))
    await user.click(returnButton)

    expect(onClose).toHaveBeenCalledOnce()
    expect(onReturn).not.toHaveBeenCalled()
  })

  it.each([
    { label: 'outcome-uncertain error', code: 'outcome_uncertain' as const, details: undefined },
    { label: 'explicit reconcile flag', code: 'internal' as const, details: { reconcileRequired: true } },
  ])('locks re-execution and automatically refreshes the swarm once after an $label', async ({ code, details }) => {
    class AmbiguousActionTransport extends DemoTransport {
      scanCount = 0
      planCount = 0
      executeCount = 0

      override async scan() {
        this.scanCount += 1
        return super.scan()
      }

      override async planAction(request: PlanRequest) {
        this.planCount += 1
        return super.planAction(request)
      }

      override async executeAction(): Promise<never> {
        this.executeCount += 1
        throw new TransportError(code, 'The local engine stopped after issuing the request.', true, details)
      }
    }
    const transport = new AmbiguousActionTransport({ latencyMs: 0, now: () => NOW, id: (prefix) => prefix })
    const user = userEvent.setup()
    render(<SwarmPage transport={transport} />)
    await user.click(await screen.findByRole('button', { name: /inspect ScreenShot Coordinator/i }))
    await user.click(screen.getByRole('button', { name: 'Request graceful stop' }))
    const dialog = await screen.findByRole('dialog', { name: /review graceful stop/i })
    await user.click(within(dialog).getByRole('checkbox', { name: /confirm this exact plan/i }))
    await user.click(within(dialog).getByRole('button', { name: 'Execute graceful stop' }))

    const alert = await within(dialog).findByRole('alert')
    expect(within(alert).getByText('Outcome uncertain')).not.toBeNull()
    expect(alert.textContent).toMatch(/Do not repeat the action/i)
    expect(within(dialog).queryByRole('button', { name: 'Execute graceful stop' })).toBeNull()
    const gracefulChoice = within(dialog).getByRole('button', { name: 'Choose graceful stop' }) as HTMLButtonElement
    const forceChoice = within(dialog).getByRole('button', { name: 'Choose force stop' }) as HTMLButtonElement
    expect(gracefulChoice.disabled).toBe(true)
    expect(forceChoice.disabled).toBe(true)

    await waitFor(() => expect(transport.scanCount).toBe(2))
    expect(within(dialog).queryByRole('button', { name: /Execute (?:graceful|force) stop/ })).toBeNull()
    await user.click(forceChoice)
    expect(transport.executeCount).toBe(1)
    expect(transport.planCount).toBe(1)
    expect(within(dialog).queryByRole('button', { name: /Execute (?:graceful|force) stop/ })).toBeNull()
  })

  it('keeps exact focus and close gating through uncertain reconciliation pending, failure, retry, and success', async () => {
    const failureGate = deferred<void>()
    const retryGate = deferred<void>()
    class FailedUncertainReconciliationTransport extends DemoTransport {
      scanCount = 0
      executeCount = 0

      override async scan() {
        this.scanCount += 1
        if (this.scanCount === 2) {
          await failureGate.promise
          throw new TransportError('partial_failure', 'Fresh swarm state is temporarily unavailable.')
        }
        if (this.scanCount === 3) await retryGate.promise
        return super.scan()
      }

      override async executeAction(): Promise<never> {
        this.executeCount += 1
        throw new TransportError('outcome_uncertain', 'The broker lost the engine receipt.', true, { reconcileRequired: true })
      }
    }
    const transport = new FailedUncertainReconciliationTransport({ latencyMs: 0, now: () => NOW, id: (prefix) => prefix })
    const user = userEvent.setup()
    render(<SwarmPage transport={transport} />)
    await user.click(await screen.findByRole('button', { name: /inspect ScreenShot Coordinator/i }))
    await user.click(screen.getByRole('button', { name: 'Request graceful stop' }))
    const dialog = await screen.findByRole('dialog', { name: /review graceful stop/i })
    await user.click(within(dialog).getByRole('checkbox', { name: /confirm this exact plan/i }))
    await user.click(within(dialog).getByRole('button', { name: 'Execute graceful stop' }))

    const pending = await within(dialog).findByText('Refreshing the swarm before this dialog can close…')
    await waitFor(() => expect(document.activeElement).toBe(pending))
    expect(pending.tabIndex).toBe(-1)
    const close = within(dialog).getByRole('button', { name: 'Close Review graceful stop' }) as HTMLButtonElement
    expect(close.disabled).toBe(true)
    expect(document.activeElement).not.toBe(document.body)
    await user.tab()
    expect(document.activeElement).toBe(pending)
    await user.tab({ shift: true })
    expect(document.activeElement).toBe(pending)

    await act(async () => failureGate.resolve())
    const retry = await within(dialog).findByRole('button', { name: 'Retry swarm reconciliation' })
    expect(within(dialog).getByRole('alert').textContent).toMatch(/Fresh swarm state is temporarily unavailable/i)
    await waitFor(() => expect(document.activeElement).toBe(retry))
    expect(close.disabled).toBe(true)
    await user.keyboard('{Escape}')
    expect(screen.getByRole('dialog', { name: /review graceful stop/i })).toBe(dialog)
    const backdrop = dialog.closest<HTMLElement>('.dialog-layer')
    if (!backdrop) throw new Error('Containment backdrop is missing')
    await user.click(backdrop)
    expect(screen.getByRole('dialog', { name: /review graceful stop/i })).toBe(dialog)
    expect(document.activeElement).toBe(retry)
    expect(document.activeElement).not.toBe(document.body)
    await user.pointer({ target: close, keys: '[MouseLeft]' })
    expect(document.activeElement).toBe(retry)
    expect(document.activeElement).not.toBe(document.body)
    expect(transport.scanCount).toBe(2)
    expect(transport.executeCount).toBe(1)
    expect(within(dialog).queryByRole('button', { name: /Execute (?:graceful|force) stop/ })).toBeNull()

    await user.click(retry)
    await waitFor(() => expect(transport.scanCount).toBe(3))
    const retryPending = within(dialog).getByText('Refreshing the swarm before this dialog can close…')
    await waitFor(() => expect(document.activeElement).toBe(retryPending))
    expect(document.activeElement).not.toBe(document.body)
    expect(close.disabled).toBe(true)
    await act(async () => retryGate.resolve())
    const reconciled = await within(dialog).findByText('Latest swarm state refreshed. The original action remains locked and cannot be repeated.')
    await waitFor(() => expect(document.activeElement).toBe(reconciled))
    expect(reconciled.tabIndex).toBe(-1)
    expect(close.disabled).toBe(false)
    expect(transport.executeCount).toBe(1)
    expect(within(dialog).queryByRole('button', { name: 'Retry swarm reconciliation' })).toBeNull()
  })

  it('uses explicit unavailable copy for native detail fields the engine does not expose', async () => {
    const rawAgent = {
      agent_id: 'native-worker', process_instance_id: null, provider: null, project: null, role: 'Native Worker', state: 'stale',
      evidence_grade: 'partial', confidence: 0.7, explanation: 'Only bounded process evidence is available.',
      evidence: [], actionable: false, managed: true, pid: 4112, process_name: 'python',
    }
    const invoke = vi.fn(async (_command: string, arguments_: unknown) => {
      const request = (arguments_ as { request: { method: string } }).request
      if (request.method === 'scan.list') return {
        requestId: '11111111-1111-4111-8111-111111111111', method: request.method,
        result: {
          agents: [rawAgent],
          coverage: {
            inspected_count: 1, denied_count: 0, vanished_count: 0, malformed_lease_count: 0,
            skipped_lease_count: 0, other_user_count: 0, unknown_owner_count: 0, identity_denied_count: 0,
            complete: true, captured_at: '2026-08-12T21:00:00Z', warnings: [],
          },
          returned: 1, total: 1,
        },
      }
      if (request.method === 'agent.detail') return {
        requestId: '22222222-2222-4222-8222-222222222222', method: request.method, result: rawAgent,
      }
      throw new Error(`Unexpected native method: ${request.method}`)
    })
    const user = userEvent.setup()
    render(<SwarmPage transport={new TauriTransport(invoke)} />)
    await user.click(await screen.findByRole('button', { name: /inspect Native Worker/i }))
    const inspector = await screen.findByRole('dialog', { name: 'Native Worker' })

    expect(await within(inspector).findByText('Current task is not exposed by the local engine.')).not.toBeNull()
    await user.click(within(inspector).getByRole('tab', { name: 'Process' }))
    expect(within(inspector).getByText('Process tree is not exposed by the local engine.')).not.toBeNull()
    expect(within(inspector).getByText('Port detail is not exposed by the local engine.')).not.toBeNull()
    expect(within(inspector).getByText('Not exposed')).not.toBeNull()
    await user.click(within(inspector).getByRole('tab', { name: 'Artifacts' }))
    expect(within(inspector).getByText('File-write detail is not exposed by the local engine.')).not.toBeNull()
    await user.click(within(inspector).getByRole('tab', { name: 'Memory' }))
    expect(within(inspector).getByText('Resource history is not exposed by the local engine.')).not.toBeNull()
    expect(within(inspector).getByText('Heartbeat history is not exposed by the local engine.')).not.toBeNull()
    await user.click(within(inspector).getByRole('tab', { name: 'Activity' }))
    expect(within(inspector).getByText('Status timeline is not exposed by the local engine.')).not.toBeNull()
    expect(inspector.textContent).not.toContain('C:\\Demo')
  })

  it('disables native containment when doctor reports no stable process binding', async () => {
    const processInstanceId = 'a'.repeat(64)
    const rawAgent = {
      agent_id: 'native-worker', process_instance_id: processInstanceId, provider: null, project: 'Local', role: 'Native Worker', state: 'stale',
      evidence_grade: 'confirmed', confidence: 0.95, explanation: 'A managed stale process was detected.',
      evidence: [], actionable: true, managed: true, pid: 4112, process_name: 'python',
    }
    const invokedMethods: string[] = []
    const invoke = vi.fn(async (_command: string, arguments_: unknown) => {
      const request = (arguments_ as { request: { method: string } }).request
      invokedMethods.push(request.method)
      if (request.method === 'doctor') return {
        requestId: '11111111-1111-4111-8111-111111111111', method: request.method,
        result: {
          healthy: false,
          checks: [
            { name: 'method:action.plan', ok: false },
            { name: 'method:action.execute', ok: false },
          ],
          warnings: ['Kernel-stable process binding is unavailable.'],
        },
      }
      if (request.method === 'scan.list') return {
        requestId: '22222222-2222-4222-8222-222222222222', method: request.method,
        result: {
          agents: [rawAgent],
          coverage: {
            inspected_count: 1, denied_count: 0, vanished_count: 0, malformed_lease_count: 0,
            skipped_lease_count: 0, other_user_count: 0, unknown_owner_count: 0, identity_denied_count: 0,
            complete: true, captured_at: '2026-08-12T21:00:00Z', warnings: [],
          },
          returned: 1, total: 1,
        },
      }
      if (request.method === 'agent.detail') return {
        requestId: '33333333-3333-4333-8333-333333333333', method: request.method, result: rawAgent,
      }
      throw new Error(`Unexpected native method: ${request.method}`)
    })
    const user = userEvent.setup()
    render(<SwarmPage transport={new TauriTransport(invoke)} />)

    expect(await screen.findByText('Local engine · process actions unavailable')).not.toBeNull()
    expect(screen.getByText(/Process scanning uses the local engine\. Process actions are unavailable on this host\./i)).not.toBeNull()
    await user.click(await screen.findByRole('button', { name: /inspect Native Worker/i }))
    const inspector = await screen.findByRole('dialog', { name: 'Native Worker' })

    expect(within(inspector).queryByRole('button', { name: 'Request graceful stop' })).toBeNull()
    expect(within(inspector).queryByRole('button', { name: 'Force stop' })).toBeNull()
    expect(within(inspector).getByText(/kernel-stable process binding/i)).not.toBeNull()
    expect(invokedMethods).not.toContain('action.plan')
  })

  it('locks normal receipt reconciliation and focuses each pending, failure, retry, and success destination', async () => {
    const failureGate = deferred<void>()
    const retryGate = deferred<void>()
    class ReconcileFailureTransport extends DemoTransport {
      scanCount = 0
      override async executeAction(request: Parameters<DemoTransport['executeAction']>[0]) {
        const receipt = await super.executeAction(request)
        return { ...receipt, title: 'Outcome uncertain' as const, certainty: 'uncertain' as const }
      }
      override async scan() {
        this.scanCount += 1
        if (this.scanCount === 2) {
          await failureGate.promise
          throw new TransportError('partial_failure', 'Reconciliation scan unavailable.')
        }
        if (this.scanCount === 3) await retryGate.promise
        return super.scan()
      }
    }
    const user = userEvent.setup()
    render(<SwarmPage transport={new ReconcileFailureTransport({ latencyMs: 0, now: () => NOW, id: (p) => p })} />)
    await user.click(await screen.findByRole('button', { name: /inspect ScreenShot Coordinator/i }))
    await user.click(screen.getByRole('button', { name: 'Request graceful stop' }))
    const dialog = await screen.findByRole('dialog', { name: /review graceful stop/i })
    await user.click(within(dialog).getByRole('checkbox', { name: /confirm this exact plan/i }))
    await user.click(within(dialog).getByRole('button', { name: 'Execute graceful stop' }))
    expect(await within(dialog).findByText('Outcome uncertain')).not.toBeNull()
    const pending = within(dialog).getByText('Reconciling the latest dashboard and inspector state…')
    await waitFor(() => expect(document.activeElement).toBe(pending))
    expect(pending.tabIndex).toBe(-1)
    await user.tab({ shift: true })
    expect(document.activeElement).toBe(within(dialog).getByRole('button', { name: 'Copy receipt summary' }))
    const close = within(dialog).getByRole('button', { name: 'Close Containment receipt' }) as HTMLButtonElement
    expect(close.disabled).toBe(true)

    await act(async () => failureGate.resolve())
    expect(within(dialog).getByRole('alert').textContent).toMatch(/reconciliation pending/i)
    const retry = within(dialog).getByRole('button', { name: 'Retry reconciliation' })
    expect(document.activeElement).toBe(retry)
    expect(close.disabled).toBe(true)
    expect(within(dialog).getByText(/Receipt ID/i)).not.toBeNull()
    await user.click(retry)
    expect(within(dialog).getByRole('button', { name: 'Retrying…' })).not.toBeNull()
    const retryPending = within(dialog).getByRole('status')
    expect(retryPending.textContent).toMatch(/retrying/i)
    await waitFor(() => expect(document.activeElement).toBe(retryPending))
    expect(document.activeElement).not.toBe(document.body)
    expect(close.disabled).toBe(true)
    await act(async () => retryGate.resolve())
    const returnButton = within(dialog).getByRole('button', { name: 'Return to inspector' })
    await waitFor(() => expect((returnButton as HTMLButtonElement).disabled).toBe(false))
    expect(document.activeElement).toBe(returnButton)
    expect(close.disabled).toBe(false)
  })

  it('keeps detail retry focus out of BODY while pending and focuses the loaded tabs', async () => {
    const retryGate = deferred<void>()
    class DetailFailureTransport extends DemoTransport {
      attempts = 0
      override async getAgentDetail(agentId: string) {
        this.attempts += 1
        if (this.attempts === 1) throw new TransportError('not_found', 'Agent disappeared during inspection.')
        await retryGate.promise
        return super.getAgentDetail(agentId)
      }
    }
    const user = userEvent.setup()
    render(<SwarmPage transport={new DetailFailureTransport({ latencyMs: 0, now: () => NOW })} />)
    await user.click(await screen.findByRole('button', { name: /inspect ScreenShot Coordinator/i }))
    expect((await screen.findByRole('alert')).textContent).toContain('Agent details unavailable')
    expect(screen.queryByRole('button', { name: 'Request graceful stop' })).toBeNull()
    await user.click(screen.getByRole('button', { name: 'Retry details' }))
    const retrying = screen.getByRole('button', { name: 'Retrying…' })
    expect(document.activeElement).toBe(retrying)
    expect(document.activeElement).not.toBe(document.body)
    await act(async () => retryGate.resolve())
    expect(await screen.findByRole('button', { name: 'Request graceful stop' })).not.toBeNull()
    expect(document.activeElement).toBe(screen.getByRole('tab', { name: 'Overview' }))
  })

  it('ignores a late overlapping refresh and keeps in-flight status accurate', async () => {
    const base = makeTransport()
    const initial = await base.scan()
    const first = deferred<ScanResult>(); const second = deferred<ScanResult>()
    let calls = 0
    const transport: EngineTransport = Object.assign(base, {
      scan: async () => { calls += 1; if (calls === 1) return initial; if (calls === 2) return first.promise; return second.promise },
    })
    let refresh: (() => Promise<void>) | null = null
    render(<SwarmPage transport={transport} registerRefresh={(value) => { refresh = value }} />)
    await screen.findByText('ScreenShot Coordinator')
    const refreshNow = refresh as (() => Promise<void>) | null
    if (!refreshNow) throw new Error('Refresh callback was not registered')
    let firstRefresh!: Promise<void>
    let secondRefresh!: Promise<void>
    act(() => {
      firstRefresh = refreshNow()
      secondRefresh = refreshNow()
    })
    expect(await screen.findByText('Updating…')).not.toBeNull()
    await act(async () => {
      second.resolve({ ...initial, revision: 'newest', agents: initial.agents.map((agent) => agent.id === 'mev-screenshot' ? { ...agent, revision: 2, state: 'interrupted' } : agent) })
      await secondRefresh
    })
    expect(screen.getByText('Updating…')).not.toBeNull()
    await act(async () => {
      first.resolve({ ...initial, revision: 'older', agents: initial.agents.map((agent) => agent.id === 'mev-screenshot' ? { ...agent, revision: 1, state: 'stale' } : agent) })
      await firstRefresh
    })
    expect(screen.queryByText('Updating…')).toBeNull()
    await userEvent.setup().click(screen.getByRole('button', { name: /1 result changed/i }))
    expect(screen.getByText('Interrupted')).not.toBeNull()
  })

  it('stages same-ID content revisions until updates are explicitly applied', async () => {
    const transport = makeTransport()
    const user = userEvent.setup()
    render(<SwarmPage transport={transport} />)
    const inspect = await screen.findByRole('button', { name: /inspect ScreenShot Coordinator/i })
    inspect.focus()
    const plan = await transport.planAction(demoActionRequest('graceful-stop'))
    await transport.executeAction({ planId: plan.planId, digest: plan.digest })
    await user.click(screen.getByRole('button', { name: 'Refresh swarm' }))

    expect(await screen.findByRole('button', { name: '1 result changed — apply updates' })).not.toBeNull()
    expect(screen.getByText('Orphaned')).not.toBeNull()
    expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Refresh swarm' }))
    await user.click(screen.getByRole('button', { name: '1 result changed — apply updates' }))
    expect(screen.getByText('Interrupted')).not.toBeNull()
    expect(screen.queryByText('Orphaned')).toBeNull()
  })

  it('isolates a pending-scan sibling inserted while agent details are modal', async () => {
    const base = makeTransport()
    const initial = await base.scan()
    const changed = structuredClone(initial)
    changed.agents[0].revision = Number(changed.agents[0].revision) + 1
    changed.agents[0].state = 'interrupted'
    let calls = 0
    const transport: EngineTransport = Object.assign(base, { scan: async () => { calls += 1; return calls === 1 ? initial : changed } })
    let refresh: (() => Promise<void>) | null = null
    const view = render(<SwarmPage transport={transport} registerRefresh={(value) => { refresh = value }} />)
    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: /inspect ScreenShot Coordinator/i }))
    expect(await screen.findByRole('dialog', { name: 'ScreenShot Coordinator' })).not.toBeNull()
    const refreshNow = refresh as (() => Promise<void>) | null
    if (!refreshNow) throw new Error('Refresh callback was not registered')
    await act(async () => { await refreshNow() })
    const pending = view.container.querySelector<HTMLButtonElement>('.changed-banner')
    expect(pending).not.toBeNull()
    await waitFor(() => expect(pending?.hasAttribute('inert')).toBe(true))
    expect(pending?.getAttribute('aria-hidden')).toBe('true')

    await user.keyboard('{Escape}')
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(pending?.hasAttribute('inert')).toBe(false)
    expect(pending?.hasAttribute('aria-hidden')).toBe(false)
  })

  it('stages content changes even when a transport accidentally reuses its scan revision', async () => {
    const base = makeTransport()
    const initial = await base.scan()
    const changed = structuredClone(initial)
    changed.agents[0].ramMb = 999
    changed.metrics.reclaimableMb = 999
    let calls = 0
    const transport: EngineTransport = Object.assign(base, {
      scan: async () => { calls += 1; return calls === 1 ? initial : changed },
    })
    const user = userEvent.setup()
    render(<SwarmPage transport={transport} />)
    await screen.findByText('ScreenShot Coordinator')
    await user.click(screen.getByRole('button', { name: 'Refresh swarm' }))
    expect(await screen.findByRole('button', { name: '1 result changed — apply updates' })).not.toBeNull()
    expect(screen.getByText('684 MB RAM')).not.toBeNull()
    await user.click(screen.getByRole('button', { name: '1 result changed — apply updates' }))
    expect(screen.getByText('999 MB RAM')).not.toBeNull()
  })

  it('applies scans immediately when only capture metadata and volatile IDs changed', async () => {
    const base = makeTransport()
    const initial = await base.scan()
    const refreshed = structuredClone(initial)
    refreshed.revision = 'new-capture-revision'
    refreshed.capturedAt = '2026-08-12T16:01:00.000Z'
    refreshed.agents.forEach((agent, index) => {
      agent.revision = `capture-${index}`
      agent.evidence.forEach((signal, signalIndex) => {
        signal.id = `volatile-agent-evidence-${index}-${signalIndex}`
        signal.observedAt = refreshed.capturedAt
      })
    })
    refreshed.evidence.forEach((signal, index) => {
      signal.id = `volatile-scan-evidence-${index}`
      signal.observedAt = refreshed.capturedAt
    })
    refreshed.resources.forEach((point) => { point.observedAt = refreshed.capturedAt })
    refreshed.timeline.forEach((event, index) => { event.id = `volatile-timeline-${index}` })
    refreshed.receipts.forEach((receipt, index) => { receipt.receiptId = `volatile-receipt-${index}`; receipt.planId = `volatile-plan-${index}` })
    let calls = 0
    const transport: EngineTransport = Object.assign(base, {
      scan: async () => { calls += 1; return calls === 1 ? initial : refreshed },
    })
    const user = userEvent.setup()
    render(<SwarmPage transport={transport} />)
    await screen.findByText('ScreenShot Coordinator')
    await user.click(screen.getByRole('button', { name: 'Refresh swarm' }))
    await waitFor(() => expect(screen.queryByText('Updating…')).toBeNull())

    expect(screen.queryByRole('button', { name: /apply updates/i })).toBeNull()
  })

  it('uses neutral update copy when only coverage changes', async () => {
    const base = makeTransport()
    const initial = await base.scan()
    const changed = structuredClone(initial)
    changed.revision = 'coverage-only'
    changed.coverage.blindSpotCount = 3
    changed.coverage.blindSpots.push('Synthetic coverage probe unavailable')
    let calls = 0
    const transport: EngineTransport = Object.assign(base, {
      scan: async () => { calls += 1; return calls === 1 ? initial : changed },
    })
    const user = userEvent.setup()
    render(<SwarmPage transport={transport} />)
    await screen.findByText('2 coverage blind spots')
    await user.click(screen.getByRole('button', { name: 'Refresh swarm' }))
    const apply = await screen.findByRole('button', { name: 'Updates available — apply updates' })
    expect(apply.textContent).not.toMatch(/1 result/i)
    await user.click(apply)
    expect(screen.getByText('3 coverage blind spots')).not.toBeNull()
  })

  it('keeps keyboard focus on refresh and can pause auto-refresh', async () => {
    const user = userEvent.setup()
    render(<SwarmPage transport={makeTransport()} refreshIntervalMs={50} />)
    const inspect = await screen.findByRole('button', { name: /inspect Search Bot/i })
    inspect.focus()
    await user.click(screen.getByRole('button', { name: 'Pause auto-refresh' }))
    expect(screen.getByRole('button', { name: 'Resume auto-refresh' })).not.toBeNull()
    expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Resume auto-refresh' }))
    await user.click(screen.getByRole('button', { name: 'Refresh swarm' }))
    await waitFor(() => expect(screen.queryByText('Updating…')).toBeNull())
    expect(document.body.contains(inspect)).toBe(true)
  })

  it('has no automated accessibility violations in radar or detail', async () => {
    const user = userEvent.setup()
    const { container } = render(<SwarmPage transport={makeTransport()} />)
    await screen.findByText('ScreenShot Coordinator')
    expect((await axe.run(container, { rules: { 'color-contrast': { enabled: false } } })).violations).toEqual([])
    await user.click(screen.getByRole('button', { name: /inspect ScreenShot Coordinator/i }))
    expect((await axe.run(container, { rules: { 'color-contrast': { enabled: false } } })).violations).toEqual([])
    await user.click(await screen.findByRole('button', { name: 'Review containment' }))
    await screen.findByRole('dialog', { name: /review graceful stop/i })
    expect(screen.getAllByRole('dialog')).toHaveLength(1)
    expect((await axe.run(container, { rules: { 'color-contrast': { enabled: false } } })).violations).toEqual([])
  })
})
