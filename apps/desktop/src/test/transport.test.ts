import { readFileSync } from 'node:fs'
import path from 'node:path'
import { describe, expect, it, vi } from 'vitest'

import { DemoTransport } from '../transport/demo'
import { createTransport, isTauriRuntime } from '../transport/factory'
import { TauriTransport } from '../transport/tauri'
import { TransportError } from '../transport/types'

describe('transport factory', () => {
  it('uses the deterministic lab only outside Tauri', () => {
    expect(createTransport({ nativeRuntime: false, dev: false })).toBeInstanceOf(DemoTransport)
  })

  it('uses the native transport inside Tauri and never probes by invoking a command', () => {
    const invoke = vi.fn()
    const transport = createTransport({ nativeRuntime: true, dev: false, invoke })
    expect(transport).toBeInstanceOf(TauriTransport)
    expect(invoke).not.toHaveBeenCalled()
  })

  it('allows an explicit demo override only in development', () => {
    expect(createTransport({ nativeRuntime: true, dev: true, demoOverride: true })).toBeInstanceOf(DemoTransport)
    expect(createTransport({ nativeRuntime: true, dev: false, demoOverride: true })).toBeInstanceOf(TauriTransport)
  })

  it('uses the supported Tauri detector without probing broad IPC globals', () => {
    expect(isTauriRuntime(() => true)).toBe(true)
    expect(isTauriRuntime(() => false)).toBe(false)
    const source = readFileSync(path.join(process.cwd(), 'src', 'transport', 'factory.ts'), 'utf8')
    expect(source).not.toMatch(/__TAURI|globalThis|window\s+as/)
  })
})

describe('process target PID boundary', () => {
  it('rejects a demo action request outside the unsigned 32-bit PID range', async () => {
    const transport = new DemoTransport({ latencyMs: 0 })

    await expect(transport.planAction({
      agentId: 'mev-screenshot',
      kind: 'graceful-stop',
      target: { pid: 4_294_967_296, processInstanceId: '1'.repeat(64) },
    })).rejects.toMatchObject({ code: 'invalid_request' })
  })
})

describe('native transport boundary', () => {
  it('reports a bounded native agent view as partial instead of complete coverage', async () => {
    const reply = nativeScanReply('a'.repeat(64))
    const source = (reply.result.agents as Array<Record<string, unknown>>)[0]!
    reply.result.agents = Array.from({ length: 500 }, (_, index) => ({ ...source, agent_id: `worker-${index}`, pid: index + 1 }))
    reply.result.returned = 500
    reply.result.total = 750
    const invoke = vi.fn(async (_command: string, arguments_: unknown) => {
      const request = (arguments_ as { request: { method: string } }).request
      return request.method === 'doctor' ? nativeDoctorReply(true) : reply
    })

    const scan = await new TauriTransport(invoke).scan()

    expect(scan.agents).toHaveLength(500)
    expect(scan.coverage.completeness).toBe('partial')
    expect(scan.coverage.blindSpotCount).toBe(250)
    expect(scan.coverage.blindSpots.join(' ')).toMatch(/500 of 750 detected agents.*250.*omitted/i)
  })

  it('does not mistake intentional unmanaged exclusion for native view truncation', async () => {
    const reply = nativeScanReply('a'.repeat(64))
    reply.result.total = 750
    const invoke = vi.fn(async (_command: string, arguments_: unknown) => {
      const request = (arguments_ as { request: { method: string } }).request
      return request.method === 'doctor' ? nativeDoctorReply(true) : reply
    })

    const scan = await new TauriTransport(invoke).scan({ includeUnmanagedCandidates: false })

    expect(scan.agents).toHaveLength(1)
    expect(scan.coverage.completeness).toBe('complete')
    expect(scan.coverage.blindSpotCount).toBe(0)
  })

  it.each([
    { returned: 0, total: 1 },
    { returned: 1, total: 0 },
    { returned: 1, total: 1.5 },
  ])('rejects inconsistent native scan counts $returned/$total', async ({ returned, total }) => {
    const reply = nativeScanReply('a'.repeat(64))
    reply.result.returned = returned
    reply.result.total = total
    const invoke = vi.fn(async (_command: string, arguments_: unknown) => {
      const request = (arguments_ as { request: { method: string } }).request
      return request.method === 'doctor' ? nativeDoctorReply(true) : reply
    })

    await expect(new TauriTransport(invoke).scan()).rejects.toMatchObject({ code: 'schema_invalid' })
  })

  it('starts process actions fail-closed and enables them only after doctor confirms both methods', async () => {
    const processInstanceId = 'a'.repeat(64)
    const invoke = vi.fn(async (_command: string, arguments_: unknown) => {
      const request = (arguments_ as { request: { method: string } }).request
      if (request.method === 'doctor') return nativeDoctorReply(true)
      if (request.method === 'scan.list') return nativeScanReply(processInstanceId)
      throw new Error(`unexpected method ${request.method}`)
    })
    const transport = new TauriTransport(invoke)

    expect(transport.capabilities.processActions).toBe(false)
    await transport.scan()

    expect(transport.capabilities.processActions).toBe(true)
    expect(transport.capabilities.processActionsUnavailableReason).toBeNull()
    expect(invoke.mock.calls.map(([, arguments_]) => (arguments_ as { request: { method: string } }).request.method)).toEqual(['doctor', 'scan.list'])
  })

  it('keeps actions unavailable when doctor reports no stable process binding', async () => {
    const processInstanceId = 'a'.repeat(64)
    const invokedMethods: string[] = []
    const invoke = vi.fn(async (_command: string, arguments_: unknown) => {
      const request = (arguments_ as { request: { method: string } }).request
      invokedMethods.push(request.method)
      if (request.method === 'doctor') return nativeDoctorReply(false)
      if (request.method === 'scan.list') return nativeScanReply(processInstanceId)
      throw new Error(`unexpected method ${request.method}`)
    })
    const transport = new TauriTransport(invoke)

    await transport.scan()

    expect(transport.capabilities.processActions).toBe(false)
    expect(transport.capabilities.processActionsUnavailableReason).toMatch(/kernel-stable process binding/i)
    await expect(transport.planAction({
      agentId: 'managed-agent', kind: 'graceful-stop', target: { pid: 4112, processInstanceId },
    })).rejects.toMatchObject({ code: 'unsupported', recoverable: false })
    expect(invokedMethods).toEqual(['doctor', 'scan.list'])
  })

  it('keeps actions fail-closed after a doctor error and retries the probe on the next scan', async () => {
    const processInstanceId = 'a'.repeat(64)
    const invokedMethods: string[] = []
    let doctorCalls = 0
    const invoke = vi.fn(async (_command: string, arguments_: unknown) => {
      const request = (arguments_ as { request: { method: string } }).request
      invokedMethods.push(request.method)
      if (request.method === 'doctor') {
        doctorCalls += 1
        if (doctorCalls === 1) throw new Error('synthetic transient doctor error')
        return nativeDoctorReply(true)
      }
      if (request.method === 'scan.list') return nativeScanReply(processInstanceId)
      throw new Error(`unexpected method ${request.method}`)
    })
    const transport = new TauriTransport(invoke)

    await transport.scan()
    expect(transport.capabilities.processActions).toBe(false)

    await transport.scan()
    expect(transport.capabilities.processActions).toBe(true)
    expect(transport.capabilities.processActionsUnavailableReason).toBeNull()
    expect(invokedMethods).toEqual(['doctor', 'scan.list', 'doctor', 'scan.list'])
  })

  it('binds graceful and force plans to the requested process instance and authoritative engine target', async () => {
    const processInstanceId = 'a'.repeat(64)
    const invoke = vi.fn(async (_command: string, arguments_: unknown) => {
      const request = (arguments_ as { request: { method: string; payload: Record<string, unknown> } }).request
      if (request.method === 'doctor') return nativeDoctorReply(true)
      if (request.method === 'scan.list') return {
        requestId: '11111111-1111-4111-8111-111111111111', method: 'scan.list',
        result: {
          agents: [{ agent_id: 'managed-agent', process_instance_id: processInstanceId, provider: null, project: 'Local', role: 'Worker', state: 'stale', evidence_grade: 'confirmed', confidence: 0.95, reason_codes: ['lease_stale'], explanation: 'Lease is stale.', evidence: [{ code: 'lease_stale', grade: 'confirmed', observed_at: '2026-08-12T21:00:00Z', detail: 'Managed lease is stale.' }], actionable: true, managed: true, pid: 4112, process_name: 'python', os_status: 'running', usage_cost: { availability: 'unknown', amount_usd: null, note: 'Unknown.' } }],
          coverage: { inspected_count: 1, denied_count: 0, vanished_count: 0, malformed_lease_count: 0, lease_file_count: 1, skipped_lease_count: 0, other_user_count: 0, unknown_owner_count: 0, identity_denied_count: 0, complete: true, captured_at: '2026-08-12T21:00:00Z', current_boot_id: 'boot', warnings: [] },
          returned: 1, total: 1,
        },
      }
      if (request.method !== 'action.plan') throw new Error('unexpected method')
      expect(Object.keys(request.payload).sort()).toEqual(['agentId', 'mode', 'target'])
      expect(request.payload).not.toHaveProperty('executable')
      expect(request.payload.target).toEqual({ pid: 4112, processInstanceId })
      return {
        requestId: '11111111-1111-4111-8111-111111111111',
        method: 'action.plan',
        result: {
          plan_id: request.payload.mode === 'request_stop' ? 'plan-graceful' : 'plan-force',
          digest: 'a'.repeat(64), expires_at: '2026-08-12T22:00:00Z',
          consequences: ['The exact process identity will be revalidated.'], warnings: [],
          target: { pid: 4112, process_instance_id: processInstanceId, state: 'stale' },
        },
      }
    })
    const transport = new TauriTransport(invoke)
    const scan = await transport.scan()
    expect(scan.agents[0]?.processInstanceId).toBe(processInstanceId)

    const target = { pid: 4112, processInstanceId }
    const graceful = await transport.planAction({ agentId: 'managed-agent', kind: 'graceful-stop', target })
    const force = await transport.planAction({ agentId: 'managed-agent', kind: 'force-stop', target })

    expect(graceful.engineMode).toBe('request_stop')
    expect(force.engineMode).toBe('kill')
    expect(graceful.target).toEqual({ pid: 4112, processInstanceId, state: 'stale' })
    expect(graceful.agentId).toBe('managed-agent')
    expect(graceful.expectedPortsReleased).toBeNull()
  })

  it('rejects unexpected runtime action kinds instead of defaulting to a force stop', async () => {
    const processInstanceId = 'a'.repeat(64)
    const invoke = vi.fn(async (_command: string, arguments_: unknown) => {
      const request = (arguments_ as { request: { method: string } }).request
      if (request.method === 'doctor') return nativeDoctorReply(true)
      if (request.method === 'scan.list') return nativeScanReply(processInstanceId)
      if (request.method === 'action.plan') return nativeReply(request.method, {
        plan_id: 'plan-unexpected', digest: 'b'.repeat(64), expires_at: '2026-08-12T22:00:00Z',
        consequences: [], warnings: [], target: { pid: 4112, process_instance_id: processInstanceId, state: 'stale' },
      })
      throw new Error(`unexpected method ${request.method}`)
    })
    const transport = new TauriTransport(invoke)
    await transport.scan()
    const unexpected = {
      agentId: 'managed-agent', kind: 'synthetic-stop', target: { pid: 4112, processInstanceId },
    } as unknown as Parameters<TauriTransport['planAction']>[0]

    await expect(transport.planAction(unexpected)).rejects.toMatchObject({ code: 'invalid_request', recoverable: false })
    expect(invoke).toHaveBeenCalledTimes(2)
  })

  it('never rolls the actionable cache back when an older overlapping scan finishes last', async () => {
    const olderInstance = 'a'.repeat(64)
    const newerInstance = 'b'.repeat(64)
    let releaseOlder!: () => void
    const olderGate = new Promise<void>((resolve) => { releaseOlder = resolve })
    let scanCalls = 0
    const invoke = vi.fn(async (_command: string, arguments_: unknown) => {
      const request = (arguments_ as { request: { method: string; payload: Record<string, unknown> } }).request
      if (request.method === 'doctor') return nativeDoctorReply(true)
      if (request.method === 'scan.list') {
        scanCalls += 1
        if (scanCalls === 1) {
          await olderGate
          return nativeScanReply(olderInstance)
        }
        return nativeScanReply(newerInstance)
      }
      if (request.method === 'action.plan') {
        expect(request.payload.target).toEqual({ pid: 4112, processInstanceId: newerInstance })
        return nativeReply(request.method, {
          plan_id: 'plan-newer', digest: 'd'.repeat(64), expires_at: '2026-08-12T22:00:00Z',
          consequences: [], warnings: [],
          target: { pid: 4112, process_instance_id: newerInstance, state: 'stale' },
        })
      }
      throw new Error(`unexpected method ${request.method}`)
    })
    const transport = new TauriTransport(invoke)

    const olderScan = transport.scan()
    await vi.waitFor(() => expect(scanCalls).toBe(1))
    const newerScan = await transport.scan()
    expect(newerScan.agents[0]?.processInstanceId).toBe(newerInstance)
    releaseOlder()
    await expect(olderScan).resolves.toMatchObject({ agents: [{ processInstanceId: olderInstance }] })

    await expect(transport.planAction({
      agentId: 'managed-agent', kind: 'graceful-stop', target: { pid: 4112, processInstanceId: newerInstance },
    })).resolves.toMatchObject({ planId: 'plan-newer', target: { processInstanceId: newerInstance } })
  })

  it('rejects an action plan whose authoritative target differs from the requested instance', async () => {
    const requestedInstance = 'a'.repeat(64)
    const invoke = vi.fn(async (_command: string, arguments_: unknown) => {
      const request = (arguments_ as { request: { method: string; payload: Record<string, unknown> } }).request
      if (request.method === 'doctor') return nativeDoctorReply(true)
      if (request.method === 'scan.list') return nativeScanReply(requestedInstance)
      return nativeReply('action.plan', {
        plan_id: 'plan-mismatch', digest: 'b'.repeat(64), expires_at: '2026-08-12T22:00:00Z',
        consequences: [], warnings: [],
        target: { pid: 4112, process_instance_id: 'c'.repeat(64), state: 'stale' },
      })
    })
    const transport = new TauriTransport(invoke)
    await transport.scan()

    await expect(transport.planAction({
      agentId: 'managed-agent', kind: 'graceful-stop',
      target: { pid: 4112, processInstanceId: requestedInstance },
    })).rejects.toMatchObject({ code: 'target_changed', details: { reason: 'process_instance_changed' } })
  })

  it('rejects an authoritative action target outside the unsigned 32-bit PID range', async () => {
    const processInstanceId = 'a'.repeat(64)
    const invoke = vi.fn(async (_command: string, arguments_: unknown) => {
      const request = (arguments_ as { request: { method: string } }).request
      if (request.method === 'doctor') return nativeDoctorReply(true)
      if (request.method === 'scan.list') return nativeScanReply(processInstanceId)
      return nativeReply('action.plan', {
        plan_id: 'plan-out-of-range', digest: 'b'.repeat(64), expires_at: '2026-08-12T22:00:00Z',
        consequences: [], warnings: [],
        target: { pid: 4_294_967_296, process_instance_id: processInstanceId, state: 'stale' },
      })
    })
    const transport = new TauriTransport(invoke)
    await transport.scan()

    await expect(transport.planAction({
      agentId: 'managed-agent', kind: 'graceful-stop',
      target: { pid: 4112, processInstanceId },
    })).rejects.toMatchObject({ code: 'schema_invalid' })
  })

  it('rejects same-ID agent detail from a replaced process instance', async () => {
    const scannedInstance = 'a'.repeat(64)
    const replacementInstance = 'b'.repeat(64)
    const invoke = vi.fn(async (_command: string, arguments_: unknown) => {
      const request = (arguments_ as { request: { method: string; payload: Record<string, unknown> } }).request
      if (request.method === 'scan.list') return nativeScanReply(scannedInstance)
      if (request.method === 'agent.detail') {
        expect(request.payload).toMatchObject({ agentId: 'managed-agent', expectedPid: 4112, expectedProcessInstanceId: scannedInstance })
        return nativeReply(request.method, { ...((nativeScanReply(replacementInstance).result as { agents: unknown[] }).agents[0] as Record<string, unknown>) })
      }
      throw new Error('unexpected method')
    })
    const transport = new TauriTransport(invoke)
    await transport.scan()

    await expect(transport.getAgentDetail('managed-agent')).rejects.toMatchObject({
      code: 'target_changed', details: { reason: 'agent_identity_changed' },
    })
  })

  it('rejects a displayed detail binding crossed with another requested agent ID', async () => {
    const scannedInstance = 'a'.repeat(64)
    const invoke = vi.fn(async (_command: string, arguments_: unknown) => {
      const request = (arguments_ as { request: { method: string } }).request
      if (request.method === 'doctor') return nativeDoctorReply(true)
      if (request.method === 'scan.list') return nativeScanReply(scannedInstance)
      throw new Error('agent.detail must not be invoked for a crossed identity binding')
    })
    const transport = new TauriTransport(invoke)
    const scanned = await transport.scan()
    const displayed = scanned.agents[0]!

    await expect(transport.getAgentDetail('different-agent', {
      id: displayed.id,
      revision: displayed.revision,
      pid: displayed.pid,
      processInstanceId: displayed.processInstanceId,
    })).rejects.toMatchObject({ code: 'target_changed' })
    expect(invoke).toHaveBeenCalledTimes(2)
  })

  it('never refetches a raw agent detail when the scan lacks complete process identity', async () => {
    const reply = nativeScanReply('a'.repeat(64))
    const agent = ((reply.result as { agents: Array<Record<string, unknown>> }).agents[0]!)
    agent.pid = null
    agent.process_instance_id = null
    agent.actionable = false
    const invoke = vi.fn(async (_command: string, arguments_: unknown) => {
      const request = (arguments_ as { request: { method: string } }).request
      if (request.method === 'doctor') return nativeDoctorReply(true)
      if (request.method === 'scan.list') return reply
      throw new Error('unbound agent.detail must not be invoked')
    })
    const transport = new TauriTransport(invoke)
    const scanned = await transport.scan()
    const displayed = scanned.agents[0]!
    const detail = await transport.getAgentDetail(displayed.id, displayed)

    expect(detail).toMatchObject({ id: 'managed-agent', pid: null, processInstanceId: null, actionable: false })
    expect(invoke).toHaveBeenCalledTimes(2)
  })

  it('treats a receipt plan mismatch as outcome uncertain and never invents agent attribution', async () => {
    const processInstanceId = 'a'.repeat(64)
    const invoke = vi.fn(async (_command: string, arguments_: unknown) => {
      const request = (arguments_ as { request: { method: string } }).request
      if (request.method === 'doctor') return nativeDoctorReply(true)
      if (request.method === 'scan.list') return nativeScanReply(processInstanceId)
      if (request.method === 'action.plan') return nativeReply(request.method, {
        plan_id: 'plan-expected', digest: 'd'.repeat(64), expires_at: '2026-08-12T22:00:00Z',
        consequences: [], warnings: [], target: { pid: 4112, process_instance_id: processInstanceId, state: 'stale' },
      })
      return nativeReply(request.method, {
        receipt_id: 'receipt-1', plan_id: 'plan-other', outcome: 'completed', certainty: 'verified',
        action_issued: true, partial_failures: [], created_at: '2026-08-12T21:01:00Z',
      })
    })
    const transport = new TauriTransport(invoke)
    await transport.scan()
    const plan = await transport.planAction({
      agentId: 'managed-agent', kind: 'graceful-stop', target: { pid: 4112, processInstanceId },
    })

    await expect(transport.executeAction({ planId: plan.planId, digest: plan.digest })).rejects.toMatchObject({
      code: 'outcome_uncertain', details: { reconcileRequired: true, expectedPlanId: 'plan-expected', receivedPlanId: 'plan-other' },
    })
  })

  it('does not silently fall back to demo data when native invocation fails', async () => {
    const transport = new TauriTransport(vi.fn().mockRejectedValue({ code: 'engine_unavailable', message: 'Local engine unavailable.', correlationId: 'corr-1' }))
    await expect(transport.scan()).rejects.toMatchObject({
      name: 'TransportError', code: 'engine_unavailable', message: 'Local engine unavailable.',
    })
  })

  it('marks an execution timeout as uncertain and requires reconciliation', async () => {
    const processInstanceId = 'a'.repeat(64)
    const transport = boundTransportWithExecuteError(processInstanceId, {
      code: 'outcome_uncertain', message: 'The action outcome is uncertain; reconcile local state.', correlationId: 'corr-2', reconcileRequired: true,
    })
    await transport.scan()
    const plan = await transport.planAction({ agentId: 'managed-agent', kind: 'graceful-stop', target: { pid: 4112, processInstanceId } })
    await expect(transport.executeAction({ planId: plan.planId, digest: plan.digest })).rejects.toEqual(
      expect.objectContaining<Partial<TransportError>>({ code: 'outcome_uncertain', recoverable: true }),
    )
  })

  it('preserves ambiguous engine errors and their mandatory reconciliation flag', async () => {
    const processInstanceId = 'a'.repeat(64)
    const transport = boundTransportWithExecuteError(processInstanceId, {
      code: 'internal', message: 'The local engine reported an internal error.', correlationId: 'corr-3', reconcileRequired: true,
    })
    await transport.scan()
    const plan = await transport.planAction({ agentId: 'managed-agent', kind: 'force-stop', target: { pid: 4112, processInstanceId } })
    await expect(transport.executeAction({ planId: plan.planId, digest: plan.digest })).rejects.toMatchObject({
      code: 'internal', details: { reconcileRequired: true },
    })
  })

  it('rejects a tampered native result instead of coercing it', async () => {
    const transport = new TauriTransport(vi.fn().mockResolvedValue({
      requestId: '11111111-1111-4111-8111-111111111111', method: 'scan.list',
      result: { agents: 'not-an-array', coverage: {}, returned: 0, total: 0 },
    }))
    await expect(transport.scan()).rejects.toMatchObject({ code: 'schema_invalid' })
  })

  it('rejects unknown receipt and quarantine states instead of coercing them', async () => {
    const reply = (method: string, result: Record<string, unknown>) => ({
      requestId: '11111111-1111-4111-8111-111111111111', method, result,
    })
    const invalidReceipt = new TauriTransport(vi.fn(async (_command: string, arguments_: unknown) => {
      const method = (arguments_ as { request: { method: string } }).request.method
      return method === 'activity.list'
        ? reply(method, { receipts: [{ receipt_id: 'r', plan_id: 'p', outcome: 'invented', certainty: 'verified', action_issued: true, partial_failures: [], created_at: '2026-08-12T20:00:00Z' }], next_cursor: null })
        : reply(method, { entries: [], next_cursor: null })
    }))
    const invalidQuarantine = new TauriTransport(vi.fn(async (_command: string, arguments_: unknown) => {
      const method = (arguments_ as { request: { method: string } }).request.method
      return method === 'activity.list'
        ? reply(method, { receipts: [], next_cursor: null })
        : reply(method, { entries: [{ entry_id: 'e', agent_id: 'a', resource_type: 'file', state: 'invented', restorable: false, created_at: '2026-08-12T20:00:00Z', updated_at: '2026-08-12T20:00:00Z' }], next_cursor: null })
    }))

    await expect(invalidReceipt.getActivity()).rejects.toMatchObject({ code: 'schema_invalid' })
    await expect(invalidQuarantine.getActivity()).rejects.toMatchObject({ code: 'schema_invalid' })
  })

  it('preserves bounded partial receipt reasons and never labels them complete', async () => {
    const invoke = vi.fn(async (_command: string, arguments_: unknown) => {
      const method = (arguments_ as { request: { method: string } }).request.method
      if (method === 'activity.list') return nativeReply(method, {
        receipts: [{
          receipt_id: 'receipt-partial', plan_id: 'plan-partial', outcome: 'completed', certainty: 'verified',
          action_issued: true, partial_failures: ['Cleanup verification failed.'], created_at: '2026-08-12T20:00:00Z',
        }],
        next_cursor: null,
      })
      return nativeReply(method, { entries: [], next_cursor: null })
    })

    const activity = await new TauriTransport(invoke).getActivity()

    expect(activity.receipts[0]).toMatchObject({
      title: 'Containment partially completed',
      outcome: 'completed',
      certainty: 'verified',
      partialFailures: ['Cleanup verification failed.'],
    })
    expect(activity.receipts[0]?.diagnostics).toContain('1 partial follow-up failure')
  })

  it('rejects missing, oversized, blank, and unexpected partial receipt fields', async () => {
    const base = {
      receipt_id: 'receipt-partial', plan_id: 'plan-partial', outcome: 'completed', certainty: 'verified',
      action_issued: true, created_at: '2026-08-12T20:00:00Z',
    }
    const invalid = [
      base,
      { ...base, partial_failures: Array.from({ length: 65 }, () => 'bounded') },
      { ...base, partial_failures: ['x'.repeat(2_049)] },
      { ...base, partial_failures: [''] },
      { ...base, partial_failures: [], unexpected: true },
    ]

    for (const receipt of invalid) {
      const transport = new TauriTransport(vi.fn(async (_command: string, arguments_: unknown) => {
        const method = (arguments_ as { request: { method: string } }).request.method
        return nativeReply(method, { receipts: [receipt], next_cursor: null })
      }))
      await expect(transport.getActivity()).rejects.toMatchObject({ code: 'schema_invalid' })
    }
  })

  it('follows opaque quarantine cursors and preserves partial-entry provenance without claiming restore', async () => {
    const quarantinePayloads: Record<string, unknown>[] = []
    const invoke = vi.fn(async (_command: string, arguments_: unknown) => {
      const request = (arguments_ as { request: { method: string; payload: Record<string, unknown> } }).request
      if (request.method === 'doctor') return nativeDoctorReply(false)
      if (request.method === 'activity.list') return nativeReply(request.method, { receipts: [], next_cursor: null })
      quarantinePayloads.push(request.payload)
      if (!request.payload.cursor) return nativeReply(request.method, {
        entries: [{ entry_id: 'entry-partial', agent_id: 'agent-1', resource_type: 'file', state: 'partial', restorable: true, created_at: '2026-08-12T20:00:00Z', updated_at: '2026-08-12T20:01:00Z' }],
        next_cursor: 'opaque-page-2',
      })
      return nativeReply(request.method, {
        entries: [{ entry_id: 'entry-complete', agent_id: 'agent-2', resource_type: 'directory', state: 'quarantined', restorable: false, created_at: '2026-08-12T20:02:00Z', updated_at: '2026-08-12T20:03:00Z' }],
        next_cursor: null,
      })
    })
    const activity = await new TauriTransport(invoke).getActivity()

    expect(quarantinePayloads).toEqual([{ limit: 500 }, { limit: 500, cursor: 'opaque-page-2' }])
    expect(activity.quarantine).toEqual([
      expect.objectContaining({ id: 'entry-partial', agentId: 'agent-1', resourceType: 'file', createdAt: '2026-08-12T20:00:00Z', state: 'Partial', restorable: false }),
      expect.objectContaining({ id: 'entry-complete', agentId: 'agent-2', resourceType: 'directory', createdAt: '2026-08-12T20:02:00Z', state: 'Quarantined', restorable: false }),
    ])
    expect(activity.pagination.quarantineTruncated).toBe(false)
  })

  it('exposes unsupported native mutations instead of fabricating demo receipts', async () => {
    const transport = new TauriTransport(vi.fn())
    expect(transport.capabilities.vaultMutation).toBe(false)
    await expect(transport.executeMemoryChange({ planId: 'plan', digest: 'c'.repeat(64) })).rejects.toMatchObject({ code: 'unsupported' })
  })

  it('preserves native Vault formats and exact string revisions', async () => {
    const revision = 'd'.repeat(64)
    const invoke = vi.fn(async (_command: string, arguments_: unknown) => {
      const request = (arguments_ as { request: { method: string } }).request
      if (request.method === 'vault.list') return {
        requestId: '11111111-1111-4111-8111-111111111111', method: 'vault.list',
        result: { sources: [{ source_id: 'faiss-source', format: 'faiss', capabilities: { readable: true, queryable: false, editable: false, snapshot: false, restore: false, reason: 'Inspection only.' }, revision }], next_cursor: null, local_only_warning: 'Local only.' },
      }
      if (request.method === 'vault.get') return {
        requestId: '11111111-1111-4111-8111-111111111111', method: 'vault.get',
        result: { record: { record_id: 'record-1', namespace: 'default', content: '', metadata: {}, embedding_present: false, source_revision: revision }, local_only_warning: 'Local only.' },
      }
      throw new Error('unexpected method')
    })
    const transport = new TauriTransport(invoke)

    const vault = await transport.getVault()
    const record = await transport.getMemoryRecord('faiss-source', 'record-1')

    expect(vault.capturedAt).toBeNull()
    expect(vault.sources[0]).toMatchObject({ kind: 'FAISS', revision, revisionDigest: revision, status: 'Unsupported' })
    expect(record).toMatchObject({ revision, sourceRevisionDigest: revision, updatedAt: null, references: null })
  })

  it('follows opaque native vault source cursors across pages', async () => {
    const payloads: Record<string, unknown>[] = []
    const invoke = vi.fn(async (_command: string, arguments_: unknown) => {
      const request = (arguments_ as { request: { method: string; payload: Record<string, unknown> } }).request
      if (request.method === 'doctor') return nativeDoctorReply(false)
      payloads.push(request.payload)
      const source = (id: string) => ({ source_id: id, format: 'json', revision: 'a'.repeat(64), capabilities: { readable: true, queryable: true, editable: false, snapshot: false, restore: false, reason: null } })
      return nativeReply(request.method, {
        sources: [source(request.payload.cursor ? 'source-page-2' : 'source-page-1')],
        next_cursor: request.payload.cursor ? null : 'vault-page-2', local_only_warning: 'Local only.',
      })
    })

    const vault = await new TauriTransport(invoke).getVault()
    expect(payloads).toEqual([{ limit: 500 }, { limit: 500, cursor: 'vault-page-2' }])
    expect(vault.sources.map((item) => item.id)).toEqual(['source-page-1', 'source-page-2'])
  })

  it('fails closed on repeated or overlong native Vault source cursor chains', async () => {
    const source = (id: string) => ({ source_id: id, format: 'json', revision: 'a'.repeat(64), capabilities: { readable: true, queryable: true, editable: false, snapshot: false, restore: false, reason: null } })
    const repeated = new TauriTransport(vi.fn(async (_command: string, arguments_: unknown) => {
      const request = (arguments_ as { request: { method: string } }).request
      if (request.method === 'doctor') return nativeDoctorReply(false)
      return nativeReply(request.method, { sources: [source('source')], next_cursor: 'repeated', local_only_warning: 'Local only.' })
    }))
    await expect(repeated.getVault()).rejects.toMatchObject({ code: 'protocol_violation' })

    let page = 0
    const overlong = new TauriTransport(vi.fn(async (_command: string, arguments_: unknown) => {
      const request = (arguments_ as { request: { method: string } }).request
      if (request.method === 'doctor') return nativeDoctorReply(false)
      page += 1
      return nativeReply(request.method, { sources: [source(`source-${page}`)], next_cursor: `cursor-${page}`, local_only_warning: 'Local only.' })
    }))
    await expect(overlong.getVault()).rejects.toMatchObject({ code: 'protocol_violation' })
    expect(page).toBe(20)
  })

  it('rejects native Vault filters that the engine query cannot honor', async () => {
    const invoke = vi.fn()
    const transport = new TauriTransport(invoke)
    await expect(transport.searchMemory({ query: 'x', sourceId: 'source', tag: 'ignored', page: 1, pageSize: 25 })).rejects.toMatchObject({ code: 'unsupported' })
    expect(invoke).not.toHaveBeenCalled()
  })

  it('forwards an opaque native query cursor and returns the next page', async () => {
    const payloads: Record<string, unknown>[] = []
    const invoke = vi.fn(async (_command: string, arguments_: unknown) => {
      const request = (arguments_ as { request: { method: string; payload: Record<string, unknown> } }).request
      payloads.push(request.payload)
      return nativeReply(request.method, {
        records: [], next_cursor: request.payload.cursor ? null : 'v1.context.25', total: 26, local_only_warning: 'Local only.',
      })
    })
    const transport = new TauriTransport(invoke)

    const first = await transport.searchMemory({ query: 'needle', sourceId: 'source', page: 1, pageSize: 25 })
    const second = await transport.searchMemory({ query: 'needle', sourceId: 'source', page: 2, pageSize: 25, cursor: first.nextCursor })

    expect(payloads).toEqual([
      { sourceId: 'source', namespace: null, text: 'needle', limit: 25 },
      { sourceId: 'source', namespace: null, text: 'needle', limit: 25, cursor: 'v1.context.25' },
    ])
    expect(first.nextCursor).toBe('v1.context.25')
    expect(second.nextCursor).toBeNull()
  })

  it('does not send a stale native query cursor for a new query or source', async () => {
    const invoke = vi.fn(async (_command: string, arguments_: unknown) => {
      const request = (arguments_ as { request: { method: string } }).request
      return nativeReply(request.method, { records: [], next_cursor: 'v1.context.25', total: 30, local_only_warning: 'Local only.' })
    })
    const transport = new TauriTransport(invoke)

    const first = await transport.searchMemory({ query: 'old-query', sourceId: 'source-a', page: 1, pageSize: 25 })
    await expect(transport.searchMemory({ query: 'new-query', sourceId: 'source-b', page: 2, pageSize: 25, cursor: first.nextCursor })).rejects.toMatchObject({ code: 'invalid_request' })
    expect(invoke).toHaveBeenCalledOnce()
  })

  it('rejects a repeated native query cursor instead of looping', async () => {
    const invoke = vi.fn(async (_command: string, arguments_: unknown) => {
      const request = (arguments_ as { request: { method: string } }).request
      return nativeReply(request.method, { records: [], next_cursor: 'v1.context.25', total: 30, local_only_warning: 'Local only.' })
    })
    const transport = new TauriTransport(invoke)
    const first = await transport.searchMemory({ query: 'needle', sourceId: 'source', page: 1, pageSize: 25 })
    await expect(transport.searchMemory({ query: 'needle', sourceId: 'source', page: 2, pageSize: 25, cursor: first.nextCursor })).rejects.toMatchObject({ code: 'protocol_violation' })
  })

  it('rejects a multi-page native query cursor cycle instead of revisiting an earlier offset', async () => {
    const invoke = vi.fn(async (_command: string, arguments_: unknown) => {
      const request = (arguments_ as { request: { method: string; payload: Record<string, unknown> } }).request
      const cursor = request.payload.cursor
      return nativeReply(request.method, {
        records: [],
        next_cursor: cursor === undefined ? 'cursor-2' : cursor === 'cursor-2' ? 'cursor-3' : 'cursor-2',
        total: 100,
        local_only_warning: 'Local only.',
      })
    })
    const transport = new TauriTransport(invoke)
    const page1 = await transport.searchMemory({ query: 'needle', sourceId: 'source', page: 1, pageSize: 25 })
    const page2 = await transport.searchMemory({ query: 'needle', sourceId: 'source', page: 2, pageSize: 25, cursor: page1.nextCursor })
    await expect(transport.searchMemory({ query: 'needle', sourceId: 'source', page: 3, pageSize: 25, cursor: page2.nextCursor })).rejects.toMatchObject({ code: 'protocol_violation' })
  })

  it('revisits earlier native pages with their page-specific cursors', async () => {
    const payloads: Record<string, unknown>[] = []
    const invoke = vi.fn(async (_command: string, arguments_: unknown) => {
      const request = (arguments_ as { request: { method: string; payload: Record<string, unknown> } }).request
      payloads.push(request.payload)
      const cursor = request.payload.cursor
      return nativeReply(request.method, { records: [], next_cursor: cursor === undefined ? 'cursor-2' : cursor === 'cursor-2' ? 'cursor-3' : null, total: 51, local_only_warning: 'Local only.' })
    })
    const transport = new TauriTransport(invoke)
    const page1 = await transport.searchMemory({ query: 'needle', sourceId: 'source', page: 1, pageSize: 25 })
    const page2 = await transport.searchMemory({ query: 'needle', sourceId: 'source', page: 2, pageSize: 25, cursor: page1.nextCursor })
    await transport.searchMemory({ query: 'needle', sourceId: 'source', page: 3, pageSize: 25, cursor: page2.nextCursor })
    await transport.searchMemory({ query: 'needle', sourceId: 'source', page: 2, pageSize: 25, cursor: page1.nextCursor })
    await transport.searchMemory({ query: 'needle', sourceId: 'source', page: 1, pageSize: 25 })
    expect(payloads.map((payload) => payload.cursor)).toEqual([undefined, 'cursor-2', 'cursor-3', 'cursor-2', undefined])
  })

  it('rejects a learned native continuation that disappears on page revisit', async () => {
    let pageTwoCalls = 0
    const invoke = vi.fn(async (_command: string, arguments_: unknown) => {
      const request = (arguments_ as { request: { method: string; payload: Record<string, unknown> } }).request
      const cursor = request.payload.cursor
      if (cursor === 'cursor-2') pageTwoCalls += 1
      return nativeReply(request.method, {
        records: [],
        next_cursor: cursor === undefined ? 'cursor-2' : pageTwoCalls === 1 ? 'cursor-3' : null,
        total: 51,
        local_only_warning: 'Local only.',
      })
    })
    const transport = new TauriTransport(invoke)
    const page1 = await transport.searchMemory({ query: 'needle', sourceId: 'source', page: 1, pageSize: 25 })
    await transport.searchMemory({ query: 'needle', sourceId: 'source', page: 2, pageSize: 25, cursor: page1.nextCursor })

    await expect(transport.searchMemory({ query: 'needle', sourceId: 'source', page: 2, pageSize: 25, cursor: page1.nextCursor })).rejects.toMatchObject({ code: 'protocol_violation' })
  })

  it('rejects a native query total that changes inside one cursor chain', async () => {
    const invoke = vi.fn(async (_command: string, arguments_: unknown) => {
      const request = (arguments_ as { request: { method: string; payload: Record<string, unknown> } }).request
      return nativeReply(request.method, {
        records: [],
        next_cursor: request.payload.cursor ? null : 'cursor-2',
        total: request.payload.cursor ? 50 : 51,
        local_only_warning: 'Local only.',
      })
    })
    const transport = new TauriTransport(invoke)
    const page1 = await transport.searchMemory({ query: 'needle', sourceId: 'source', page: 1, pageSize: 25 })

    await expect(transport.searchMemory({ query: 'needle', sourceId: 'source', page: 2, pageSize: 25, cursor: page1.nextCursor })).rejects.toMatchObject({ code: 'protocol_violation' })
  })

  it('rejects a native source revision that changes inside one cursor chain', async () => {
    const invoke = vi.fn(async (_command: string, arguments_: unknown) => {
      const request = (arguments_ as { request: { method: string; payload: Record<string, unknown> } }).request
      const revision = request.payload.cursor ? 'b'.repeat(64) : 'a'.repeat(64)
      return nativeReply(request.method, {
        records: [{ record_id: 'record-1', namespace: 'default', content: 'bounded', metadata: {}, embedding_present: false, source_revision: revision }],
        next_cursor: request.payload.cursor ? null : 'cursor-2',
        total: 26,
        local_only_warning: 'Local only.',
      })
    })
    const transport = new TauriTransport(invoke)
    const page1 = await transport.searchMemory({ query: 'needle', sourceId: 'source', page: 1, pageSize: 25 })

    await expect(transport.searchMemory({ query: 'needle', sourceId: 'source', page: 2, pageSize: 25, cursor: page1.nextCursor })).rejects.toMatchObject({ code: 'protocol_violation' })
  })

  it('rejects mixed source revisions inside one native query page', async () => {
    const record = (id: string, revision: string) => ({ record_id: id, namespace: 'default', content: 'bounded', metadata: {}, embedding_present: false, source_revision: revision })
    const invoke = vi.fn(async (_command: string, arguments_: unknown) => {
      const request = (arguments_ as { request: { method: string } }).request
      return nativeReply(request.method, {
        records: [record('record-a', 'a'.repeat(64)), record('record-b', 'b'.repeat(64))],
        next_cursor: null,
        total: 2,
        local_only_warning: 'Local only.',
      })
    })

    await expect(new TauriTransport(invoke).searchMemory({ query: 'needle', sourceId: 'source', page: 1, pageSize: 25 })).rejects.toMatchObject({ code: 'protocol_violation' })
  })
})

function nativeReply(method: string, result: Record<string, unknown>) {
  return { requestId: '11111111-1111-4111-8111-111111111111', method, result }
}

function nativeDoctorReply(processActions: boolean) {
  return nativeReply('doctor', {
    healthy: processActions,
    checks: [
      { name: 'method:action.plan', ok: processActions },
      { name: 'method:action.execute', ok: processActions },
    ],
    warnings: processActions ? [] : ['Kernel-stable process binding is unavailable.'],
  })
}

function nativeScanReply(processInstanceId: string) {
  return nativeReply('scan.list', {
    agents: [{ agent_id: 'managed-agent', process_instance_id: processInstanceId, provider: null, project: 'Local', role: 'Worker', state: 'stale', evidence_grade: 'confirmed', confidence: 0.95, reason_codes: ['lease_stale'], explanation: 'Lease is stale.', evidence: [{ code: 'lease_stale', grade: 'confirmed', observed_at: '2026-08-12T21:00:00Z', detail: 'Managed lease is stale.' }], actionable: true, managed: true, pid: 4112, process_name: 'python', os_status: 'running', usage_cost: { availability: 'unknown', amount_usd: null, note: 'Unknown.' } }],
    coverage: { inspected_count: 1, denied_count: 0, vanished_count: 0, malformed_lease_count: 0, lease_file_count: 1, skipped_lease_count: 0, other_user_count: 0, unknown_owner_count: 0, identity_denied_count: 0, complete: true, captured_at: '2026-08-12T21:00:00Z', current_boot_id: 'boot', warnings: [] },
    returned: 1, total: 1,
  })
}

function boundTransportWithExecuteError(processInstanceId: string, error: Record<string, unknown>) {
  return new TauriTransport(vi.fn(async (_command: string, arguments_: unknown) => {
    const request = (arguments_ as { request: { method: string } }).request
    if (request.method === 'doctor') return nativeDoctorReply(true)
    if (request.method === 'scan.list') return nativeScanReply(processInstanceId)
    if (request.method === 'action.plan') return nativeReply(request.method, {
      plan_id: 'plan-bound', digest: 'b'.repeat(64), expires_at: '2026-08-12T22:00:00Z',
      consequences: [], warnings: [], target: { pid: 4112, process_instance_id: processInstanceId, state: 'stale' },
    })
    throw error
  }))
}
