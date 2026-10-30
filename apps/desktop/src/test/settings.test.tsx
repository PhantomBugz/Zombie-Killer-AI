import axe from 'axe-core'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import App from '../App'
import { CommandPalette } from '../components/CommandPalette'
import { SettingsPage } from '../features/settings/SettingsPage'
import { DemoTransport, TransportError } from '../transport'
import { TauriTransport } from '../transport/tauri'

describe('Settings and About', () => {
  it('labels partial native settings without exposing demo-only controls', async () => {
    const invoke = vi.fn().mockResolvedValue({
      requestId: '11111111-1111-4111-8111-111111111111', method: 'settings.get',
      result: { settings: { scan_interval_seconds: 30, heartbeat_grace_seconds: 120, retention_days: 30, include_unmanaged_candidates: true, appearance: 'system', reduced_motion: false }, revision: 1 },
    })
    render(<SettingsPage transport={new TauriTransport(invoke)} />)

    expect(await screen.findByText('LOCAL ENGINE')).not.toBeNull()
    expect(screen.getByText(/Native capability/)).not.toBeNull()
    expect(screen.getByText(/Detection presets are not exposed/)).not.toBeNull()
    expect(screen.getByText(/local engine did not confirm a kernel-stable process binding/i)).not.toBeNull()
    expect(screen.getByText('Stored engine scan interval')).not.toBeNull()
    expect(screen.queryByText('LOCAL DEMO')).toBeNull()
  })

  it('uses revisioned bounded updates, presets, theme, and reset defaults', async () => {
    const user = userEvent.setup()
    const demo = new DemoTransport({ latencyMs: 0 })
    render(<SettingsPage transport={demo} />)
    expect(await screen.findByRole('heading', { name: 'Settings' })).not.toBeNull()
    await user.selectOptions(screen.getByLabelText('Detection preset'), 'Aggressive')
    expect(await screen.findByText(/3 corroborating signals/i)).not.toBeNull()
    await user.selectOptions(screen.getByLabelText('Theme'), 'light')
    expect(document.documentElement.dataset.theme).toBe('light')
    await user.click(screen.getByRole('button', { name: 'Reset defaults' }))
    expect((screen.getByLabelText('Detection preset') as HTMLSelectElement).value).toBe('Balanced')
  })

  it('states exact privacy, attribution, version, license, and donations', async () => {
    const { container } = render(<SettingsPage transport={new DemoTransport({ latencyMs: 0 })} />)
    expect(await screen.findByText('Made by PhantomBugz')).not.toBeNull()
    expect(screen.getByText('Zombie Killer mark by PhantomBugz · CC BY 4.0')).not.toBeNull()
    expect(container.innerHTML).not.toMatch(/Created by/i)
    expect(screen.getByText('0.1.0-alpha.1')).not.toBeNull()
    expect(screen.getByText('Apache-2.0')).not.toBeNull()
    for (const value of [
      '0x34566329186f1ec2498017879fB362d8071B28e5',
      'bc1q24vhcxytz7fwaqllrwjf6vjmkx795c92t7q4q6',
      'GoGJqR6AP9ERZkx2UksDH9rFV8ysYoKVXJRGExvs6j7S',
    ]) expect(screen.getByText(value)).not.toBeNull()
    expect(screen.getByText(/unlock nothing/i)).not.toBeNull()
    expect(screen.getByText(/never share a seed phrase or private key/i)).not.toBeNull()
    expect(screen.queryByLabelText(/api key|provider key/i)).toBeNull()
  })

  it('opens an accessible keyboard command palette that only navigates', async () => {
    const user = userEvent.setup()
    const { container } = render(<App />)
    await user.keyboard('{Control>}k{/Control}')
    const dialog = screen.getByRole('dialog', { name: 'Command palette' })
    expect(dialog).not.toBeNull()
    expect(screen.getByRole('listbox', { name: 'Commands' })).not.toBeNull()
    await user.keyboard('{End}{Enter}')
    await screen.findByLabelText('Theme')
    const heading = await screen.findByRole('heading', { name: 'Settings' })
    await waitFor(() => expect(document.activeElement).toBe(heading))
    expect(screen.queryByRole('button', { name: /execute|apply|purge/i })).toBeNull()
    expect((await axe.run(container, { rules: { 'color-contrast': { enabled: false } } })).violations).toEqual([])
  })

  it('uses native command-palette copy without demo fixture names', () => {
    const view = render(<CommandPalette
      mode="native"
      onClose={() => undefined}
      onNavigate={() => undefined}
      restoreFocusRef={{ current: document.body as HTMLElement | null }}
    />)

    expect(screen.getByText('Review local-engine coverage; no action is executed')).not.toBeNull()
    expect(screen.getByText('Registered local sources and reviewed scalar repair')).not.toBeNull()
    expect(view.container.textContent).not.toMatch(/Mev BOT|MTGA Cardbot|demo coverage|Demo lab/i)
  })

  it('keeps palette navigation focus on the durable Settings heading after async loading', async () => {
    const user = userEvent.setup()
    render(<App />)
    await user.keyboard('{Control>}k{/Control}')
    await user.keyboard('{End}{Enter}')
    await screen.findByLabelText('Theme')
    const heading = screen.getByRole('heading', { name: 'Settings' })
    await waitFor(() => expect(document.activeElement).toBe(heading))
    expect(document.activeElement).not.toBe(document.body)
  })

  it('restores keyboard-opened palette focus to the exact active input', async () => {
    const user = userEvent.setup()
    render(<App />)
    await user.click(screen.getByRole('link', { name: 'Memory Vault' }))
    const search = await screen.findByRole('searchbox', { name: 'Search memory' })
    await waitFor(() => expect(search.hasAttribute('disabled')).toBe(false))
    search.focus()
    expect(document.activeElement).toBe(search)
    await user.keyboard('{Control>}k{/Control}')
    expect(screen.getByRole('dialog', { name: 'Command palette' })).not.toBeNull()
    await user.keyboard('{Escape}')
    expect(document.activeElement).toBe(search)
  })

  it('serializes rapid settings updates against the latest persisted revision', async () => {
    const user = userEvent.setup()
    const demo = new DemoTransport({ latencyMs: 15 })
    render(<SettingsPage transport={demo} />)
    await user.selectOptions(await screen.findByLabelText('Detection preset'), 'Aggressive')
    await user.selectOptions(screen.getByLabelText('Theme'), 'light')
    expect(await screen.findByText('All local settings saved.')).not.toBeNull()
    const persisted = await demo.getSettings()
    expect(persisted.detectionPreset).toBe('Aggressive')
    expect(persisted.theme).toBe('light')
    expect(document.documentElement.dataset.theme).toBe('light')
    expect(screen.queryByRole('alert')).toBeNull()
  })

  it('replays queued intent B against the reconciled revision after conflict A', async () => {
    const calls: Array<{ expectedRevision: number; changes: Record<string, unknown> }> = []
    let first = true
    let releaseFirst: (() => void) | undefined
    class ConflictQueueTransport extends DemoTransport {
      override async updateSettings(request: Parameters<DemoTransport['updateSettings']>[0]): ReturnType<DemoTransport['updateSettings']> {
        calls.push(request as { expectedRevision: number; changes: Record<string, unknown> })
        if (first) {
          first = false
          await new Promise<void>((resolve) => { releaseFirst = resolve })
          await super.updateSettings({ expectedRevision: request.expectedRevision, changes: { theme: 'dark' } })
          throw new TransportError('conflict', 'Settings revision changed.')
        }
        return super.updateSettings(request)
      }
    }
    const demo = new ConflictQueueTransport({ latencyMs: 0 })
    const user = userEvent.setup()
    render(<SettingsPage transport={demo} />)
    const theme = await screen.findByLabelText('Theme')
    await user.selectOptions(theme, 'light')
    await user.selectOptions(await screen.findByLabelText('Motion'), 'reduce')
    releaseFirst?.()
    await waitFor(() => expect(calls).toHaveLength(3))
    expect(calls[1]).toEqual({ expectedRevision: 2, changes: { theme: 'light' } })
    expect(calls[2]).toEqual({ expectedRevision: 3, changes: { motion: 'reduce' } })
    expect((await demo.getSettings()).theme).toBe('light')
    expect((await demo.getSettings()).motion).toBe('reduce')
  })

  it('keeps retried intent A and queued intent B visible while B is still in flight', async () => {
    const calls: Array<{ expectedRevision: number; changes: Record<string, unknown> }> = []
    let releaseFirst: (() => void) | undefined
    let releaseSecond: (() => void) | undefined
    let first = true
    class GatedConflictQueueTransport extends DemoTransport {
      override async updateSettings(request: Parameters<DemoTransport['updateSettings']>[0]): ReturnType<DemoTransport['updateSettings']> {
        calls.push(request as { expectedRevision: number; changes: Record<string, unknown> })
        if (first) {
          first = false
          await new Promise<void>((resolve) => { releaseFirst = resolve })
          await super.updateSettings({ expectedRevision: request.expectedRevision, changes: { theme: 'dark' } })
          throw new TransportError('conflict', 'Settings revision changed.')
        }
        if (request.changes.motion === 'reduce') await new Promise<void>((resolve) => { releaseSecond = resolve })
        return super.updateSettings(request)
      }
    }
    const demo = new GatedConflictQueueTransport({ latencyMs: 0 })
    const user = userEvent.setup()
    render(<SettingsPage transport={demo} />)
    const theme = await screen.findByLabelText('Theme') as HTMLSelectElement
    const motion = screen.getByLabelText('Motion') as HTMLSelectElement

    await user.selectOptions(theme, 'light')
    await user.selectOptions(motion, 'reduce')
    releaseFirst?.()

    await waitFor(() => expect(calls).toHaveLength(3))
    await waitFor(() => expect(releaseSecond).toBeTypeOf('function'))
    expect(theme.value).toBe('light')
    expect(motion.value).toBe('reduce')
    expect(screen.getByText('Saving local settings…')).not.toBeNull()
    expect(screen.queryByRole('alert')).toBeNull()

    releaseSecond?.()
    expect(await screen.findByText('All local settings saved.')).not.toBeNull()
    expect(await demo.getSettings()).toMatchObject({ theme: 'light', motion: 'reduce', revision: 4 })
  })

  it('recognizes conflict intent A as complete when the reconciled durable value already matches', async () => {
    const calls: Array<{ expectedRevision: number; changes: Record<string, unknown> }> = []
    let releaseFirst: (() => void) | undefined
    let first = true
    class AlreadyAppliedConflictTransport extends DemoTransport {
      override async updateSettings(request: Parameters<DemoTransport['updateSettings']>[0]) {
        calls.push(request as { expectedRevision: number; changes: Record<string, unknown> })
        if (first) {
          first = false
          await new Promise<void>((resolve) => { releaseFirst = resolve })
          await super.updateSettings(request)
          throw new TransportError('conflict', 'Settings revision changed after the write became durable.')
        }
        return super.updateSettings(request)
      }
    }
    const demo = new AlreadyAppliedConflictTransport({ latencyMs: 0 })
    const user = userEvent.setup()
    render(<SettingsPage transport={demo} />)
    await user.selectOptions(await screen.findByLabelText('Theme'), 'light')
    await user.selectOptions(await screen.findByLabelText('Motion'), 'reduce')
    releaseFirst?.()

    await waitFor(() => expect(calls).toHaveLength(2))
    expect(calls[0]).toEqual({ expectedRevision: 1, changes: { theme: 'light' } })
    expect(calls[1]).toEqual({ expectedRevision: 2, changes: { motion: 'reduce' } })
    expect(await demo.getSettings()).toMatchObject({ theme: 'light', motion: 'reduce', revision: 3 })
    expect(screen.queryByRole('alert')).toBeNull()
  })

  it('blocks queued settings writes when conflict reconciliation fails', async () => {
    const calls: Array<Record<string, unknown>> = []
    let getCount = 0
    let releaseFirst: (() => void) | undefined
    class UnavailableReconciliationTransport extends DemoTransport {
      override async getSettings() {
        getCount += 1
        if (getCount > 1) throw new Error('Settings database is unavailable.')
        return super.getSettings()
      }
      override async updateSettings(request: Parameters<DemoTransport['updateSettings']>[0]): ReturnType<DemoTransport['updateSettings']> {
        calls.push(request as Record<string, unknown>)
        await new Promise<void>((resolve) => { releaseFirst = resolve })
        throw new TransportError('conflict', 'Settings revision changed.')
      }
    }
    const user = userEvent.setup()
    render(<SettingsPage transport={new UnavailableReconciliationTransport({ latencyMs: 0 })} />)
    const theme = await screen.findByLabelText('Theme')
    await user.selectOptions(theme, 'light')
    await user.selectOptions(await screen.findByLabelText('Motion'), 'reduce')
    releaseFirst?.()
    expect(await screen.findByRole('alert')).not.toBeNull()
    await waitFor(() => expect(calls).toHaveLength(1))
    expect((screen.getByLabelText('Motion') as HTMLSelectElement).value).toBe('system')
  })

  it('keeps A and queued B blocked when the exact conflict retry also fails', async () => {
    const calls: Array<{ expectedRevision: number; changes: Record<string, unknown> }> = []
    let releaseFirst: (() => void) | undefined
    let first = true
    class PermanentConflictTransport extends DemoTransport {
      override async updateSettings(request: Parameters<DemoTransport['updateSettings']>[0]): ReturnType<DemoTransport['updateSettings']> {
        calls.push(request as { expectedRevision: number; changes: Record<string, unknown> })
        if (first) {
          first = false
          await new Promise<void>((resolve) => { releaseFirst = resolve })
          await super.updateSettings({ expectedRevision: request.expectedRevision, changes: { theme: 'dark' } })
        }
        throw new TransportError('conflict', 'Settings revision changed.')
      }
    }
    const demo = new PermanentConflictTransport({ latencyMs: 0 })
    const user = userEvent.setup()
    render(<SettingsPage transport={demo} />)
    await user.selectOptions(await screen.findByLabelText('Theme'), 'light')
    await user.selectOptions(await screen.findByLabelText('Motion'), 'reduce')
    releaseFirst?.()
    expect(await screen.findByRole('alert')).not.toBeNull()
    await waitFor(() => expect(calls).toHaveLength(2))
    const retry = screen.getByRole('button', { name: 'Reload settings and retry pending changes' })
    await waitFor(() => expect(document.activeElement).toBe(retry))
    expect(calls[1]).toEqual({ expectedRevision: 2, changes: { theme: 'light' } })
    expect(calls.some((call) => 'motion' in call.changes)).toBe(false)
    expect((await demo.getSettings()).theme).toBe('dark')
    expect((screen.getByLabelText('Motion') as HTMLSelectElement).value).toBe('system')
    await user.click(retry)
    await waitFor(() => expect(calls).toHaveLength(4))
    expect(calls.some((call) => 'motion' in call.changes)).toBe(false)
  })

  it('does not replay a non-conflict or uncertain settings failure', async () => {
    const calls: Array<Record<string, unknown>> = []
    let first = true
    class UncertainTransport extends DemoTransport {
      override async updateSettings(request: Parameters<DemoTransport['updateSettings']>[0]) {
        calls.push(request as Record<string, unknown>)
        if (first) {
          first = false
          throw new TransportError('outcome_uncertain', 'Settings write outcome is uncertain.')
        }
        return super.updateSettings(request)
      }
    }
    const demo = new UncertainTransport({ latencyMs: 0 })
    const user = userEvent.setup()
    render(<SettingsPage transport={demo} />)
    await user.selectOptions(await screen.findByLabelText('Theme'), 'light')
    expect(await screen.findByRole('alert')).not.toBeNull()
    expect(calls).toHaveLength(1)
    expect((screen.getByLabelText('Theme') as HTMLSelectElement).value).toBe('system')
    expect(screen.queryByRole('button', { name: 'Reload settings and retry pending changes' })).toBeNull()
    const discard = screen.getByRole('button', { name: 'Reload durable settings and discard pending changes' })
    await waitFor(() => expect(document.activeElement).toBe(discard))
    await user.click(discard)
    await waitFor(() => expect(screen.queryByRole('alert')).toBeNull())
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole('heading', { name: 'Settings' })))
    expect(calls).toHaveLength(1)
    await user.selectOptions(screen.getByLabelText('Theme'), 'light')
    await waitFor(() => expect(calls).toHaveLength(2))
    expect(await demo.getSettings()).toMatchObject({ theme: 'light', revision: 2 })
  })

  it('maps native update and reset payloads onto the latest persisted revision', async () => {
    const firstRevision = 3
    const updatedRevision = 4
    const resetRevision = 5
    let revision = firstRevision
    let state = {
      scan_interval_seconds: 30,
      heartbeat_grace_seconds: 120,
      retention_days: 30,
      include_unmanaged_candidates: true,
      appearance: 'system',
      reduced_motion: false,
    }
    const updatePayloads: Record<string, unknown>[] = []
    const invoke = vi.fn(async (_command: string, arguments_: unknown) => {
      const request = (arguments_ as { request: { method: string; payload: Record<string, unknown> } }).request
      if (request.method === 'doctor') return { requestId: '11111111-1111-4111-8111-111111111111', method: request.method, result: { healthy: true, checks: [{ name: 'method:settings.update', ok: true }], warnings: [] } }
      if (request.method === 'settings.get') return {
        requestId: '11111111-1111-4111-8111-111111111111', method: request.method, result: { settings: state, revision },
      }
      if (request.method !== 'settings.update') throw new Error(`Unexpected native method: ${request.method}`)
      updatePayloads.push(request.payload)
      const changes = request.payload.changes as Record<string, unknown>
      state = {
        scan_interval_seconds: changes.scanIntervalSeconds as number ?? state.scan_interval_seconds,
        heartbeat_grace_seconds: changes.heartbeatGraceSeconds as number ?? state.heartbeat_grace_seconds,
        retention_days: changes.retentionDays as number ?? state.retention_days,
        include_unmanaged_candidates: changes.includeUnmanagedCandidates as boolean ?? state.include_unmanaged_candidates,
        appearance: changes.appearance as string ?? state.appearance,
        reduced_motion: changes.reducedMotion as boolean ?? state.reduced_motion,
      }
      revision = revision === firstRevision ? updatedRevision : resetRevision
      return {
        requestId: revision === updatedRevision ? '22222222-2222-4222-8222-222222222222' : '33333333-3333-4333-8333-333333333333',
        method: request.method, result: { settings: state, revision },
      }
    })
    const user = userEvent.setup()
    render(<SettingsPage transport={new TauriTransport(invoke)} />)

    await user.selectOptions(await screen.findByLabelText('Theme'), 'dark')
    await waitFor(() => expect(updatePayloads).toHaveLength(1))
    expect(updatePayloads[0]).toEqual({ expectedRevision: firstRevision, changes: { appearance: 'dark' } })
    expect(await screen.findByText('All local settings saved.')).not.toBeNull()

    await user.click(screen.getByRole('button', { name: 'Reset defaults' }))
    await waitFor(() => expect(updatePayloads).toHaveLength(2))
    expect(updatePayloads[1]).toEqual({
      expectedRevision: updatedRevision,
      changes: {
        appearance: 'system', reducedMotion: false, scanIntervalSeconds: 30,
        retentionDays: 30, heartbeatGraceSeconds: 120, includeUnmanagedCandidates: true,
      },
    })
    await waitFor(() => expect((screen.getByLabelText('Theme') as HTMLSelectElement).value).toBe('system'))
  })

  it('refreshes durable settings after a reset revision conflict', async () => {
    const user = userEvent.setup()
    const demo = new DemoTransport({ latencyMs: 0 })
    render(<SettingsPage transport={demo} />)
    await screen.findByRole('heading', { name: 'Settings' })
    await demo.updateSettings({ expectedRevision: 1, changes: { theme: 'dark' } })
    await user.click(screen.getByRole('button', { name: 'Reset defaults' }))
    await waitFor(() => expect((screen.getByLabelText('Theme') as HTMLSelectElement).value).toBe('system'))
    expect(screen.queryByRole('alert')).toBeNull()
  })

  it('reloads native settings after a CAS conflict and keeps the durable conflict visible', async () => {
    let getCount = 0
    const initial = { scan_interval_seconds: 30, heartbeat_grace_seconds: 120, retention_days: 30, include_unmanaged_candidates: true, appearance: 'system', reduced_motion: false }
    const fresh = { ...initial, appearance: 'dark' }
    const invoke = vi.fn(async (_command: string, arguments_: unknown) => {
      const request = (arguments_ as { request: { method: string } }).request
      if (request.method === 'doctor') return { requestId: '11111111-1111-4111-8111-111111111111', method: request.method, result: { healthy: true, checks: [{ name: 'method:settings.update', ok: true }], warnings: [] } }
      if (request.method === 'settings.get') {
        getCount += 1
        return { requestId: `${getCount}`.padStart(8, '0') + '-1111-4111-8111-111111111111', method: request.method, result: { settings: getCount === 1 ? initial : fresh, revision: getCount === 1 ? 8 : 9 } }
      }
      throw { code: 'conflict', message: 'Settings revision changed.', reason: 'settings_revision_mismatch' }
    })
    const user = userEvent.setup()
    render(<SettingsPage transport={new TauriTransport(invoke)} />)
    await user.selectOptions(await screen.findByLabelText('Theme'), 'light')

    expect(await screen.findByRole('alert')).not.toBeNull()
    await waitFor(() => expect((screen.getByLabelText('Theme') as HTMLSelectElement).value).toBe('dark'))
    expect(getCount).toBe(2)
  })

  it('offers a focused retry after initial settings failure and moves focus to the durable heading after recovery', async () => {
    class InitiallyUnavailableSettings extends DemoTransport {
      attempts = 0
      override async getSettings() {
        this.attempts += 1
        if (this.attempts === 1) throw new Error('Settings database is temporarily unavailable.')
        return super.getSettings()
      }
    }
    const user = userEvent.setup()
    render(<SettingsPage transport={new InitiallyUnavailableSettings({ latencyMs: 0 })} />)

    const retry = await screen.findByRole('button', { name: 'Retry settings' })
    expect(screen.getByRole('alert').textContent).toMatch(/temporarily unavailable/i)
    await waitFor(() => expect(document.activeElement).toBe(retry))
    await user.click(retry)
    const heading = await screen.findByRole('heading', { name: 'Settings' })
    await waitFor(() => expect(document.activeElement).toBe(heading))
  })

  it('rejects invalid and ineffective settings changes without revision bumps', async () => {
    const demo = new DemoTransport({ latencyMs: 0 })
    const before = await demo.getSettings()
    for (const changes of [[], {}, { theme: before.theme }, { denseMode: 'yes' }, { unknown: true }]) {
      await expect(demo.updateSettings({ expectedRevision: before.revision, changes } as never)).rejects.toMatchObject({ code: 'schema_invalid' })
      expect((await demo.getSettings()).revision).toBe(before.revision)
    }
  })
})
