import axe from 'axe-core'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import { ActivityPage } from '../features/activity/ActivityPage'
import { buildSanitizedExport, copyText } from '../features/activity/export'
import { redactSensitiveText, safeDisplayValue, sanitizeForExport, truncateSafeText } from '../features/activity/redaction'
import { DemoTransport, TransportError } from '../transport'
import { TauriTransport } from '../transport/tauri'

function punctuationDelimitedUrlPathFixtures() {
  const remoteUrl = ['https:', '', 'example.test', 'safe'].join('/')
  const posixPaths = [
    ['', 'private', 'pipe-fixture.json'].join('/'),
    ['', 'opt', 'semicolon-fixture.json'].join('/'),
    ['', 'var', 'comma-fixture.json'].join('/'),
    ['', 'tmp', 'paren-fixture.json'].join('/'),
  ]
  const windowsPaths = [
    ['C:', 'Fixture User', 'pipe-cache.db'].join('\\'),
    ['D:', 'Fixture Data', 'semicolon-cache.db'].join('\\'),
    ['E:', 'Fixture Cache', 'comma-cache.db'].join('\\'),
    ['F:', 'Fixture Temp', 'paren-cache.db'].join('\\'),
  ]
  const composites = ['|', ';', ',', ')'].flatMap((delimiter, index) => [
    `${remoteUrl}${delimiter}${posixPaths[index]}`,
    `${remoteUrl}${delimiter}${windowsPaths[index]}`,
  ])
  return { composites, localPaths: [...posixPaths, ...windowsPaths] }
}

describe('Activity and Graveyard', () => {
  it('renders native activity as partial read-only data without demo claims or restore controls', async () => {
    let quarantinePage = 0
    const invoke = vi.fn(async (_command: string, arguments_: unknown) => {
      const request = (arguments_ as { request: { method: string; payload: Record<string, unknown> } }).request
      const method = request.method
      if (method === 'doctor') return { requestId: '11111111-1111-4111-8111-111111111111', method, result: { healthy: true, checks: [{ name: 'method:activity.list', ok: true }, { name: 'method:quarantine.list', ok: true }], warnings: [] } }
      if (method === 'activity.list') return {
        requestId: '11111111-1111-4111-8111-111111111111', method,
        result: { receipts: [{ receipt_id: 'receipt-native', plan_id: 'plan-native', outcome: 'completed', certainty: 'verified', action_issued: true, partial_failures: ['Cleanup verification failed.'], created_at: '2026-08-12T20:00:00Z' }], next_cursor: null },
      }
      quarantinePage += 1
      return {
        requestId: '11111111-1111-4111-8111-111111111111', method,
        result: {
          entries: quarantinePage === 1 ? [{ entry_id: 'entry-native', agent_id: 'agent-native', resource_type: 'file', state: 'partial', restorable: true, created_at: '2026-08-12T20:00:00Z', updated_at: '2026-08-12T20:01:00Z' }] : [],
          next_cursor: 'repeated-cursor',
        },
      }
    })
    render(<ActivityPage transport={new TauriTransport(invoke)} />)

    expect(await screen.findByText('LOCAL ENGINE · PARTIAL')).not.toBeNull()
    expect(screen.getByText(/Read-only native activity/)).not.toBeNull()
    expect(screen.queryByText('DEMO DATA')).toBeNull()
    expect(screen.getByText(/Diagnostics export is unavailable/)).not.toBeNull()
    await userEvent.click(screen.getByRole('tab', { name: 'Receipts' }))
    const nativeReceipt = screen.getByRole('tabpanel')
    expect(within(nativeReceipt).getByText('Containment partially completed')).not.toBeNull()
    expect(within(nativeReceipt).getByText('Partial', { selector: 'dd' })).not.toBeNull()
    expect(within(nativeReceipt).getByText('Cleanup verification failed.')).not.toBeNull()
    expect(within(nativeReceipt).getAllByText('Not reported', { selector: 'dd' }).length).toBeGreaterThan(0)
    await userEvent.click(screen.getByRole('tab', { name: 'Quarantine' }))
    expect(await screen.findByText('Partial', { selector: 'dd' })).not.toBeNull()
    expect(screen.getByText('agent-native', { selector: 'dd' })).not.toBeNull()
    expect(screen.getByText('file', { selector: 'dd' })).not.toBeNull()
    expect(screen.getByText('2026-08-12T20:00:00Z', { selector: 'dd' })).not.toBeNull()
    expect(screen.getByRole('alert').textContent).toMatch(/quarantine.*truncated/i)
    expect(screen.getAllByText('Not reported', { selector: 'option' }).length).toBeGreaterThan(0)
    expect(screen.queryByRole('button', { name: 'Review restore' })).toBeNull()
  })

  it('uses the shared trapped dialog and restores the exact Graveyard opener', async () => {
    const user = userEvent.setup()
    const { container } = render(<ActivityPage transport={new DemoTransport({ latencyMs: 0 })} />)
    await user.click(await screen.findByRole('tab', { name: 'Quarantine' }))
    const opener = screen.getAllByRole('button', { name: 'Review restore' })[0]!
    await user.click(opener)
    expect(document.activeElement).toBe(await screen.findByRole('heading', { name: 'Review quarantine restore' }))
    expect((await axe.run(container, { rules: { 'color-contrast': { enabled: false } } })).violations).toEqual([])
    await user.keyboard('{Escape}')
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(document.activeElement).toBe(opener)
  })

  it('shows containment receipts and restores exact quarantined entries without overwrite', async () => {
    const user = userEvent.setup()
    const demo = new DemoTransport({ latencyMs: 0 })
    const plan = await demo.planAction({ agentId: 'mev-screenshot', kind: 'graceful-stop', target: { pid: 4188, processInstanceId: '1'.repeat(64) } })
    await demo.executeAction({ planId: plan.planId, digest: plan.digest })
    render(<ActivityPage transport={demo} />)
    await user.click(await screen.findByRole('tab', { name: 'Receipts' }))
    expect(screen.getAllByText('Containment complete').length).toBeGreaterThan(0)
    await user.click(screen.getByRole('tab', { name: 'Quarantine' }))
    expect(await screen.findByText('frame-014.png')).not.toBeNull()
    await user.click(screen.getAllByRole('button', { name: 'Review restore' })[0]!)
    expect(screen.getByText(/digest/i)).not.toBeNull()
    await user.click(screen.getByRole('button', { name: 'Restore exact entry' }))
    expect(await screen.findByText('Restored', { selector: 'dd' })).not.toBeNull()
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole('heading', { name: 'Activity' })))
    expect(screen.queryByRole('button', { name: /purge/i })).toBeNull()
  })

  it('filters events and exports only the documented sanitized fields', async () => {
    const user = userEvent.setup()
    render(<ActivityPage transport={new DemoTransport({ latencyMs: 0 })} />)
    const search = await screen.findByRole('searchbox', { name: /activity/i })
    await user.type(search, 'heartbeat')
    expect(screen.getByText('Heartbeat missed')).not.toBeNull()
    const payload = buildSanitizedExport((await new DemoTransport({ latencyMs: 0 }).getActivity()).events, 'jsonl')
    expect(payload).toContain('correlationId')
    expect(payload).not.toMatch(/api[_-]?key|bearer |c:\\/i)
  })

  it('filters activity by actor and date as well as search', async () => {
    const user = userEvent.setup()
    render(<ActivityPage transport={new DemoTransport({ latencyMs: 0, now: () => new Date('2026-08-12T18:00:00.000Z') })} />)
    const actor = await screen.findByLabelText('Actor')
    await user.selectOptions(actor, 'Local user')
    expect(screen.getByText('Containment complete')).not.toBeNull()
    await user.type(screen.getByLabelText('Date'), '2026-08-11')
    expect(screen.queryByText('Containment complete')).toBeNull()
  })

  it('keeps memory change receipts in the same durable receipt ledger', async () => {
    const user = userEvent.setup()
    const demo = new DemoTransport({ latencyMs: 0 })
    const record = (await demo.searchMemory({ query: 'card-0001', page: 1, pageSize: 10 })).records[0]!
    const plan = await demo.planMemoryChange({ sourceId: record.sourceId, recordId: record.id, operation: 'exclude', expectedSourceRevision: 4, expectedRecordRevision: record.revision, changes: {} })
    const receipt = await demo.executeMemoryChange({ planId: plan.planId, digest: plan.digest })
    render(<ActivityPage transport={demo} />)
    await user.click(await screen.findByRole('tab', { name: 'Receipts' }))
    expect(screen.getByText(receipt.receiptId)).not.toBeNull()
    expect(screen.getByText('Memory exclude')).not.toBeNull()
  })

  it('reports clipboard fallback truthfully', async () => {
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: undefined })
    expect(await copyText('safe preview')).toBe(false)
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: vi.fn().mockResolvedValue(undefined) } })
    expect(await copyText('safe preview')).toBe(true)
  })

  it('redacts JWT, bearer, named secrets, URL credentials, and paths from exports', () => {
    const event = {
      id: 'unsafe', timestamp: '2026-08-12T18:00:00.000Z', actor: 'Bearer abc.def.ghi client_secret=synthetic-ultrahush', project: 'api_key=synthetic-super-secret',
      target: ['https:/', '/user:pass@example.test/a'].join(''), action: 'C:\\Users\\demo\\secret.txt', result: 'Succeeded' as const,
      correlationId: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signaturefixture', detail: 'private_key=synthetic-hush',
    }
    const payload = buildSanitizedExport([event], 'jsonl')
    expect(payload).toContain('[REDACTED]')
    expect(payload).not.toMatch(/abc\.def\.ghi|super-secret|ultrahush|user:pass|Users\\demo|eyJhbGci|hush/i)
  })

  it('redacts protocol-relative user-info on every export surface', () => {
    const syntheticUserInfo = ['fixture-user', 'fixture-pass'].join(':')
    const protocolRelativeUrl = ['', '', `${syntheticUserInfo}@example.test`, 'safe'].join('/')
    const expectedRemote = '//[REDACTED]@example.test/safe'

    expect(redactSensitiveText(protocolRelativeUrl)).toBe(expectedRemote)
    expect(sanitizeForExport({ protocolRelativeUrl })).toEqual({ protocolRelativeUrl: expectedRemote })
    expect(safeDisplayValue({ oldValue: protocolRelativeUrl })).toBe(`{"oldValue":"${expectedRemote}"}`)

    const event = {
      id: 'url-user-info', timestamp: '2026-08-12T18:00:00.000Z', actor: protocolRelativeUrl,
      project: 'Demo', target: 'local', action: 'Inspect', result: 'Succeeded' as const,
      correlationId: 'correlation-url-user-info', detail: '',
    }
    for (const format of ['jsonl', 'csv'] as const) {
      const exported = buildSanitizedExport([event], format)
      expect(exported).toContain('[REDACTED]@example.test/safe')
      expect(exported).not.toContain(syntheticUserInfo)
    }
  })

  it('redacts username-only user-info in supported remote URLs while preserving ordinary email text', () => {
    const username = ['fixture', 'user'].join('-')
    const samples = [
      { value: ['http:', '', `${username}@example.test`, 'safe'].join('/'), expected: ['http:', '', '[REDACTED]@example.test', 'safe'].join('/') },
      { value: ['https:', '', `${username}@example.test`, 'safe'].join('/'), expected: ['https:', '', '[REDACTED]@example.test', 'safe'].join('/') },
      { value: ['ftp:', '', `${username}@files.example.test`, 'pub'].join('/'), expected: ['ftp:', '', '[REDACTED]@files.example.test', 'pub'].join('/') },
      { value: ['', '', `${username}@example.test`, 'safe'].join('/'), expected: ['', '', '[REDACTED]@example.test', 'safe'].join('/') },
      { value: ['https:', '', ':fixture-pass@example.test', 'safe'].join('/'), expected: ['https:', '', '[REDACTED]@example.test', 'safe'].join('/') },
      { value: ['', '', ':fixture-pass@example.test', 'safe'].join('/'), expected: ['', '', '[REDACTED]@example.test', 'safe'].join('/') },
      { value: ['https:', '', `${username}:@example.test`, 'safe'].join('/'), expected: ['https:', '', '[REDACTED]@example.test', 'safe'].join('/') },
      { value: ['', '', `${username}:@example.test`, 'safe'].join('/'), expected: ['', '', '[REDACTED]@example.test', 'safe'].join('/') },
      { value: ['https:', '', `${username}%3Afixture-pass@example.test`, 'safe'].join('/'), expected: ['https:', '', '[REDACTED]@example.test', 'safe'].join('/') },
      { value: ['', '', `${username}%3Afixture-pass@example.test`, 'safe'].join('/'), expected: ['', '', '[REDACTED]@example.test', 'safe'].join('/') },
    ]
    for (const sample of samples) expect(redactSensitiveText(sample.value)).toBe(sample.expected)

    const safeValues = [
      `${username}@example.test`,
      `Contact ${username}@example.test for support`,
      ['https:', '', 'example.test', 'safe'].join('/'),
      ['', '', 'example.test', 'safe'].join('/'),
    ]
    for (const value of safeValues) expect(redactSensitiveText(value)).toBe(value)
  })

  it('redacts username-only URL user-info from nested, Memory-preview, JSONL, and CSV surfaces', () => {
    const username = ['fixture', 'user'].join('-')
    const values = [
      ['http:', '', `${username}@example.test`, 'safe'].join('/'),
      ['https:', '', `${username}@example.test`, 'safe'].join('/'),
      ['ftp:', '', `${username}@files.example.test`, 'pub'].join('/'),
      ['', '', `${username}@example.test`, 'safe'].join('/'),
    ]
    const expected = [
      ['http:', '', '[REDACTED]@example.test', 'safe'].join('/'),
      ['https:', '', '[REDACTED]@example.test', 'safe'].join('/'),
      ['ftp:', '', '[REDACTED]@files.example.test', 'pub'].join('/'),
      ['', '', '[REDACTED]@example.test', 'safe'].join('/'),
    ]
    expect(sanitizeForExport({ values })).toEqual({ values: expected })
    for (let index = 0; index < values.length; index += 1) {
      expect(safeDisplayValue({ oldValue: values[index] })).toBe(`{"oldValue":"${expected[index]}"}`)
    }

    const events = values.map((actor, index) => ({
      id: `url-username-${index}`, timestamp: '2026-08-12T18:00:00.000Z', actor,
      project: 'Demo', target: 'local', action: 'Inspect', result: 'Succeeded' as const,
      correlationId: `correlation-url-username-${index}`, detail: '',
    }))
    for (const format of ['jsonl', 'csv'] as const) {
      const exported = buildSanitizedExport(events, format)
      expect((exported.match(/\[REDACTED\]@/g) ?? [])).toHaveLength(values.length)
      expect(exported).not.toContain(username)
    }
  })

  it('redacts raw multi-at URL user-info through the last authority delimiter', () => {
    const first = ['fixture', 'user'].join('-')
    const remainder = ['realm', 'fixture-pass'].join(':')
    const inputs = [
      ['https:', '', `${first}@${remainder}@example.test`, 'safe'].join('/'),
      ['', '', `${first}@${remainder}@example.test`, 'safe'].join('/'),
      ['https:', '', `${first}%40realm:fixture-pass@example.test`, 'safe'].join('/'),
      ['', '', `${first}%40realm:fixture-pass@example.test`, 'safe'].join('/'),
    ]
    const expected = [
      ['https:', '', '[REDACTED]@example.test', 'safe'].join('/'),
      ['', '', '[REDACTED]@example.test', 'safe'].join('/'),
      ['https:', '', '[REDACTED]@example.test', 'safe'].join('/'),
      ['', '', '[REDACTED]@example.test', 'safe'].join('/'),
    ]
    for (let index = 0; index < inputs.length; index += 1) {
      expect(redactSensitiveText(inputs[index]!)).toBe(expected[index])
      expect(safeDisplayValue(inputs[index]!)).toBe(expected[index])
    }
    expect(sanitizeForExport({ inputs })).toEqual({ inputs: expected })

    const safeEncodedControls = [
      ['https:', '', 'example.test', 'safe%40segment'].join('/'),
      ['https:', '', 'example.test', 'safe', 'fixture@segment'].join('/'),
      ['', '', 'example.test', 'safe%40segment'].join('/'),
      ['https:', '', `example.test?contact=${first}@mail.example.test`].join('/'),
      ['', '', `example.test#contact=${first}@mail.example.test`].join('/'),
    ]
    for (const value of safeEncodedControls) expect(redactSensitiveText(value)).toBe(value)
  })

  it('redacts protocol-relative URL credentials after punctuation and typographic separators', () => {
    const username = ['fixture', 'user'].join('-')
    const password = ['fixture', 'pass'].join('-')
    const remote = ['', '', `${username}:${password}@example.test`, 'safe'].join('/')
    const safeRemote = ['', '', 'example.test', 'safe'].join('/')
    const separators = ['`', '|', '?', '#', '&', ')', ']', '}', '‘', '’', '“', '”']
    for (const separator of separators) {
      expect(redactSensitiveText(`${separator}${remote}`)).toBe(`${separator}//[REDACTED]@example.test/safe`)
      expect(redactSensitiveText(`${separator}${safeRemote}`)).toBe(`${separator}${safeRemote}`)
    }
    expect(redactSensitiveText(`${username}@example.test`)).toBe(`${username}@example.test`)
  })

  it('redacts delimiter-adjacent local paths after URL text on every export surface', () => {
    const remoteUrl = ['https:', '', 'example.test', 'safe'].join('/')
    const posixPath = ['', 'private', 'fixture-data.json'].join('/')
    const windowsPath = ['C:', 'Fixture User', 'cache.db'].join('/')
    const posixAfterUrl = `${remoteUrl};cwd=${posixPath}`
    const windowsAfterUrl = `${remoteUrl},cache=${windowsPath}`
    const safeCompound = `${remoteUrl};mode=read/write;date=2026/08/12;math=10/2`

    expect(redactSensitiveText(posixAfterUrl)).toBe('[REDACTED_PATH]')
    expect(redactSensitiveText(windowsAfterUrl)).toBe('[REDACTED_PATH]')
    expect(redactSensitiveText(safeCompound)).toBe(safeCompound)
    expect(sanitizeForExport({ posixAfterUrl, windowsAfterUrl, safeCompound })).toEqual({
      posixAfterUrl: '[REDACTED_PATH]',
      windowsAfterUrl: '[REDACTED_PATH]',
      safeCompound,
    })
    expect(safeDisplayValue({ oldValue: posixAfterUrl, newValue: windowsAfterUrl })).toBe(
      '{"oldValue":"[REDACTED_PATH]","newValue":"[REDACTED_PATH]"}',
    )

    const event = {
      id: 'url-path-boundaries', timestamp: '2026-08-12T18:00:00.000Z', actor: posixAfterUrl,
      project: windowsAfterUrl, target: 'local', action: safeCompound, result: 'Succeeded' as const,
      correlationId: 'correlation-url-path-boundaries', detail: '',
    }
    for (const format of ['jsonl', 'csv'] as const) {
      const exported = buildSanitizedExport([event], format)
      expect(exported).toContain('[REDACTED_PATH]')
      expect(exported).toContain(safeCompound)
      for (const unsafe of [posixPath, windowsPath]) expect(exported).not.toContain(unsafe)
    }
  })

  it('redacts punctuation-delimited local path suffixes after safe URLs', () => {
    const { composites } = punctuationDelimitedUrlPathFixtures()
    for (const value of composites) expect(redactSensitiveText(value)).toBe('[REDACTED_PATH]')
  })

  it('uses a principled Unicode boundary for URL-adjacent POSIX, Windows, and UNC paths', () => {
    const remote = ['https:', '', 'example.test', 'safe'].join('/')
    const delimiters = [
      '`', '‘', '’', '“', '”', '(', '[', '{', '=', ':', '&', ']', '}',
      '—', '–', '…', '：', '，', '；', '｜', '（', '）', '［', '］',
      '!', '<', '>', '@', '^', '~', '💥',
    ]
    const paths = ['/private/fixture.txt', 'C:\\Fixture\\secret.txt', '\\\\fixture-host\\share\\secret.txt']

    for (const delimiter of delimiters) {
      for (const path of paths) {
        expect(redactSensitiveText(`${remote}${delimiter}${path}`)).toBe('[REDACTED_PATH]')
        expect(redactSensitiveText(`label${delimiter}${path}`)).toBe('[REDACTED_PATH]')
      }
    }

    const wordContinuationControls = ['label\u0301/private/fixture.txt', 'label＿/private/fixture.txt']
    for (const value of wordContinuationControls) expect(redactSensitiveText(value)).toBe(value)
  })

  it('redacts protocol-relative credentials after every Unicode punctuation and symbol boundary', () => {
    const remote = ['', '', 'fixture-user:fixture-pass@example.test', 'safe'].join('/')
    const delimiters = ['—', '–', '…', '：', '，', '；', '｜', '（', '）', '［', '］', '!', '<', '>', '@', '^', '~', '💥']
    for (const delimiter of delimiters) {
      const redacted = redactSensitiveText(`label${delimiter}${remote}`)
      expect(redacted).toBe(`label${delimiter}//[REDACTED]@example.test/safe`)
      expect(redacted).not.toContain('fixture-pass')
    }
  })

  it('fails closed on WHATWG-normalized special-scheme credential separators', () => {
    const userInfo = 'fixture-user:fixture-pass@outside.example.test/safe'
    const values = [
      ['https:', '///', userInfo].join(''),
      ['http:', '////', userInfo].join(''),
      ['https:', '\\\\', userInfo].join(''),
      ['https:', '/\\', userInfo].join(''),
      ['https:', '\\/', userInfo].join(''),
    ]
    for (const value of values) {
      const redacted = redactSensitiveText(value)
      const preview = safeDisplayValue({ value })
      expect(redacted).toMatch(/\[REDACTED(?:_PATH)?\]/u)
      expect(redacted).not.toContain('fixture-pass')
      expect(preview).not.toContain('fixture-pass')
    }
  })

  it('sanitizes punctuation-delimited URL and local-path composites in Memory previews', () => {
    const { composites } = punctuationDelimitedUrlPathFixtures()
    expect(sanitizeForExport({ values: composites })).toEqual({ values: composites.map(() => '[REDACTED_PATH]') })
    for (const value of composites) expect(safeDisplayValue({ oldValue: value })).toBe('{"oldValue":"[REDACTED_PATH]"}')
  })

  it('sanitizes punctuation-delimited URL and local-path composites in JSONL and CSV', () => {
    const { composites, localPaths } = punctuationDelimitedUrlPathFixtures()
    const events = composites.map((actor, index) => ({
      id: `url-path-punctuation-${index}`, timestamp: '2026-08-12T18:00:00.000Z', actor,
      project: 'Demo', target: 'local', action: 'Inspect', result: 'Succeeded' as const,
      correlationId: `correlation-url-path-punctuation-${index}`, detail: '',
    }))
    for (const format of ['jsonl', 'csv'] as const) {
      const exported = buildSanitizedExport(events, format)
      expect((exported.match(/\[REDACTED_PATH\]/g) ?? [])).toHaveLength(composites.length)
      for (const path of localPaths) expect(exported).not.toContain(path)
    }
  })

  it('fails closed on raw and encoded local paths in remote URL query and fragment values', () => {
    const remotes = [
      ['http:', '', 'example.test', 'safe'].join('/'),
      ['https:', '', 'example.test', 'safe'].join('/'),
      ['ftp:', '', 'files.example.test', 'pub'].join('/'),
      ['', '', 'cdn.example.test', 'assets'].join('/'),
    ]
    const localPaths = [
      '/private/fixture.json',
      'C:/Fixture/private.txt',
      'D:\\Fixture\\private.txt',
      '\\\\fixture-host\\share\\private.txt',
      'file:///private/fixture.db',
    ]
    const composites = remotes.flatMap((remote) => ['?', '#'].flatMap((separator) => (
      localPaths.flatMap((localPath) => [
        `${remote}${separator}cwd=${localPath}`,
        `${remote}${separator}cwd=${encodeURIComponent(localPath)}`,
      ])
    )))
    for (const value of composites) {
      expect(redactSensitiveText(value)).toBe('[REDACTED_PATH]')
      expect(safeDisplayValue(value)).toBe('[REDACTED_PATH]')
      expect(sanitizeForExport({ value })).toEqual({ value: '[REDACTED_PATH]' })
    }

    const events = composites.map((actor, index) => ({
      id: `url-parameter-path-${index}`, timestamp: '2026-08-12T18:00:00.000Z', actor,
      project: 'Demo', target: 'local', action: 'Inspect', result: 'Succeeded' as const,
      correlationId: `correlation-url-parameter-path-${index}`, detail: '',
    }))
    for (const format of ['jsonl', 'csv'] as const) {
      const exported = buildSanitizedExport(events, format)
      expect((exported.match(/\[REDACTED_PATH\]/g) ?? [])).toHaveLength(composites.length)
    }

    const safeRemoteValues = [
      ['https:', '', 'example.test', 'private', 'fixture.json'].join('/'),
      `${['https:', '', 'example.test', 'safe'].join('/')}?mode=read/write&date=2026/08/12&ratio=1/2`,
      `${['https:', '', 'example.test', 'safe'].join('/')}#version=v1.2.3/4.5.6`,
      `${['https:', '', 'example.test', 'safe'].join('/')}?next=${['https:', '', 'cdn.example.test', 'asset.js'].join('/')}`,
      `${['https:', '', 'example.test', 'safe'].join('/')}?next=${encodeURIComponent(['https:', '', 'cdn.example.test', 'asset.js'].join('/'))}`,
      `${['https:', '', 'example.test', 'safe'].join('/')}#next=${encodeURIComponent(['', '', 'cdn.example.test', 'asset.js'].join('/'))}`,
    ]
    for (const value of safeRemoteValues) expect(redactSensitiveText(value)).toBe(value)
  })

  it('inspects nested safe URLs with bounded near-linear work', { timeout: 1_000 }, () => {
    let value = ['https:', '', 'cdn.example.test', 'safe'].join('/')
    for (let depth = 0; depth < 10; depth += 1) value = `${['https:', '', 'example.test', 'safe'].join('/')}?next=${value}`
    expect(value.length).toBeLessThan(512)
    expect(redactSensitiveText(value)).toBe(value)
  })

  it('fails closed when nested URL inspection exceeds its global work budget', { timeout: 1_000 }, () => {
    const safeNested = encodeURIComponent(['https:', '', 'cdn.example.test', 'safe'].join('/'))
    const parameters = Array.from({ length: 400 }, (_, index) => `next${index}=${safeNested}`).join('&')
    const value = `${['https:', '', 'example.test', 'safe'].join('/')}?${parameters}`
    expect(value.length).toBeGreaterThan(16_384)
    expect(redactSensitiveText(value)).toBe('[REDACTED]')
  })

  it('fails closed on raw, once-encoded, twice-encoded, and over-depth nested URL credentials', () => {
    const outer = ['https:', '', 'outer.example.test', 'safe'].join('/')
    const nested = [
      ['https:', '', 'fixture-user:fixture-pass@inner.example.test', 'safe'].join('/'),
      ['', '', 'fixture-user:fixture-pass@inner.example.test', 'safe'].join('/'),
      ['https:', '', 'fixture-user@realm:fixture-pass@inner.example.test', 'safe'].join('/'),
      ['', '', ':fixture-pass@inner.example.test', 'safe'].join('/'),
    ]
    const encodeLayers = (value: string, layers: number) => {
      let encoded = value
      for (let layer = 0; layer < layers; layer += 1) encoded = encodeURIComponent(encoded)
      return encoded
    }
    for (const separator of ['?', '#']) {
      for (const inner of nested) {
        for (const layers of [0, 1, 2, 3]) {
          const value = `${outer}${separator}next=${encodeLayers(inner, layers)}`
          expect(redactSensitiveText(value)).toBe('[REDACTED]')
          expect(safeDisplayValue({ value })).toBe('{"value":"[REDACTED]"}')
        }
      }
    }

    const safeNested = [
      ['https:', '', 'inner.example.test', 'safe'].join('/'),
      ['', '', 'cdn.example.test', 'asset.js'].join('/'),
      'fixture-user@example.test',
    ]
    for (const inner of safeNested) {
      for (const layers of [0, 1, 2]) {
        const value = `${outer}?next=${encodeLayers(inner, layers)}`
        expect(redactSensitiveText(value)).toBe(value)
      }
    }
  })

  it('recognizes bounded Unicode and control whitespace in textual sensitive-key aliases', () => {
    const separators = ['\t', '\n', '\r\n', '\u00a0', '\u2003', '\u200b', '\u200c', '\uFEFF', '    ', ' '.repeat(16), '.', '-', '_']
    for (const separator of separators) {
      expect(redactSensitiveText(`api${separator}key=q`)).toBe('[REDACTED]')
      expect(redactSensitiveText(`aws${separator}session${separator}token=q`)).toBe('[REDACTED]')
    }
    const safeValues = [
      `api${' '.repeat(17)}key=q`,
      'The API key concept is documented without a value.',
      'tokenizer=enabled passwordless=true',
    ]
    for (const value of safeValues) expect(redactSensitiveText(value)).toBe(value)
  })

  it('redacts quoted structured assignments and bounded CLI whitespace values', () => {
    const unsafeValues = [
      'agent --token synthetic-short-private next',
      'agent --api-key "synthetic two word private" --mode local',
      "agent -password 'unterminated synthetic private",
      'client_secret synthetic-other-private',
      'token\tsynthetic-tab-private',
      'json={"password": "synthetic json private"}',
      "yaml={'api_key': 'synthetic yaml private'}",
      '"client_secret" = `synthetic toml private`',
    ]
    for (const value of unsafeValues) {
      expect(redactSensitiveText(value)).toBe('[REDACTED]')
      expect(safeDisplayValue({ value })).toBe('{"value":"[REDACTED]"}')
    }

    const safeValues = [
      '--token',
      'tokenizer synthetic-value',
      'client-secretary synthetic-value',
      'The API key concept is documented without a value.',
      'Token rotation is enabled.',
      `client_secret${' '.repeat(17)}synthetic-value`,
    ]
    for (const value of safeValues) expect(redactSensitiveText(value)).toBe(value)
  })

  it('keeps frontend token signatures in parity with the source scanner', () => {
    const tokens = [
      ['glpat-', 'Ab3dEf5hIj7kLm9nPq2s'].join(''),
      ['pypi-', 'Ab3dEf5hIj7kLm9nPq2sTu4wXy6zA8'].join(''),
      ['AGPA', '1234567890ABCDEF'].join(''),
      ['ASCA', '1234567890ABCDEF'].join(''),
    ]
    for (const value of tokens) expect(redactSensitiveText(value)).toBe('[REDACTED]')
  })

  it('stops object sanitization after the configured own-property limit', () => {
    let reads = 0
    const value: Record<string, string> = {}
    for (let index = 0; index < 5_000; index += 1) {
      Object.defineProperty(value, `safe_${index}`, {
        enumerable: true,
        get: () => { reads += 1; return `safe-${index}` },
      })
    }
    const sanitized = sanitizeForExport(value) as Record<string, string>
    expect(Object.keys(sanitized)).toHaveLength(50)
    expect(reads).toBe(50)
  })

  it('redacts adversarial unkeyed tokens, PEM bodies, and multiline secret values with bounded output', () => {
    const tokenShapes = [
      'sk-proj-fixtureabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJK',
      'ghp_fixtureabcdefghijklmnopqrstuvwxyz0123456789AB',
      'github_pat_11AA0_fixtureabcdefghijklmnopqrstuvwxyz0123456789',
      'AKIAIOSFODNN7EXAMPLE',
    ]
    const event = {
      id: 'adversarial', timestamp: '2026-08-12T18:00:00.000Z', actor: tokenShapes.join(' '), project: 'password: first line\n second line with spaces',
      target: '-----BEGIN PRIVATE KEY-----\nsyntheticfixtureQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\n-----END PRIVATE KEY-----',
      action: `MII${'A'.repeat(80)}`, result: 'Succeeded' as const, correlationId: 'safe'.repeat(5_000), detail: 'not exported',
    }
    const payload = buildSanitizedExport([event], 'jsonl')
    for (const secret of [...tokenShapes, 'first line', 'second line', 'syntheticfixture', 'MIIAAAA']) expect(payload).not.toContain(secret)
    expect(payload).toContain('[REDACTED]')
    expect(payload.length).toBeLessThan(5_000)
  })

  it('fails closed on unterminated private-key PEM blocks while preserving safe PEM and prose controls', () => {
    const labels = ['PRIVATE KEY', 'RSA PRIVATE KEY', 'EC PRIVATE KEY', 'OPENSSH PRIVATE KEY', 'ENCRYPTED PRIVATE KEY', 'DSA PRIVATE KEY', 'PGP PRIVATE KEY BLOCK']
    const privateBlocks = labels.flatMap((label) => {
      const begin = ['-----BEGIN ', `${label}-----`].join('')
      const end = ['-----END ', `${label}-----`].join('')
      return [
        [begin, 'synthetic non-MII private material'].join('\n'),
        [begin, 'synthetic complete private material', end].join('\n'),
      ]
    })
    for (const value of privateBlocks) {
      expect(redactSensitiveText(value)).toBe('[REDACTED]')
      expect(safeDisplayValue(value)).toBe('[REDACTED]')
    }
    expect(sanitizeForExport({ privateBlocks })).toEqual({ privateBlocks: privateBlocks.map(() => '[REDACTED]') })

    const publicBlocks = ['CERTIFICATE', 'PUBLIC KEY'].map((label) => [
      ['-----BEGIN ', `${label}-----`].join(''),
      'synthetic public material',
      ['-----END ', `${label}-----`].join(''),
    ].join('\n'))
    const proseNearMiss = 'Documentation may mention BEGIN PRIVATE KEY without containing a PEM marker.'
    const malformedMarker = [['-----BEGIN ', 'PRIVATE KEY----'].join(''), 'synthetic prose'].join('\n')
    for (const value of [...publicBlocks, proseNearMiss, malformedMarker]) expect(redactSensitiveText(value)).toBe(value)
  })

  it('recursively sanitizes nested non-string data, common tokens, and private paths', () => {
    const unsafe = {
      nested: [{ slack: 'xoxb-123456789012-fixtureabcdefghijklmnopqrstuvwxyz', google: 'AIzaSyfixtureabcdefghijklmnopqrstuvwxyz1234567' }],
      credentials: { password: 'synthetic words with spaces and\nmultiple lines', access_token: 'synthetic-short-but-private' },
      paths: ['C:\\Users\\Demo User\\secret file.txt', '\\\\server\\private share\\secret.txt', '/opt/private/data.json'],
      values: [null, 42, true],
    }
    const sanitized = JSON.stringify(sanitizeForExport(unsafe))
    expect(sanitized).not.toMatch(/xoxb-|AIza|Demo User|server|\/opt\/private|words with spaces|short-but-private/i)
    expect(sanitized).toContain('[REDACTED')
    expect(sanitized).toContain('42')
  })

  it('redacts the full sensitive-key vocabulary even when assigned values are short', () => {
    const sensitiveKeys = [
      'api_key', 'api key', 'api.key', 'authorization', 'access_token', 'access token',
      'refresh_token', 'client_secret', 'client secret', 'private_key', 'password', 'passwd',
      'passphrase', 'secret', 'seed_phrase', 'seed.phrase', 'credential', 'credentials', 'token',
      'auth_token', 'auth token', 'id_token', 'id.token', 'session_token', 'session-token',
      'AWS_SECRET_ACCESS_KEY', 'AWS.SESSION.TOKEN', 'x_api_key', 'x-api-key', 'x.api.key', 'x api key',
    ]
    const shortValues = sensitiveKeys.map((_, index) => `q${index}`)
    for (let index = 0; index < sensitiveKeys.length; index += 1) {
      expect(redactSensitiveText(`${sensitiveKeys[index]}=${shortValues[index]}`)).toBe('[REDACTED]')
    }

    const record = Object.fromEntries(sensitiveKeys.map((key, index) => [key, shortValues[index]]))
    const sanitized = sanitizeForExport(record) as Record<string, unknown>
    expect(Object.keys(sanitized).every((key) => /^\[REDACTED_KEY_\d+\]$/u.test(key))).toBe(true)
    expect(Object.values(sanitized).every((value) => value === '[REDACTED]')).toBe(true)
    const preview = safeDisplayValue(record)
    for (const value of shortValues) expect(preview).not.toContain(`"${value}"`)

    const safeProse = [
      'Token refresh completed without storing values.',
      'Credentials are managed locally.',
      'Use a passphrase manager and review seed phrase guidance.',
      'AWS_SECRET_ACCESS_KEY is unset; auth_token rotation is documented.',
    ]
    for (const value of safeProse) expect(redactSensitiveText(value)).toBe(value)
  })

  it('preserves repeated non-cyclic references while marking actual cycles', () => {
    const shared = { label: 'shared-safe-value' }
    const repeated = { first: shared, second: shared }
    expect(sanitizeForExport(repeated)).toEqual({
      first: { label: 'shared-safe-value' },
      second: { label: 'shared-safe-value' },
    })
    expect(safeDisplayValue(repeated)).toBe('{"first":{"label":"shared-safe-value"},"second":{"label":"shared-safe-value"}}')

    const cyclic: { label: string, self?: unknown } = { label: 'cyclic-safe-value' }
    cyclic.self = cyclic
    expect(sanitizeForExport(cyclic)).toEqual({ label: 'cyclic-safe-value', self: '[CIRCULAR]' })
  })

  it('redacts nested Slack app and Google OAuth tokens plus every private path root', () => {
    const value = sanitizeForExport({
      nested: [{ slack: ['xapp', '1', 'demo', 'abcdefghijklmnopqrstuvwxyz012345'].join('-') }, { oauth: ['1', '', 'abcdefghijklmnopqrstuvwxyz0123456789'].join('/') }],
      paths: ['/usr/local/private/config', '/mnt/private volume/file', '/private/var/item', '/home/demo/item', '/Users/demo/item', '/var/lib/item', '/tmp/item'],
      platformPaths: ['C:\\Users\\Demo Person\\private file.txt', '\\\\host\\private share\\file.txt'],
    })
    const serialized = JSON.stringify(value)
    const unsafeMarkers = ['xapp-', '1//', '/usr/', '/mnt/', '/private/', '/home/', '/Users/', '/var/', '/tmp/', 'C:\\', '\\\\host']
    expect(unsafeMarkers.some((marker) => serialized.includes(marker))).toBe(false)
    expect((serialized.match(/\[REDACTED/g) ?? []).length).toBeGreaterThanOrEqual(10)
  })

  it('redacts generic absolute POSIX paths while preserving surrounding non-path syntax', () => {
    const safeUrl = ['https:', '', 'example.test', 'a', 'b'].join('/')
    const input = `roots=/workspace,/run,/Volumes; runtime="/run/app.sock"; volume="/Volumes/External/item"; url=${safeUrl}; json={"value":"/workspace/cache"}; math=10 / 2; date=2026/08/12; prose=read/write and/or; slash=/`
    const redacted = redactSensitiveText(input)
    expect(redacted).toBe('[REDACTED_PATH]')
    expect(safeDisplayValue({ location: '/workspace/private/item' })).toBe('{"location":"[REDACTED_PATH]"}')
  })

  it('redacts numeric, symbol, and Unicode POSIX roots in exports and Memory previews', () => {
    const paths = ['/123/secret.txt', '/+data/key.pem', '/$data/token', '/équipe/secret.txt', '/😀/secret.txt']
    const event = { id: 'unicode-paths', timestamp: '2026-08-12T18:00:00.000Z', actor: paths.join(' | '), project: 'Demo', target: 'local', action: 'Inspect', result: 'Succeeded' as const, correlationId: 'correlation-paths', detail: '' }
    const exported = buildSanitizedExport([event], 'jsonl')
    for (const path of paths) {
      expect(exported).not.toContain(path)
      expect(safeDisplayValue({ oldValue: path })).toBe('{"oldValue":"[REDACTED_PATH]"}')
    }
    expect((exported.match(/\[REDACTED_PATH\]/g) ?? [])).toHaveLength(1)
  })

  it('redacts single-component and noncanonical POSIX tokens in JSONL, CSV, and Memory previews', () => {
    const repeatedSeparatorPath = ['/data/', '/secret.txt'].join('')
    const paths = ['/123', '/+data', '/$data', '/équipe', '/😀', '/workspace/', '/123/', repeatedSeparatorPath]
    const event = { id: 'path-variants', timestamp: '2026-08-12T18:00:00.000Z', actor: paths.join(' | '), project: 'Demo', target: 'local', action: 'Inspect', result: 'Succeeded' as const, correlationId: 'correlation-path-variants', detail: '' }
    for (const format of ['jsonl', 'csv'] as const) {
      const exported = buildSanitizedExport([event], format)
      for (const path of paths) expect(exported).not.toContain(path)
      expect((exported.match(/\[REDACTED_PATH\]/g) ?? [])).toHaveLength(1)
    }
    for (const path of paths) expect(safeDisplayValue({ newValue: path })).toBe('{"newValue":"[REDACTED_PATH]"}')
  })

  it('fails closed on local POSIX, Windows, device, UNC, and file URI paths at field level', () => {
    const nel = String.fromCharCode(0x85)
    const nbsp = '\u00A0'
    const remoteWithLocalSuffix = `${['https:', '', 'example.test', 'safe'].join('/')} /private/local.txt`
    const localPaths = [
      '/:name', '/=name', '/Volumes/External Disk/private.txt', '//server/share/private.txt', '///var/tmp/private.txt',
      'path:/compact/private.txt', 'path:C:/compact/private.txt', 'cwd:/compact/private.txt', 'cache:C:/compact/private.txt', 'file:///var/lib/private.db', 'file://server/share/private.txt', 'C:/Users/Demo/private.txt',
      '\\Device\\HarddiskVolume1\\private.bin', '\\SystemRoot\\System32\\config', 'C:\\Users\\Demo\\private.txt',
      '\\Users\\Demo\\private.txt', '\\??\\C:\\Users\\Demo\\private.txt', '\\\\?\\C:\\Users\\Demo\\private.txt', '\\\\server\\share\\private.txt', 'file:///C:/Users/Demo/private.txt',
      `${nel}/private/path`, `${nbsp}/private/path`, `\uFEFF/private/path`, remoteWithLocalSuffix,
    ]
    for (const value of localPaths) {
      expect(redactSensitiveText(value)).toBe('[REDACTED_PATH]')
      expect(safeDisplayValue(value)).toBe('[REDACTED_PATH]')
    }
    const nested = sanitizeForExport({ records: localPaths.map((value) => ({ value })) }) as { records: Array<{ value: string }> }
    expect(nested.records.every((record) => record.value === '[REDACTED_PATH]')).toBe(true)
    const event = { id: 'local-paths', timestamp: '2026-08-12T18:00:00.000Z', actor: localPaths.join(' | '), project: 'Demo', target: 'local', action: 'Inspect', result: 'Succeeded' as const, correlationId: 'correlation-local-paths', detail: '' }
    for (const format of ['jsonl', 'csv'] as const) {
      const exported = buildSanitizedExport([event], format)
      expect(exported).toContain('[REDACTED_PATH]')
      for (const value of localPaths) expect(exported).not.toContain(value)
    }
  })

  it('treats triple-leading host-shaped POSIX values and every rooted backslash token as local', () => {
    const localPaths = [
      ...['cdn.example.test/private', 'localhost/private', '127.0.0.1/private'].flatMap((suffix) => [`///${suffix}`, `////${suffix}`]),
      '\\single', '\\Folder Name', '\\équipe', '\\😀', '\\root/mixed separator/private.txt',
    ]
    for (const value of localPaths) {
      expect(redactSensitiveText(value)).toBe('[REDACTED_PATH]')
      expect(safeDisplayValue(value)).toBe('[REDACTED_PATH]')
    }
    expect((sanitizeForExport({ nested: localPaths }) as { nested: string[] }).nested.every((value) => value === '[REDACTED_PATH]')).toBe(true)
    const event = { id: 'rooted-paths', timestamp: '2026-08-12T18:00:00.000Z', actor: localPaths.join(' | '), project: 'Demo', target: 'local', action: 'Inspect', result: 'Succeeded' as const, correlationId: 'correlation-rooted-paths', detail: '' }
    for (const format of ['jsonl', 'csv'] as const) {
      const exported = buildSanitizedExport([event], format)
      expect(exported).toContain('[REDACTED_PATH]')
      for (const value of localPaths) expect(exported).not.toContain(value)
    }
  })

  it('redacts local paths after closing and pipe delimiters on every surface', () => {
    const delimiters = ['|', '?', '#', '&', ')', ']', '}', '`', '‘', '’', '“', '”']
    const posixPaths = delimiters.map((_, index) => `/private/boundary-${index}.json`)
    const windowsPaths = delimiters.map((_, index) => `${String.fromCharCode(67 + index)}:\\Fixture\\boundary-${index}.db`)
    const composites = delimiters.flatMap((delimiter, index) => [
      `status${delimiter}${posixPaths[index]}`,
      `status${delimiter}${windowsPaths[index]}`,
    ])
    for (const value of composites) {
      expect(redactSensitiveText(value)).toBe('[REDACTED_PATH]')
      expect(safeDisplayValue(value)).toBe('[REDACTED_PATH]')
    }
    expect(sanitizeForExport(composites)).toEqual(composites.map(() => '[REDACTED_PATH]'))

    const event = { id: 'closing-boundary-paths', timestamp: '2026-08-12T18:00:00.000Z', actor: composites.join(' '), project: 'Demo', target: 'local', action: 'Inspect', result: 'Succeeded' as const, correlationId: 'correlation-closing-boundary-paths', detail: '' }
    for (const format of ['jsonl', 'csv'] as const) {
      const exported = buildSanitizedExport([event], format)
      expect(exported).toContain('[REDACTED_PATH]')
      for (const path of [...posixPaths, ...windowsPaths]) expect(exported).not.toContain(path)
    }
  })

  it('recognizes every cleaned control and Unicode whitespace as a local path boundary', () => {
    const boundaryCodes = [
      ...Array.from({ length: 32 }, (_, code) => code),
      ...Array.from({ length: 33 }, (_, index) => index + 0x7f),
      0xfeff,
    ]
    const boundaries = [...boundaryCodes.map((code) => String.fromCharCode(code)), '\u00a0', '\u1680', '\u2000', '\u2028', '\u2029', '\u202f', '\u205f', '\u3000']
    const localPaths = boundaries.flatMap((boundary) => [`${boundary}/private/control-path`, `${boundary}\\private control-path`])
    for (const value of localPaths) expect(redactSensitiveText(value)).toBe('[REDACTED_PATH]')
    const remotePrefix = ['https:', '', 'example.test', 'safe'].join('/')
    for (const boundary of boundaries) {
      expect(redactSensitiveText(`${remotePrefix}${boundary}/private/control-path`)).toBe('[REDACTED_PATH]')
      expect(redactSensitiveText(`${remotePrefix}${boundary}\\private control-path`)).toBe('[REDACTED_PATH]')
    }
    const event = { id: 'control-paths', timestamp: '2026-08-12T18:00:00.000Z', actor: localPaths.join('|'), project: 'Demo', target: 'local', action: 'Inspect', result: 'Succeeded' as const, correlationId: 'correlation-control-paths', detail: '' }
    for (const format of ['jsonl', 'csv'] as const) {
      const exported = buildSanitizedExport([event], format)
      expect(exported).toContain('[REDACTED_PATH]')
      expect(exported).not.toContain('/private/control-path')
      expect(exported).not.toContain('\\private control-path')
    }
  })

  it('preserves explicit remote URLs and non-path slash expressions', () => {
    const values = [
      ['http:', '', 'example.test', 'a', 'b'].join('/'),
      ['https:', '', 'example.test', 'a', 'b'].join('/'),
      ['ftp:', '', 'files.example.test', 'pub', 'item'].join('/'),
      ['', '', 'cdn.example.test', 'assets', 'app.js'].join('/'),
      ['', '', 'localhost', 'assets', 'app.js'].join('/'),
      ['', '', '127.0.0.1', 'assets', 'app.js'].join('/'),
      ['', '', '[::1]', 'assets', 'app.js'].join('/'),
      '2026/08/12', '1/2', '10 / 2', 'read/write', 'v1.2.3/4.5.6', '/', '{"ratio":"1/2"}',
    ]
    for (const value of values) {
      expect(redactSensitiveText(value)).toBe(value)
      expect(safeDisplayValue(value)).toBe(value)
    }
    expect((sanitizeForExport({ values }) as { values: string[] }).values).toEqual(values)
    const event = { id: 'slash-negatives', timestamp: '2026-08-12T18:00:00.000Z', actor: values.join(' | '), project: 'Demo', target: 'local', action: 'Inspect', result: 'Succeeded' as const, correlationId: 'correlation-slash-negatives', detail: '' }
    for (const format of ['jsonl', 'csv'] as const) expect(buildSanitizedExport([event], format)).not.toContain('[REDACTED')
  })

  it('emits RFC4180 CSV with stable columns and formula neutralization', () => {
    const event = { id: 'csv', timestamp: '2026-08-12T18:00:00.000Z', actor: '=SUM(1,2)', project: 'Quoted "project"', target: '+cmd', action: '@mention', result: 'Succeeded' as const, correlationId: '\t=formula', detail: '' }
    const csv = buildSanitizedExport([event], 'csv')
    expect(csv.split('\r\n')).toHaveLength(2)
    expect(csv.split('\r\n')[0]).toBe('"timestamp","actor","project","target","action","result","correlationId"')
    expect(csv).toContain('"\'=SUM(1,2)"')
    expect(csv).toContain('"Quoted ""project"""')
    expect(csv).toContain('"\'+cmd"')
    expect(csv).toContain('"\'@mention"')
    expect(csv).toContain('"\' =formula"')
  })

  it('neutralizes formulas after LF and all leading ASCII control whitespace', () => {
    const event = { id: 'controls', timestamp: '2026-08-12T18:00:00.000Z', actor: '\n=SUM(1,2)', project: ' \t+cmd', target: '\x01\x1f-name', action: '\r\n@call', result: 'Succeeded' as const, correlationId: '\x7f=hidden', detail: '' }
    const csv = buildSanitizedExport([event], 'csv')
    for (const value of ["'\n=SUM(1,2)", "'  +cmd", "'  -name", "'\r\n@call", "' =hidden"]) expect(csv.includes(value)).toBe(true)
    expect(csv.startsWith('"timestamp","actor","project","target","action","result","correlationId"\r\n')).toBe(true)
  })

  it('removes forbidden CSV control bytes, preserves CRLF content, and leaves blank fields unprefixed', () => {
    const forbidden = [...Array.from({ length: 9 }, (_, code) => code), 9, 11, 12, ...Array.from({ length: 18 }, (_, index) => index + 14), 127]
    const controls = forbidden.filter((code) => code !== 9).map((code) => String.fromCharCode(code)).join('')
    const event = { id: 'bytes', timestamp: '2026-08-12T18:00:00.000Z', actor: `${controls}safe`, project: '\t=SUM(1,2)', target: '\v\f+cmd', action: 'line1\r\nline2', result: 'Succeeded' as const, correlationId: ' \t', detail: '' }
    const csv = buildSanitizedExport([event], 'csv')
    for (const code of forbidden) expect(csv.includes(String.fromCharCode(code))).toBe(false)
    expect(csv).toContain('"\' =SUM(1,2)"')
    expect(csv).toContain('"\'  +cmd"')
    expect(csv).toContain('"line1\r\nline2"')
    expect(csv).toContain('"  "')
    expect(csv).not.toContain('"\'  "')
    const blankCsv = buildSanitizedExport([{ ...event, actor: '', project: '   ', target: 'safe', action: 'safe', correlationId: 'safe' }], 'csv')
    expect(blankCsv.split('\r\n')[1]).toContain(',"","   ","safe"')
    expect(blankCsv).not.toContain('"\'"')
  })

  it('cleans the full C1 range and uses Unicode whitespace before formula decisions', () => {
    const c1 = Array.from({ length: 32 }, (_, index) => String.fromCharCode(0x80 + index)).join('')
    const nel = String.fromCharCode(0x85)
    const event = { id: 'unicode-controls', timestamp: '2026-08-12T18:00:00.000Z', actor: `${c1}=SUM(1,2)`, project: `\uFEFF+cmd`, target: `\u00A0-cmd`, action: `${nel}@call`, result: 'Succeeded' as const, correlationId: c1, detail: '' }
    const csv = buildSanitizedExport([event], 'csv')
    for (let code = 0x80; code <= 0x9f; code += 1) expect(csv.includes(String.fromCharCode(code))).toBe(false)
    expect(csv.includes('\uFEFF')).toBe(false)
    expect(csv).toContain(`"'${' '.repeat(32)}=SUM(1,2)"`)
    expect(csv).toContain('"\' +cmd"')
    expect(csv).toContain('"\'\u00A0-cmd"')
    expect(csv).toContain('"\' @call"')
    expect(csv).toContain(`"${' '.repeat(32)}"`)
    expect(csv).not.toContain(`"'${' '.repeat(32)}"`)
  })

  it('truncates at 510, 511, and 512 grapheme boundaries without malformed UTF-16 or UTF-8', async () => {
    const isWellFormed = (value: string) => (value as string & { isWellFormed: () => boolean }).isWellFormed()
    const cases = [
      { input: `${'a'.repeat(510)}😀beyond`, expected: `${'a'.repeat(510)}😀` },
      { input: `${'a'.repeat(511)}😀beyond`, expected: 'a'.repeat(511) },
      { input: `${'a'.repeat(512)}😀beyond`, expected: 'a'.repeat(512) },
    ]
    for (const sample of cases) {
      const truncated = truncateSafeText(sample.input)
      expect(truncated).toBe(sample.expected)
      expect(isWellFormed(truncated)).toBe(true)
      expect(redactSensitiveText(sample.input)).toBe(sample.expected)
      expect(safeDisplayValue(sample.input)).toBe(sample.expected)
      const json = JSON.stringify({ truncated })
      expect(JSON.parse(json)).toEqual({ truncated })
      expect(await new Blob([json], { type: 'application/json;charset=utf-8' }).text()).toBe(json)
      const event = { id: 'unicode-boundary', timestamp: '2026-08-12T18:00:00.000Z', actor: sample.input, project: 'Demo', target: 'local', action: 'Inspect', result: 'Succeeded' as const, correlationId: 'correlation-unicode-boundary', detail: '' }
      const jsonl = buildSanitizedExport([event], 'jsonl')
      expect(isWellFormed(jsonl)).toBe(true)
      expect(JSON.parse(jsonl).actor).toBe(sample.expected)
      expect(await new Blob([jsonl], { type: 'application/x-ndjson;charset=utf-8' }).text()).toBe(jsonl)
      const csv = buildSanitizedExport([event], 'csv')
      expect(isWellFormed(csv)).toBe(true)
      expect(csv).toContain(sample.expected)
      expect(await new Blob([csv], { type: 'text/csv;charset=utf-8' }).text()).toBe(csv)
    }
    expect(truncateSafeText(`${'a'.repeat(511)}e\u0301beyond`)).toBe('a'.repeat(511))
    expect(isWellFormed(truncateSafeText(`${'a'.repeat(511)}\ud83d`))).toBe(true)
  })

  it('clears stale export previews when filters change and avoids scan-certification claims', async () => {
    const user = userEvent.setup()
    render(<ActivityPage transport={new DemoTransport({ latencyMs: 0 })} />)
    await user.click(await screen.findByRole('button', { name: 'Preview sanitized JSONL' }))
    expect(screen.getByRole('textbox', { name: 'Sanitized export preview' })).not.toBeNull()
    expect(screen.queryByText(/secret scan passed/i)).toBeNull()
    await user.type(screen.getByRole('searchbox', { name: 'Search activity' }), 'heartbeat')
    expect(screen.queryByRole('textbox', { name: 'Sanitized export preview' })).toBeNull()
  })

  it('makes the horizontally scrollable events table keyboard reachable', async () => {
    render(<ActivityPage transport={new DemoTransport({ latencyMs: 0 })} />)
    const region = await screen.findByRole('region', { name: 'Activity events table' })
    expect(region.tabIndex).toBe(0)
    region.focus()
    expect(document.activeElement).toBe(region)
  })

  it('uses roving keyboard tabs with linked panels', async () => {
    const user = userEvent.setup()
    render(<ActivityPage transport={new DemoTransport({ latencyMs: 0 })} />)
    const events = await screen.findByRole('tab', { name: 'Events' })
    const receipts = screen.getByRole('tab', { name: 'Receipts' })
    expect(events.tabIndex).toBe(0); expect(receipts.tabIndex).toBe(-1)
    events.focus(); await user.keyboard('{ArrowRight}')
    expect(document.activeElement).toBe(receipts)
    expect(receipts.getAttribute('aria-selected')).toBe('true')
    const panel = screen.getByRole('tabpanel')
    expect(receipts.getAttribute('aria-controls')).toBe(panel.id)
    expect(panel.getAttribute('aria-labelledby')).toBe(receipts.id)
  })

  it('guards Graveyard restore against double submit', async () => {
    let calls = 0
    const demo = new DemoTransport({ latencyMs: 15 })
    const original = demo.executeGraveyardRestore.bind(demo)
    vi.spyOn(demo, 'executeGraveyardRestore').mockImplementation(async (request) => { calls += 1; return original(request) })
    render(<ActivityPage transport={demo} />)
    fireEvent.click(await screen.findByRole('tab', { name: 'Quarantine' }))
    fireEvent.click(await screen.findAllByRole('button', { name: 'Review restore' }).then((buttons) => buttons[0]!))
    const restore = await screen.findByRole('button', { name: 'Restore exact entry' })
    fireEvent.click(restore); fireEvent.click(restore)
    expect(await screen.findByText('Restored', { selector: 'dd' })).not.toBeNull()
    expect(calls).toBe(1)
  })

  it('keeps Graveyard restore failures inside the modal and focuses an exact retry', async () => {
    const demo = new DemoTransport({ latencyMs: 0 })
    const original = demo.executeGraveyardRestore.bind(demo)
    let calls = 0
    let releaseRetry: (() => void) | undefined
    vi.spyOn(demo, 'executeGraveyardRestore').mockImplementation(async (request) => {
      calls += 1
      if (calls === 1) throw new Error('Destination changed while restoring.')
      await new Promise<void>((resolve) => { releaseRetry = resolve })
      return original(request)
    })
    const user = userEvent.setup()
    render(<ActivityPage transport={demo} />)
    await user.click(await screen.findByRole('tab', { name: 'Quarantine' }))
    await user.click((await screen.findAllByRole('button', { name: 'Review restore' }))[0]!)
    const dialog = await screen.findByRole('dialog', { name: 'Review quarantine restore' })
    await user.click(within(dialog).getByRole('button', { name: 'Restore exact entry' }))
    const retry = await within(dialog).findByRole('button', { name: 'Retry restore' })
    expect(within(dialog).getByRole('alert').textContent).toMatch(/destination changed/i)
    expect(screen.queryByText('Nothing was restored.')).toBeNull()
    await waitFor(() => expect(document.activeElement).toBe(retry))
    await user.click(retry)
    expect(dialog.contains(document.activeElement)).toBe(true)
    expect(document.activeElement).toBe(retry)
    releaseRetry?.()
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Review quarantine restore' })).toBeNull())
    expect(calls).toBe(2)
  })

  it('restores the exact Graveyard opener when Escape closes a failed restore review', async () => {
    const demo = new DemoTransport({ latencyMs: 0 })
    vi.spyOn(demo, 'executeGraveyardRestore').mockRejectedValue(new Error('Restore service is temporarily unavailable.'))
    const user = userEvent.setup()
    render(<ActivityPage transport={demo} />)
    await user.click(await screen.findByRole('tab', { name: 'Quarantine' }))
    const opener = (await screen.findAllByRole('button', { name: 'Review restore' }))[0]!
    await user.click(opener)
    const dialog = await screen.findByRole('dialog', { name: 'Review quarantine restore' })
    await user.click(within(dialog).getByRole('button', { name: 'Restore exact entry' }))
    await within(dialog).findByRole('button', { name: 'Retry restore' })

    await user.keyboard('{Escape}')

    expect(screen.queryByRole('dialog', { name: 'Review quarantine restore' })).toBeNull()
    expect(document.activeElement).toBe(opener)
  })

  it('guards a Graveyard retry against double submit', async () => {
    const demo = new DemoTransport({ latencyMs: 0 })
    const original = demo.executeGraveyardRestore.bind(demo)
    let calls = 0
    let releaseRetry: (() => void) | undefined
    vi.spyOn(demo, 'executeGraveyardRestore').mockImplementation(async (request) => {
      calls += 1
      if (calls === 1) throw new Error('Restore service is temporarily unavailable.')
      await new Promise<void>((resolve) => { releaseRetry = resolve })
      return original(request)
    })
    render(<ActivityPage transport={demo} />)
    fireEvent.click(await screen.findByRole('tab', { name: 'Quarantine' }))
    fireEvent.click((await screen.findAllByRole('button', { name: 'Review restore' }))[0]!)
    const dialog = await screen.findByRole('dialog', { name: 'Review quarantine restore' })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Restore exact entry' }))
    const retry = await within(dialog).findByRole('button', { name: 'Retry restore' })

    fireEvent.click(retry); fireEvent.click(retry)

    expect(calls).toBe(2)
    releaseRetry?.()
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Review quarantine restore' })).toBeNull())
  })

  it.each([
    ['plan_expired', 'Restore plan expired.'],
    ['conflict', 'Quarantine entry changed after review.'],
    ['plan_replayed', 'Restore plan was already used.'],
    ['outcome_uncertain', 'The restore result could not be confirmed.'],
  ] as const)('does not retry a terminal Graveyard %s result with the same plan', async (code, message) => {
    const demo = new DemoTransport({ latencyMs: 0 })
    let calls = 0
    vi.spyOn(demo, 'executeGraveyardRestore').mockImplementation(async () => {
      calls += 1
      throw new TransportError(code, message)
    })
    const user = userEvent.setup()
    render(<ActivityPage transport={demo} />)
    await user.click(await screen.findByRole('tab', { name: 'Quarantine' }))
    await user.click((await screen.findAllByRole('button', { name: 'Review restore' }))[0]!)
    const dialog = await screen.findByRole('dialog', { name: 'Review quarantine restore' })
    await user.click(within(dialog).getByRole('button', { name: 'Restore exact entry' }))

    expect(await within(dialog).findByText(message)).not.toBeNull()
    expect(within(dialog).queryByRole('button', { name: 'Retry restore' })).toBeNull()
    expect(within(dialog).getByRole('button', { name: 'Close and refresh' })).not.toBeNull()
    expect(calls).toBe(1)
  })

  it('expires and replays Graveyard restore plans and appends the receipt to Activity', async () => {
    let now = new Date('2026-08-12T18:00:00.000Z')
    const demo = new DemoTransport({ latencyMs: 0, now: () => now })
    const entry = (await demo.getActivity()).quarantine[0]!
    const expired = await demo.planGraveyardRestore(entry.id)
    now = new Date(expired.expiresAt)
    await expect(demo.executeGraveyardRestore({ planId: expired.planId, digest: expired.digest })).rejects.toMatchObject({ code: 'plan_expired' })
    now = new Date('2026-08-12T18:00:01.000Z')
    const plan = await demo.planGraveyardRestore(entry.id)
    const receipt = await demo.executeGraveyardRestore({ planId: plan.planId, digest: plan.digest })
    await expect(demo.executeGraveyardRestore({ planId: plan.planId, digest: plan.digest })).rejects.toMatchObject({ code: 'plan_replayed' })
    const activity = await demo.getActivity()
    expect(activity.graveyardReceipts).toContainEqual(receipt)
    expect(activity.events.some((event) => event.correlationId === receipt.correlationId && event.action === 'Quarantine restore')).toBe(true)
  })

  it('applies project, actor, result, date, and search filters to receipts and quarantine', async () => {
    const user = userEvent.setup()
    const demo = new DemoTransport({ latencyMs: 0, now: () => new Date('2026-08-12T18:00:00.000Z') })
    const entry = (await demo.getActivity()).quarantine[0]!
    const plan = await demo.planGraveyardRestore(entry.id)
    const restored = await demo.executeGraveyardRestore({ planId: plan.planId, digest: plan.digest })
    render(<ActivityPage transport={demo} />)
    await user.click(await screen.findByRole('tab', { name: 'Receipts' }))
    await user.selectOptions(screen.getByLabelText('Project'), 'Local recovery')
    expect(screen.getByText('Quarantine restore')).not.toBeNull()
    expect(screen.getByText(restored.receiptId)).not.toBeNull()
    expect(screen.queryByText('Containment complete')).toBeNull()
    await user.clear(screen.getByLabelText('Search activity'))
    await user.type(screen.getByLabelText('Search activity'), 'no-match')
    expect(screen.getByText(/No receipts match/i)).not.toBeNull()

    await user.click(screen.getByRole('tab', { name: 'Quarantine' }))
    await user.clear(screen.getByLabelText('Search activity'))
    await user.selectOptions(screen.getByLabelText('Project'), 'All')
    await user.selectOptions(screen.getByLabelText('Result'), 'Restored')
    expect(screen.getByText('capture-old.png')).not.toBeNull()
    expect(screen.getByText('Restored', { selector: 'dd' })).not.toBeNull()
  })

  it('filters quarantine by correlated activity time, not retention expiry', async () => {
    const user = userEvent.setup()
    render(<ActivityPage transport={new DemoTransport({ latencyMs: 0, now: () => new Date('2026-08-12T00:30:00.000Z') })} />)
    await user.click(await screen.findByRole('tab', { name: 'Quarantine' }))
    const date = screen.getByLabelText('Date')
    fireEvent.change(date, { target: { value: '2026-08-11' } })
    expect(screen.getByText('capture-old.png')).not.toBeNull()
    fireEvent.change(date, { target: { value: '2026-09-11' } })
    expect(screen.queryByText('capture-old.png')).toBeNull()
  })
})
