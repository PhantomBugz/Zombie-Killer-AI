import axe from 'axe-core'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { describe, expect, it, vi } from 'vitest'

import { Dialog } from '../components/Dialog'
import { MemoryPage } from '../features/memory/MemoryPage'
import { MemoryEditor } from '../features/memory/MemoryEditor'
import { parseMemoryDraft } from '../features/memory/memoryDraft'
import App from '../App'
import { DemoTransport, TransportError } from '../transport'
import { TauriTransport } from '../transport/tauri'

const clock = () => new Date('2026-08-12T18:00:00.000Z')
let sequence = 0
const transport = () => new DemoTransport({ latencyMs: 0, now: clock, id: (prefix) => `${prefix}-${++sequence}` })

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((resolvePromise) => { resolve = resolvePromise })
  return { promise, resolve }
}

describe('demo Memory Vault transport', () => {
  it('rejects advanced drafts with schema, type, and size violations', () => {
    expect(parseMemoryDraft('{"title":4,"content":"x","tags":[],"collection":"c"}').error).toMatch(/title/i)
    expect(parseMemoryDraft('{"title":"x","content":"x","tags":[],"collection":"c","unknown":true}').error).toMatch(/schema/i)
    expect(parseMemoryDraft(JSON.stringify({ title: 'x', content: 'x'.repeat(17_000), tags: [], collection: 'c' })).error).toMatch(/byte limit/i)
  })

  it('decodes escaped duplicate keys recursively before schema validation', () => {
    expect(parseMemoryDraft('{"title":"one","\\u0074itle":"two","content":"x","tags":[],"collection":"c"}').error).toMatch(/duplicate key "title"/i)
    expect(parseMemoryDraft('{"title":"x","content":"x","tags":[],"collection":"c","meta":{"a":1,"\\u0061":2}}').error).toMatch(/duplicate key "a"/i)
  })

  it('searches deterministically without exposing raw embeddings', async () => {
    const demo = transport()
    const vault = await demo.getVault()
    expect(vault.mode).toBe('demo')
    expect(vault.sources.map((source) => source.name)).toEqual(['MTGA JSON memory', 'Mev BOT SQLite memory'])
    expect(vault.sources[0]?.status).toBe('Healthy')
    expect(vault.sources[1]?.status).toBe('Backup missing')

    const first = await demo.searchMemory({ query: 'flying', sourceId: 'mtga-json', page: 1, pageSize: 2 })
    expect(first.records.map((record) => record.id)).toEqual(['card-0001', 'card-0003'])
    expect(first.records[0]?.embedding).toBe('Present')
    expect(JSON.stringify(first)).not.toMatch(/\[[\d.,-]{20,}\]/)
  })

  it('plans, snapshots, applies, receipts, and restores an exact structured edit', async () => {
    const demo = transport()
    const before = (await demo.searchMemory({ query: 'card-0001', page: 1, pageSize: 10 })).records[0]!
    const plan = await demo.planMemoryChange({
      sourceId: before.sourceId,
      recordId: before.id,
      operation: 'update',
      expectedSourceRevision: 4,
      expectedRecordRevision: before.revision,
      changes: { content: 'A safe synthetic flying card search result.' },
    })
    expect(plan.snapshot.verified).toBe(true)
    expect(plan.diff).toEqual([{ field: 'content', oldValue: before.content, newValue: 'A safe synthetic flying card search result.' }])

    const receipt = await demo.executeMemoryChange({ planId: plan.planId, digest: plan.digest })
    expect(receipt.snapshotId).toBe(plan.snapshot.id)
    expect(receipt.operation).toBe('update')
    await expect(demo.executeMemoryChange({ planId: plan.planId, digest: plan.digest })).rejects.toMatchObject({ code: 'plan_replayed' })

    const changed = (await demo.searchMemory({ query: 'card-0001', page: 1, pageSize: 10 })).records[0]!
    expect(changed.content).toContain('safe synthetic')
    const restorePlan = await demo.planMemoryRestore({
      receiptId: receipt.receiptId,
      snapshotId: receipt.snapshotId,
      expectedRecordRevision: changed.revision,
    })
    const restored = await demo.executeMemoryRestore({ planId: restorePlan.planId, digest: restorePlan.digest })
    expect(restored.operation).toBe('restore')
    expect((await demo.searchMemory({ query: 'card-0001', page: 1, pageSize: 10 })).records[0]?.content).toBe(before.content)
  })

  it('rejects tampered and stale plans without changing memory', async () => {
    const demo = transport()
    const record = (await demo.searchMemory({ query: 'card-0001', page: 1, pageSize: 10 })).records[0]!
    const request = {
      sourceId: record.sourceId, recordId: record.id, operation: 'exclude' as const,
      expectedSourceRevision: 4, expectedRecordRevision: record.revision, changes: {},
    }
    const plan = await demo.planMemoryChange(request)
    await expect(demo.executeMemoryChange({ planId: plan.planId, digest: 'tampered' })).rejects.toMatchObject({ code: 'plan_changed' })
    const sibling = await demo.planMemoryChange(request)
    await demo.executeMemoryChange({ planId: plan.planId, digest: plan.digest })
    await expect(demo.executeMemoryChange({ planId: sibling.planId, digest: sibling.digest })).rejects.toMatchObject({ code: 'target_changed' })
    await expect(demo.planMemoryChange(request)).rejects.toBeInstanceOf(TransportError)
  })

  it('rejects no-op and empty memory changes without revisions or receipts', async () => {
    const demo = transport()
    const beforeVault = await demo.getVault()
    const record = (await demo.searchMemory({ query: 'card-0001', page: 1, pageSize: 10 })).records[0]!
    const beforeReceipts = (await demo.getActivity()).memoryReceipts.length
    for (const request of [
      { operation: 'update' as const, changes: {} },
      { operation: 'update' as const, changes: [] as never },
      { operation: 'update' as const, changes: { content: record.content } },
    ]) await expect(demo.planMemoryChange({ sourceId: record.sourceId, recordId: record.id, expectedSourceRevision: 4, expectedRecordRevision: record.revision, ...request })).rejects.toMatchObject({ code: 'schema_invalid' })
    const exclude = await demo.planMemoryChange({ sourceId: record.sourceId, recordId: record.id, operation: 'exclude', expectedSourceRevision: 4, expectedRecordRevision: record.revision, changes: {} })
    await demo.executeMemoryChange({ planId: exclude.planId, digest: exclude.digest })
    const excluded = (await demo.searchMemory({ query: record.id, page: 1, pageSize: 10 })).records[0]!
    await expect(demo.planMemoryChange({ sourceId: record.sourceId, recordId: record.id, operation: 'exclude', expectedSourceRevision: 5, expectedRecordRevision: excluded.revision, changes: {} })).rejects.toMatchObject({ code: 'schema_invalid' })
    expect(Number((await demo.getVault()).sources[0]!.revision)).toBe(Number(beforeVault.sources[0]!.revision) + 1)
    expect((await demo.getActivity()).memoryReceipts).toHaveLength(beforeReceipts + 1)
  })

  it('strictly validates every optional memory search filter', async () => {
    const demo = transport()
    await expect(demo.searchMemory({ query: '', page: 1, pageSize: 10, sourceId: 4 } as never)).rejects.toMatchObject({ code: 'invalid_request' })
    await expect(demo.searchMemory({ query: '', page: 1, pageSize: 10, unknown: 'field' } as never)).rejects.toMatchObject({ code: 'invalid_request' })
    await expect(demo.searchMemory({ query: '', page: 1, pageSize: 10, from: 'not-a-date' })).rejects.toMatchObject({ code: 'invalid_request' })
    const record = (await demo.searchMemory({ query: 'card-0001', page: 1, pageSize: 10 })).records[0]!
    await expect(demo.planMemoryChange({ sourceId: record.sourceId, recordId: record.id, operation: 'update', expectedSourceRevision: 4, expectedRecordRevision: record.revision, changes: { content: 'x'.repeat(8193) } })).rejects.toMatchObject({ code: 'schema_invalid' })
  })

  it('expires restore plans and rejects concurrent source changes', async () => {
    let now = new Date('2026-08-12T18:00:00.000Z')
    const demo = new DemoTransport({ latencyMs: 0, now: () => now, id: (prefix) => `${prefix}-${++sequence}` })
    const first = (await demo.searchMemory({ query: 'card-0001', page: 1, pageSize: 10 })).records[0]!
    const change = await demo.planMemoryChange({ sourceId: first.sourceId, recordId: first.id, operation: 'update', expectedSourceRevision: 4, expectedRecordRevision: first.revision, changes: { content: 'changed' } })
    const receipt = await demo.executeMemoryChange({ planId: change.planId, digest: change.digest })
    const changed = (await demo.searchMemory({ query: 'card-0001', page: 1, pageSize: 10 })).records[0]!
    const restore = await demo.planMemoryRestore({ receiptId: receipt.receiptId, snapshotId: receipt.snapshotId, expectedRecordRevision: changed.revision })
    expect(restore.expectedSourceRevision).toBe(5)
    now = new Date(restore.expiresAt)
    await expect(demo.executeMemoryRestore({ planId: restore.planId, digest: restore.digest })).rejects.toMatchObject({ code: 'plan_expired' })

    now = new Date('2026-08-12T18:00:01.000Z')
    const freshRestore = await demo.planMemoryRestore({ receiptId: receipt.receiptId, snapshotId: receipt.snapshotId, expectedRecordRevision: changed.revision })
    const sibling = (await demo.searchMemory({ query: 'card-0002', page: 1, pageSize: 10 })).records[0]!
    const siblingPlan = await demo.planMemoryChange({ sourceId: sibling.sourceId, recordId: sibling.id, operation: 'exclude', expectedSourceRevision: freshRestore.expectedSourceRevision, expectedRecordRevision: sibling.revision, changes: {} })
    await demo.executeMemoryChange({ planId: siblingPlan.planId, digest: siblingPlan.digest })
    await expect(demo.executeMemoryRestore({ planId: freshRestore.planId, digest: freshRestore.digest })).rejects.toMatchObject({ code: 'conflict' })
  })

  it('records immutable version history for changes and restores', async () => {
    const demo = transport()
    const before = (await demo.searchMemory({ query: 'card-0001', page: 1, pageSize: 10 })).records[0]!
    const plan = await demo.planMemoryChange({ sourceId: before.sourceId, recordId: before.id, operation: 'update', expectedSourceRevision: 4, expectedRecordRevision: before.revision, changes: { title: 'History title' } })
    const receipt = await demo.executeMemoryChange({ planId: plan.planId, digest: plan.digest })
    let history = await demo.getMemoryHistory(before.sourceId, before.id)
    expect(history[0]).toMatchObject({ operation: 'update', receiptId: receipt.receiptId, snapshotId: receipt.snapshotId, revision: receipt.afterRevision })
    const restorePlan = await demo.planMemoryRestore({ receiptId: receipt.receiptId, snapshotId: receipt.snapshotId, expectedRecordRevision: receipt.afterRevision })
    const restored = await demo.executeMemoryRestore({ planId: restorePlan.planId, digest: restorePlan.digest })
    history = await demo.getMemoryHistory(before.sourceId, before.id)
    expect(history[0]).toMatchObject({ operation: 'restore', receiptId: restored.receiptId, revision: restored.afterRevision })
    expect(history.at(-1)?.operation).toBe('created')
  })
})

describe('Memory Vault interface', () => {
  it('does not query a non-queryable native source and labels its exact digest', async () => {
    const revision = 'e'.repeat(64)
    const invoke = vi.fn(async (_command: string, arguments_: unknown) => {
      const request = (arguments_ as { request: { method: string } }).request
      if (request.method !== 'vault.list') throw new Error(`Unexpected native method: ${request.method}`)
      return {
        requestId: '11111111-1111-4111-8111-111111111111', method: request.method,
        result: {
          sources: [{
            source_id: 'offline-faiss', format: 'faiss', revision,
            capabilities: { readable: true, queryable: false, editable: false, snapshot: false, restore: false, reason: 'Index inspection only.' },
          }],
          next_cursor: null, local_only_warning: 'Local records only.',
        },
      }
    })
    const user = userEvent.setup()
    render(<MemoryPage transport={new TauriTransport(invoke)} />)

    const source = await screen.findByRole('button', { name: /offline-faiss/i })
    expect(source.textContent).toContain(`source digest ${revision}`)
    expect(source.textContent).toContain('Not queryable')
    await user.click(source)
    expect(screen.getByText('This source is registered but not queryable.')).not.toBeNull()
    expect((screen.getByRole('searchbox', { name: 'Search memory' }) as HTMLInputElement).disabled).toBe(true)
    expect(invoke.mock.calls.some(([, arguments_]) => (arguments_ as { request?: { method?: string } })?.request?.method === 'vault.query')).toBe(false)
  })

  it('shows absent native record metadata and references as Not reported', async () => {
    const revision = 'f'.repeat(64)
    const invoke = vi.fn(async (_command: string, arguments_: unknown) => {
      const request = (arguments_ as { request: { method: string; payload: Record<string, unknown> } }).request
      if (request.method === 'vault.list') return {
        requestId: '11111111-1111-4111-8111-111111111111', method: request.method,
        result: {
          sources: [{
            source_id: 'local-jsonl', format: 'jsonl', revision,
            capabilities: { readable: true, queryable: true, editable: false, snapshot: false, restore: false, reason: null },
          }],
          next_cursor: null, local_only_warning: 'Local records only.',
        },
      }
      if (request.method === 'vault.query') return {
        requestId: '22222222-2222-4222-8222-222222222222', method: request.method,
        result: {
          records: [{
            record_id: 'record-without-metadata', namespace: 'default', content: 'Bounded local record.',
            metadata: {}, embedding_present: false, source_revision: revision,
          }],
          next_cursor: null, total: 1, local_only_warning: 'Local records only.',
        },
      }
      throw new Error(`Unexpected native method: ${request.method}`)
    })
    const user = userEvent.setup()
    render(<MemoryPage transport={new TauriTransport(invoke)} />)

    await screen.findAllByText('record-without-metadata')
    const source = screen.getByRole('button', { name: /local-jsonl/i })
    expect(source.textContent).toContain(`source digest ${revision}`)
    const queryCall = invoke.mock.calls.find(([, arguments_]) => (arguments_ as { request?: { method?: string } })?.request?.method === 'vault.query')
    expect((queryCall?.[1] as { request: { payload: Record<string, unknown> } }).request.payload).toEqual({
      sourceId: 'local-jsonl', namespace: null, text: null, limit: 25,
    })

    await user.click(screen.getByRole('tab', { name: 'Metadata' }))
    expect(within(screen.getByRole('tabpanel')).getAllByText('Not reported')).toHaveLength(2)
    await user.click(screen.getByRole('tab', { name: 'References' }))
    expect(within(screen.getByRole('tabpanel')).getAllByText('Not reported')).toHaveLength(2)
  })

  it('loads a second native memory page with the returned opaque cursor', async () => {
    const revision = 'e'.repeat(64)
    const records = Array.from({ length: 30 }, (_, index) => ({
      record_id: `native-record-${index}`,
      namespace: 'default',
      content: `needle-${index}`,
      metadata: {},
      embedding_present: false,
      source_revision: revision,
    }))
    const payloads: Record<string, unknown>[] = []
    const reply = (method: string, result: Record<string, unknown>) => ({ requestId: '11111111-1111-4111-8111-111111111111', method, result })
    const invoke = vi.fn(async (_command: string, arguments_: unknown) => {
      const request = (arguments_ as { request: { method: string; payload: Record<string, unknown> } }).request
      payloads.push(request.payload)
      if (request.method === 'vault.list') return reply(request.method, {
        sources: [{ source_id: 'native-source', format: 'json', revision, capabilities: { readable: true, queryable: true, editable: false, snapshot: false, restore: false, reason: null } }],
        next_cursor: null, local_only_warning: 'Local records only.',
      })
      if (request.method === 'vault.query') {
        const offset = request.payload.cursor ? 25 : 0
        return reply(request.method, { records: records.slice(offset, offset + 25), next_cursor: offset ? null : 'v1.context.25', total: records.length, local_only_warning: 'Local records only.' })
      }
      throw new Error(`Unexpected native method: ${request.method}`)
    })
    const user = userEvent.setup()
    render(<MemoryPage transport={new TauriTransport(invoke)} />)

    await screen.findAllByText('native-record-0')
    expect(screen.queryByText('native-record-29')).toBeNull()
    await user.click(screen.getByRole('button', { name: 'Next page' }))
    await screen.findAllByText('native-record-29')

    expect(payloads.filter((payload) => 'text' in payload)).toEqual([
      { sourceId: 'native-source', namespace: null, text: null, limit: 25 },
      { sourceId: 'native-source', namespace: null, text: null, limit: 25, cursor: 'v1.context.25' },
    ])
    expect(screen.getByText('Page 2')).not.toBeNull()
  })

  it('resets a failed native cursor chain before retrying from page 1', async () => {
    const revision = 'f'.repeat(64)
    const records = Array.from({ length: 30 }, (_, index) => ({
      record_id: `restart-record-${index}`,
      namespace: 'default',
      content: `needle-${index}`,
      metadata: {},
      embedding_present: false,
      source_revision: revision,
    }))
    let rejectCursor = true
    const invoke = vi.fn(async (_command: string, arguments_: unknown) => {
      const request = (arguments_ as { request: { method: string; payload: Record<string, unknown> } }).request
      const reply = (result: Record<string, unknown>) => ({ requestId: '11111111-1111-4111-8111-111111111111', method: request.method, result })
      if (request.method === 'vault.list') return reply({
        sources: [{ source_id: 'native-source', format: 'json', revision, capabilities: { readable: true, queryable: true, editable: false, snapshot: false, restore: false, reason: null } }],
        next_cursor: null,
        local_only_warning: 'Local records only.',
      })
      if (request.method === 'vault.query' && request.payload.cursor && rejectCursor) {
        rejectCursor = false
        throw { code: 'conflict', message: 'The query cursor is stale.', correlationId: 'cursor-stale' }
      }
      if (request.method === 'vault.query') return reply({ records: records.slice(0, 25), next_cursor: 'cursor-page-2', total: 30, local_only_warning: 'Local records only.' })
      throw new Error(`Unexpected native method: ${request.method}`)
    })
    const user = userEvent.setup()
    render(<MemoryPage transport={new TauriTransport(invoke)} />)
    await screen.findAllByText('restart-record-0')
    await user.click(screen.getByRole('button', { name: 'Next page' }))

    expect((await screen.findByRole('alert')).textContent).toMatch(/query cursor is stale/i)
    expect(screen.queryByText('restart-record-0')).toBeNull()
    expect(screen.queryByRole('navigation', { name: 'Memory pagination' })).toBeNull()
    await user.click(screen.getByRole('button', { name: 'Retry' }))
    await screen.findAllByText('restart-record-0')
    expect(screen.getByText('Page 1')).not.toBeNull()
  })

  it('warns when a native page total proves that its next cursor is missing', async () => {
    const revision = '9'.repeat(64)
    const records = Array.from({ length: 10 }, (_, index) => ({
      record_id: `partial-record-${index}`,
      namespace: 'default',
      content: `needle-${index}`,
      metadata: {},
      embedding_present: false,
      source_revision: revision,
    }))
    const invoke = vi.fn(async (_command: string, arguments_: unknown) => {
      const request = (arguments_ as { request: { method: string } }).request
      return request.method === 'vault.list'
        ? { requestId: '11111111-1111-4111-8111-111111111111', method: request.method, result: { sources: [{ source_id: 'native-source', format: 'json', revision, capabilities: { readable: true, queryable: true, editable: false, snapshot: false, restore: false, reason: null } }], next_cursor: null, local_only_warning: 'Local records only.' } }
        : { requestId: '22222222-2222-4222-8222-222222222222', method: request.method, result: { records, next_cursor: null, total: 20, local_only_warning: 'Local records only.' } }
    })
    render(<MemoryPage transport={new TauriTransport(invoke)} />)

    expect((await screen.findByRole('alert')).textContent).toMatch(/next page cursor was not provided/i)
    expect(screen.getByText('10 of 20')).not.toBeNull()
  })

  it('keeps nested modal isolation and scroll ownership until the final dialog closes', async () => {
    let unlockInner: () => void = () => undefined
    function Harness() {
      const [outer, setOuter] = useState(true)
      const [inner, setInner] = useState(true)
      const [innerLocked, setInnerLocked] = useState(true)
      unlockInner = () => setInnerLocked(false)
      return <><main data-testid="modal-background" aria-hidden="false">Background</main><aside data-testid="pre-inert" inert aria-hidden="false">Pre-inert</aside>{outer && <Dialog title="Outer review" onClose={() => setOuter(false)}><button type="button">Outer action</button>{inner && <Dialog title="Inner review" closeDisabled={innerLocked} onClose={() => setInner(false)}><button type="button">Inner action</button></Dialog>}</Dialog>}</>
    }
    document.body.style.setProperty('overflow', 'clip', 'important'); document.body.style.position = 'relative'; document.body.style.top = '4px'
    const outsideOpener = document.createElement('button')
    outsideOpener.textContent = 'Open nested reviews'
    document.body.append(outsideOpener); outsideOpener.focus()
    const view = render(<Harness />)
    try {
      const background = screen.getByTestId('modal-background')
      const preInert = screen.getByTestId('pre-inert')
      expect(background.hasAttribute('inert')).toBe(true); expect(background.getAttribute('aria-hidden')).toBe('true')
      expect(preInert.hasAttribute('inert')).toBe(true); expect(preInert.getAttribute('aria-hidden')).toBe('true')
      expect(document.body.classList.contains('modal-scroll-locked')).toBe(true); expect(document.body.style.position).toBe('relative'); expect(document.body.style.overflow).toBe('clip')
      document.body.tabIndex = -1; document.body.focus(); fireEvent.keyDown(document, { key: 'Escape' })
      expect(screen.getByRole('dialog', { name: 'Inner review' })).not.toBeNull()
      expect(screen.getByRole('dialog', { name: 'Outer review' })).not.toBeNull()

      act(() => unlockInner())
      fireEvent.keyDown(document, { key: 'Escape' })
      await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Inner review' })).toBeNull())
      expect(screen.getByRole('dialog', { name: 'Outer review' })).not.toBeNull()
      expect(screen.getByRole('button', { name: 'Outer action' }).hasAttribute('inert')).toBe(false)
      expect(background.hasAttribute('inert')).toBe(true); expect(document.body.classList.contains('modal-scroll-locked')).toBe(true)

      document.body.focus(); fireEvent.keyDown(document, { key: 'Escape' })
      await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
      expect(background.hasAttribute('inert')).toBe(false); expect(background.getAttribute('aria-hidden')).toBe('false')
      expect(preInert.hasAttribute('inert')).toBe(true); expect(preInert.getAttribute('aria-hidden')).toBe('false')
      expect(document.body.classList.contains('modal-scroll-locked')).toBe(false)
      expect(document.body.style.overflow).toBe('clip'); expect(document.body.style.position).toBe('relative'); expect(document.body.style.top).toBe('4px')
      expect(document.body.style.getPropertyPriority('overflow')).toBe('important')
      expect(document.activeElement).toBe(outsideOpener)
    } finally {
      view.unmount(); outsideOpener.remove(); document.body.removeAttribute('style'); document.body.removeAttribute('tabindex')
    }
  })

  it('keeps the top dialog interactive and background locked if an earlier sibling unmounts', async () => {
    let removeFirst: () => void = () => undefined
    let showSecond: () => void = () => undefined
    function Harness() {
      const [first, setFirst] = useState(true)
      const [second, setSecond] = useState(false)
      removeFirst = () => setFirst(false)
      showSecond = () => setSecond(true)
      return <><main data-testid="sibling-background">Background</main>{first && <Dialog title="First review" onClose={() => setFirst(false)}><button type="button">First action</button></Dialog>}{second && <Dialog title="Second review" onClose={() => setSecond(false)}><button type="button">Second action</button></Dialog>}</>
    }
    const outsideOpener = document.createElement('button')
    outsideOpener.textContent = 'Open sibling reviews'
    document.body.append(outsideOpener); outsideOpener.focus()
    const view = render(<Harness />)
    try {
      const background = screen.getByTestId('sibling-background')
      act(() => showSecond())
      const secondLayer = screen.getByRole('dialog', { name: 'Second review', hidden: true }).closest('.dialog-layer') as HTMLElement
      expect(secondLayer.hasAttribute('inert')).toBe(false)
      expect(background.hasAttribute('inert')).toBe(true); expect(document.body.classList.contains('modal-scroll-locked')).toBe(true)
      act(() => removeFirst())
      expect(screen.queryByRole('dialog', { name: 'First review' })).toBeNull()
      expect(screen.getByRole('dialog', { name: 'Second review' })).not.toBeNull()
      expect(background.hasAttribute('inert')).toBe(true); expect(document.body.classList.contains('modal-scroll-locked')).toBe(true)
      document.body.tabIndex = -1; document.body.focus(); fireEvent.keyDown(document, { key: 'Escape' })
      await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
      expect(background.hasAttribute('inert')).toBe(false); expect(document.body.classList.contains('modal-scroll-locked')).toBe(false)
      expect(document.activeElement).toBe(outsideOpener)
    } finally {
      view.unmount(); outsideOpener.remove(); document.body.removeAttribute('tabindex')
    }
  })

  it('re-isolates and focuses the new top dialog when stable sibling layers reorder', async () => {
    let reverseDialogs: () => void = () => undefined
    function Harness() {
      const [reversed, setReversed] = useState(false)
      const [open, setOpen] = useState({ first: true, second: true })
      reverseDialogs = () => setReversed(true)
      const order = reversed ? ['second', 'first'] as const : ['first', 'second'] as const
      return <><main data-testid="reorder-background" aria-hidden="false">Background</main>{order.map((id) => open[id] && <Dialog key={id} title={`${id} reorder review`} onClose={() => setOpen((value) => ({ ...value, [id]: false }))}><button type="button">{id} action</button></Dialog>)}</>
    }
    const outsideOpener = document.createElement('button')
    outsideOpener.textContent = 'Open reordered reviews'
    document.body.append(outsideOpener); outsideOpener.focus()
    const view = render(<Harness />)
    try {
      const first = screen.getByRole('dialog', { name: 'first reorder review', hidden: true })
      const second = screen.getByRole('dialog', { name: 'second reorder review' })
      const firstLayer = first.closest('.dialog-layer') as HTMLElement
      const secondLayer = second.closest('.dialog-layer') as HTMLElement
      expect(second.contains(document.activeElement)).toBe(true)
      act(() => reverseDialogs())
      await waitFor(() => expect(firstLayer.hasAttribute('inert')).toBe(false))
      expect(secondLayer.hasAttribute('inert')).toBe(true)
      expect(first.contains(document.activeElement)).toBe(true)

      fireEvent.keyDown(document, { key: 'Escape' })
      await waitFor(() => expect(screen.queryByRole('dialog', { name: 'first reorder review' })).toBeNull())
      expect(screen.getByRole('dialog', { name: 'second reorder review' }).contains(document.activeElement)).toBe(true)
      fireEvent.keyDown(document, { key: 'Escape' })
      await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
      const background = screen.getByTestId('reorder-background')
      expect(background.hasAttribute('inert')).toBe(false)
      expect(background.getAttribute('aria-hidden')).toBe('false')
      expect(document.activeElement).toBe(outsideOpener)
    } finally {
      view.unmount(); outsideOpener.remove()
    }
  })

  it('returns a nested dialog to its exact opener before restoring the external opener', async () => {
    function Harness() {
      const [outer, setOuter] = useState(true)
      const [inner, setInner] = useState(false)
      return outer ? <Dialog title="Outer direct focus" onClose={() => setOuter(false)}><button type="button" onClick={() => setInner(true)}>Open inner direct focus</button>{inner && <Dialog title="Inner direct focus" onClose={() => setInner(false)}><button type="button">Inner action</button></Dialog>}</Dialog> : null
    }
    const outsideOpener = document.createElement('button')
    outsideOpener.textContent = 'Open direct focus review'
    document.body.append(outsideOpener); outsideOpener.focus()
    const view = render(<Harness />)
    try {
      const innerOpener = screen.getByRole('button', { name: 'Open inner direct focus' })
      innerOpener.focus(); fireEvent.click(innerOpener)
      expect(screen.getByRole('dialog', { name: 'Inner direct focus' })).not.toBeNull()
      fireEvent.keyDown(document, { key: 'Escape' })
      await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Inner direct focus' })).toBeNull())
      expect(document.activeElement).toBe(innerOpener)
      fireEvent.keyDown(document, { key: 'Escape' })
      await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
      expect(document.activeElement).toBe(outsideOpener)
    } finally {
      view.unmount(); outsideOpener.remove()
    }
  })

  it('falls back inside the remaining dialog when a nested opener becomes disabled', async () => {
    let disableOpener: () => void = () => undefined
    function Harness() {
      const [outer, setOuter] = useState(true)
      const [inner, setInner] = useState(false)
      const [disabled, setDisabled] = useState(false)
      disableOpener = () => setDisabled(true)
      return outer ? <Dialog title="Outer disabled focus" onClose={() => setOuter(false)}><button type="button" disabled={disabled} onClick={() => setInner(true)}>Open disabled inner focus</button>{inner && <Dialog title="Inner disabled focus" onClose={() => setInner(false)}><button type="button">Inner action</button></Dialog>}</Dialog> : null
    }
    const outsideOpener = document.createElement('button')
    outsideOpener.textContent = 'Open disabled focus review'
    document.body.append(outsideOpener); outsideOpener.focus()
    const view = render(<Harness />)
    try {
      const innerOpener = screen.getByRole('button', { name: 'Open disabled inner focus' })
      innerOpener.focus(); fireEvent.click(innerOpener)
      act(() => disableOpener())
      fireEvent.keyDown(document, { key: 'Escape' })
      await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Inner disabled focus' })).toBeNull())
      const outerHeading = screen.getByRole('heading', { name: 'Outer disabled focus' })
      expect(document.activeElement).toBe(outerHeading)
      expect(document.activeElement).not.toBe(document.body)
      fireEvent.keyDown(document, { key: 'Escape' })
      await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
      expect(document.activeElement).toBe(outsideOpener)
    } finally {
      view.unmount(); outsideOpener.remove()
    }
  })

  it.each(['hidden', 'inert ancestor', 'non-focusable ref'] as const)('rejects a %s nested restore target', async (mode) => {
    let invalidateTarget: () => void = () => undefined
    const restoreRef: { current: HTMLElement | null } = { current: null }
    function Harness() {
      const [outer, setOuter] = useState(true)
      const [inner, setInner] = useState(false)
      const [invalid, setInvalid] = useState(false)
      invalidateTarget = () => setInvalid(true)
      return outer ? <Dialog title={`Outer ${mode}`} onClose={() => setOuter(false)}><div><div inert={mode === 'inert ancestor' && invalid ? true : undefined}><button type="button" hidden={mode === 'hidden' && invalid} disabled={mode === 'non-focusable ref' && invalid} onClick={(event) => { restoreRef.current = event.currentTarget; setInner(true) }}>Open invalid target</button></div><div data-testid="plain-restore-target">Plain target</div></div>{inner && <Dialog title={`Inner ${mode}`} restoreFocusRef={restoreRef} onClose={() => setInner(false)}><button type="button">Inner action</button></Dialog>}</Dialog> : null
    }
    const outsideOpener = document.createElement('button')
    outsideOpener.textContent = `Open ${mode} review`
    document.body.append(outsideOpener); outsideOpener.focus()
    const view = render(<Harness />)
    try {
      const innerOpener = screen.getByRole('button', { name: 'Open invalid target' })
      innerOpener.focus(); fireEvent.click(innerOpener)
      act(() => invalidateTarget())
      if (mode === 'non-focusable ref') restoreRef.current = screen.getByTestId('plain-restore-target')
      fireEvent.keyDown(document, { key: 'Escape' })
      await waitFor(() => expect(screen.queryByRole('dialog', { name: `Inner ${mode}` })).toBeNull())
      expect(document.activeElement).toBe(screen.getByRole('heading', { name: `Outer ${mode}` }))
      fireEvent.keyDown(document, { key: 'Escape' })
      await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
      expect(document.activeElement).toBe(outsideOpener)
    } finally {
      view.unmount(); outsideOpener.remove()
    }
  })

  it('falls back to the live route heading when the dialog opener is disconnected', async () => {
    const restoreRef: { current: HTMLElement | null } = { current: null }
    function Harness() {
      const [open, setOpen] = useState(false)
      return <main><h1 data-route-heading="true" tabIndex={-1}>Durable workspace</h1><button type="button" onClick={(event) => { restoreRef.current = event.currentTarget; setOpen(true) }}>Open transient review</button>{open && <Dialog title="Transient review" restoreFocusRef={restoreRef} onClose={() => setOpen(false)}><button type="button" onClick={() => { restoreRef.current?.remove(); setOpen(false) }}>Remove opener and close</button></Dialog>}</main>
    }
    const user = userEvent.setup()
    render(<Harness />)

    await user.click(screen.getByRole('button', { name: 'Open transient review' }))
    await user.click(screen.getByRole('button', { name: 'Remove opener and close' }))

    const heading = screen.getByRole('heading', { name: 'Durable workspace' })
    await waitFor(() => expect(document.activeElement).toBe(heading))
  })

  it('preserves a React-owned inert opener ancestor when the nested dialog closes', async () => {
    let makeOpenerInert: () => void = () => undefined
    function Harness() {
      const [outer, setOuter] = useState(true)
      const [inner, setInner] = useState(false)
      const [openerInert, setOpenerInert] = useState(false)
      makeOpenerInert = () => setOpenerInert(true)
      return <><main data-testid="react-owned-background" aria-hidden="false">Background</main>{outer && <Dialog title="Outer React ownership" onClose={() => setOuter(false)}><div data-testid="react-owned-opener-parent" inert={openerInert ? true : undefined} aria-hidden={openerInert ? 'true' : undefined}><button type="button" onClick={() => setInner(true)}>Open React-owned inner</button></div>{inner && <Dialog title="Inner React ownership" onClose={() => setInner(false)}><button type="button">Inner action</button></Dialog>}</Dialog>}</>
    }
    const outsideOpener = document.createElement('button')
    outsideOpener.textContent = 'Open React ownership review'
    document.body.append(outsideOpener); outsideOpener.focus()
    const view = render(<Harness />)
    try {
      const innerOpener = screen.getByRole('button', { name: 'Open React-owned inner' })
      const openerParent = screen.getByTestId('react-owned-opener-parent')
      innerOpener.focus(); fireEvent.click(innerOpener)
      expect(openerParent.hasAttribute('inert')).toBe(true)
      await act(async () => { makeOpenerInert(); await Promise.resolve() })

      fireEvent.keyDown(document, { key: 'Escape' })
      await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Inner React ownership' })).toBeNull())
      expect(openerParent.hasAttribute('inert')).toBe(true)
      expect(openerParent.getAttribute('aria-hidden')).toBe('true')
      expect(document.activeElement).toBe(screen.getByRole('heading', { name: 'Outer React ownership' }))

      fireEvent.keyDown(document, { key: 'Escape' })
      await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
      const background = screen.getByTestId('react-owned-background')
      expect(background.hasAttribute('inert')).toBe(false)
      expect(background.getAttribute('aria-hidden')).toBe('false')
      expect(document.activeElement).toBe(outsideOpener)
    } finally {
      view.unmount(); outsideOpener.remove()
    }
  })

  it('restores focus to the exact action opener and blocks the palette over a modal', async () => {
    const user = userEvent.setup()
    const standalone = render(<MemoryPage transport={transport()} />)
    await screen.findAllByText('Lightning Drake')
    const quarantine = screen.getByRole('button', { name: 'Quarantine record' })
    await user.click(quarantine)
    expect(screen.getByRole('dialog')).not.toBeNull()
    expect((await axe.run(standalone.container, { rules: { 'color-contrast': { enabled: false } } })).violations).toEqual([])
    await user.keyboard('{Escape}')
    expect(document.activeElement).toBe(quarantine)
    standalone.unmount()

    render(<App />)
    await user.click(screen.getByRole('link', { name: 'Memory Vault' }))
    await screen.findAllByText('Lightning Drake')
    await user.click(screen.getAllByRole('button', { name: 'Edit draft' }).at(-1)!)
    await user.keyboard('{Control>}k{/Control}')
    expect(screen.getAllByRole('dialog')).toHaveLength(1)
    expect(screen.queryByRole('dialog', { name: 'Command palette' })).toBeNull()
  })

  it('starts read-only, searches, and exposes structured review without raw vectors', async () => {
    const user = userEvent.setup()
    render(<MemoryPage transport={transport()} />)
    expect(await screen.findByRole('heading', { name: 'Memory Vault' })).not.toBeNull()
    expect(screen.getAllByText(/local-only/i).length).toBeGreaterThan(0)
    expect(await screen.findByText('MTGA JSON memory')).not.toBeNull()
    await user.type(screen.getByRole('searchbox', { name: /search memory/i }), 'flying')
    expect((await screen.findAllByText('Lightning Drake')).length).toBeGreaterThan(0)
    expect(screen.queryByText(/0\.123/)).toBeNull()
    expect(screen.getByText('Present')).not.toBeNull()
    expect(screen.getByRole('tab', { name: 'Content' }).getAttribute('aria-selected')).toBe('true')
    for (const tab of ['Metadata', 'References', 'History']) expect(screen.getByRole('tab', { name: tab })).not.toBeNull()
    const content = screen.getByRole('tab', { name: 'Content' }); const metadata = screen.getByRole('tab', { name: 'Metadata' })
    expect(content.tabIndex).toBe(0); expect(metadata.tabIndex).toBe(-1)
    content.focus(); await user.keyboard('{ArrowRight}')
    expect(document.activeElement).toBe(metadata)
    const panel = screen.getByRole('tabpanel')
    expect(metadata.getAttribute('aria-controls')).toBe(panel.id)
    expect(panel.getAttribute('aria-labelledby')).toBe(metadata.id)
  })

  it('never renders history or restore controls from a different selected record', async () => {
    const user = userEvent.setup()
    const demo = transport()
    const record = (await demo.searchMemory({ query: 'card-0001', page: 1, pageSize: 10 })).records[0]!
    const plan = await demo.planMemoryChange({ sourceId: record.sourceId, recordId: record.id, operation: 'update', expectedSourceRevision: 4, expectedRecordRevision: record.revision, changes: { title: 'History-only title' } })
    const receipt = await demo.executeMemoryChange({ planId: plan.planId, digest: plan.digest })
    render(<MemoryPage transport={demo} />)
    await user.click(await screen.findByRole('tab', { name: 'History' }))
    expect(await screen.findByText(new RegExp(receipt.receiptId))).not.toBeNull()
    await user.click(screen.getByRole('button', { name: /Forest Guardian/ }))
    expect(screen.queryByText(new RegExp(receipt.receiptId))).toBeNull()
    expect(screen.queryByRole('button', { name: 'Restore version' })).toBeNull()
  })

  it('discards a pending restore review when the visible record changes', async () => {
    const user = userEvent.setup()
    const demo = transport()
    const record = (await demo.searchMemory({ query: 'card-0001', page: 1, pageSize: 10 })).records[0]!
    const plan = await demo.planMemoryChange({ sourceId: record.sourceId, recordId: record.id, operation: 'update', expectedSourceRevision: 4, expectedRecordRevision: record.revision, changes: { title: 'Pending restore source' } })
    await demo.executeMemoryChange({ planId: plan.planId, digest: plan.digest })
    const original = demo.planMemoryRestore.bind(demo)
    let release: (() => void) | undefined
    vi.spyOn(demo, 'planMemoryRestore').mockImplementation((request) => new Promise((resolve, reject) => { release = () => void original(request).then(resolve, reject) }))
    render(<MemoryPage transport={demo} />)
    await user.click(await screen.findByRole('tab', { name: 'History' }))
    await user.click(await screen.findByRole('button', { name: 'Restore version' }))
    await user.click(screen.getByRole('button', { name: /Forest Guardian/ }))
    await act(async () => { release?.() })
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Review version restore' })).toBeNull())
  })

  it('immediately clears history and restore review when search changes the selection', async () => {
    const user = userEvent.setup()
    const demo = transport()
    const record = (await demo.searchMemory({ query: 'card-0001', page: 1, pageSize: 10 })).records[0]!
    const plan = await demo.planMemoryChange({ sourceId: record.sourceId, recordId: record.id, operation: 'update', expectedSourceRevision: 4, expectedRecordRevision: record.revision, changes: { title: 'Search-bound restore' } })
    const receipt = await demo.executeMemoryChange({ planId: plan.planId, digest: plan.digest })
    render(<MemoryPage transport={demo} />)
    await user.click(await screen.findByRole('tab', { name: 'History' }))
    expect(await screen.findByText(new RegExp(receipt.receiptId))).not.toBeNull()
    await user.type(screen.getByRole('searchbox', { name: 'Search memory' }), 'Forest')
    expect(screen.queryByText(new RegExp(receipt.receiptId))).toBeNull()
    expect(await screen.findByRole('button', { name: /Forest Guardian/ })).not.toBeNull()
  })

  it('revalidates source and record before displaying an async restore plan after search', async () => {
    const user = userEvent.setup()
    const demo = transport()
    const record = (await demo.searchMemory({ query: 'card-0001', page: 1, pageSize: 10 })).records[0]!
    const plan = await demo.planMemoryChange({ sourceId: record.sourceId, recordId: record.id, operation: 'update', expectedSourceRevision: 4, expectedRecordRevision: record.revision, changes: { title: 'Async search restore' } })
    await demo.executeMemoryChange({ planId: plan.planId, digest: plan.digest })
    const original = demo.planMemoryRestore.bind(demo)
    let release: (() => void) | undefined
    vi.spyOn(demo, 'planMemoryRestore').mockImplementation((request) => new Promise((resolve, reject) => { release = () => void original(request).then(resolve, reject) }))
    render(<MemoryPage transport={demo} />)
    await user.click(await screen.findByRole('tab', { name: 'History' }))
    await user.click(await screen.findByRole('button', { name: 'Restore version' }))
    await user.type(screen.getByRole('searchbox', { name: 'Search memory' }), 'Forest')
    await screen.findByRole('button', { name: /Forest Guardian/ })
    await act(async () => { release?.() })
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Review version restore' })).toBeNull())
  })

  it('runs edit review, verified snapshot, receipt, and one-click restore', async () => {
    const user = userEvent.setup()
    render(<MemoryPage transport={transport()} />)
    await screen.findAllByText('Lightning Drake')
    await user.click(screen.getByRole('button', { name: 'Edit draft' }))
    const editor = screen.getByRole('textbox', { name: 'Content' })
    await user.clear(editor)
    await user.type(editor, 'Updated safe card-search note.')
    await user.click(screen.getByRole('button', { name: 'Review diff' }))
    expect(screen.getByText('Verified snapshot')).not.toBeNull()
    expect(screen.getByText(/expected revision/i)).not.toBeNull()
    await user.click(screen.getByRole('button', { name: 'Apply local change' }))
    expect(await screen.findByRole('heading', { name: 'Change receipt' })).not.toBeNull()
    expect(screen.getByRole('dialog').contains(document.activeElement)).toBe(true)
    expect(screen.getByText('Correlation ID')).not.toBeNull()
    await user.click(screen.getByRole('button', { name: 'Restore snapshot' }))
    expect(await screen.findByText(/restore receipt/i)).not.toBeNull()
    expect(screen.getByRole('dialog').contains(document.activeElement)).toBe(true)
  })

  it('does not resurrect or execute a review after the draft changes while planning', async () => {
    const user = userEvent.setup()
    const demo = transport()
    const originalPlan = demo.planMemoryChange.bind(demo)
    let releaseReview: (() => void) | undefined
    const planSpy = vi.spyOn(demo, 'planMemoryChange')
    planSpy.mockImplementationOnce((request) => new Promise((resolve, reject) => { releaseReview = () => void originalPlan(request).then(resolve, reject) }))
    planSpy.mockImplementation(originalPlan)
    const execute = vi.spyOn(demo, 'executeMemoryChange')
    render(<MemoryPage transport={demo} />)
    await screen.findAllByText('Lightning Drake')
    await user.click(screen.getByRole('button', { name: 'Edit draft' }))
    const editor = screen.getByRole('textbox', { name: 'Content' }) as HTMLTextAreaElement
    await user.clear(editor); await user.type(editor, 'First reviewed draft.')
    await user.click(screen.getByRole('button', { name: 'Review diff' }))
    await user.clear(editor); await user.type(editor, 'Second unreviewed draft.')
    expect(editor.value).toBe('Second unreviewed draft.')
    await act(async () => { releaseReview?.() })
    expect(screen.queryByRole('button', { name: 'Apply local change' })).toBeNull()
    expect(document.activeElement).toBe(editor)
    await user.keyboard(' ')
    expect(execute).not.toHaveBeenCalled()
    expect(editor.value).toBe('Second unreviewed draft. ')
    await user.click(screen.getByRole('button', { name: 'Review diff' }))
    expect(await screen.findByRole('button', { name: 'Apply local change' })).not.toBeNull()
    expect(screen.getAllByRole('cell').some((cell) => cell.textContent === 'Second unreviewed draft. ')).toBe(true)
  })

  it('discards a pending review when its operation or source and record revisions change', async () => {
    const demo = transport()
    const record = (await demo.searchMemory({ query: 'card-0001', page: 1, pageSize: 10 })).records[0]!
    const originalPlan = demo.planMemoryChange.bind(demo)
    let releaseReview: (() => void) | undefined
    vi.spyOn(demo, 'planMemoryChange').mockImplementationOnce((request) => new Promise((resolve, reject) => { releaseReview = () => void originalPlan(request).then(resolve, reject) }))
    const props = { transport: demo, onClose: () => undefined, onChanged: async () => undefined }
    const view = render(<MemoryEditor {...props} record={record} sourceRevision={4} operation="update" />)
    fireEvent.change(screen.getByRole('textbox', { name: 'Content' }), { target: { value: 'Pending old-context draft.' } })
    fireEvent.click(screen.getByRole('button', { name: 'Review diff' }))
    view.rerender(<MemoryEditor {...props} record={{ ...record, revision: record.revision + 1 }} sourceRevision={5} operation="quarantine" />)
    await act(async () => { releaseReview?.() })
    expect(screen.queryByRole('button', { name: 'Apply local change' })).toBeNull()
    expect(screen.getByRole('button', { name: 'Review diff' })).not.toBeNull()
  })

  it('focuses the durable Memory heading after a successful History version restore settles', async () => {
    const user = userEvent.setup()
    const demo = transport()
    const record = (await demo.searchMemory({ query: 'card-0001', page: 1, pageSize: 10 })).records[0]!
    const plan = await demo.planMemoryChange({ sourceId: record.sourceId, recordId: record.id, operation: 'update', expectedSourceRevision: 4, expectedRecordRevision: record.revision, changes: { title: 'Restorable history title' } })
    await demo.executeMemoryChange({ planId: plan.planId, digest: plan.digest })
    render(<MemoryPage transport={demo} />)
    const heading = await screen.findByRole('heading', { name: 'Memory Vault' })
    await user.click(await screen.findByRole('tab', { name: 'History' }))
    await user.click(await screen.findByRole('button', { name: 'Restore version' }))
    await user.click(await screen.findByRole('button', { name: 'Restore exact version' }))
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Review version restore' })).toBeNull())
    await waitFor(() => expect(screen.getByText(/Current revision 4/)).not.toBeNull())
    await new Promise((resolve) => window.setTimeout(resolve, 250))
    expect(document.activeElement).toBe(heading)
    expect(document.activeElement).not.toBe(document.body)
  })

  it('keeps History restore failures inside the modal and focuses an exact retry', async () => {
    const user = userEvent.setup()
    const demo = transport()
    const record = (await demo.searchMemory({ query: 'card-0001', page: 1, pageSize: 10 })).records[0]!
    const change = await demo.planMemoryChange({ sourceId: record.sourceId, recordId: record.id, operation: 'update', expectedSourceRevision: 4, expectedRecordRevision: record.revision, changes: { title: 'Retryable history title' } })
    await demo.executeMemoryChange({ planId: change.planId, digest: change.digest })
    const original = demo.executeMemoryRestore.bind(demo)
    let calls = 0
    let releaseRetry: (() => void) | undefined
    vi.spyOn(demo, 'executeMemoryRestore').mockImplementation(async (request) => {
      calls += 1
      if (calls === 1) throw new Error('Snapshot changed while restoring.')
      await new Promise<void>((resolve) => { releaseRetry = resolve })
      return original(request)
    })
    render(<MemoryPage transport={demo} />)
    await user.click(await screen.findByRole('tab', { name: 'History' }))
    await user.click(await screen.findByRole('button', { name: 'Restore version' }))
    const dialog = await screen.findByRole('dialog', { name: 'Review version restore' })
    await user.click(within(dialog).getByRole('button', { name: 'Restore exact version' }))
    const retry = await within(dialog).findByRole('button', { name: 'Retry restore' })
    expect(within(dialog).getByRole('alert').textContent).toMatch(/snapshot changed/i)
    await waitFor(() => expect(document.activeElement).toBe(retry))
    await user.click(retry)
    expect(dialog.contains(document.activeElement)).toBe(true)
    expect(document.activeElement).toBe(retry)
    releaseRetry?.()
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Review version restore' })).toBeNull())
    expect(calls).toBe(2)
  })

  it('restores the exact History opener when Escape closes a failed restore review', async () => {
    const user = userEvent.setup()
    const demo = transport()
    const record = (await demo.searchMemory({ query: 'card-0001', page: 1, pageSize: 10 })).records[0]!
    const change = await demo.planMemoryChange({ sourceId: record.sourceId, recordId: record.id, operation: 'update', expectedSourceRevision: 4, expectedRecordRevision: record.revision, changes: { title: 'Escape restore title' } })
    await demo.executeMemoryChange({ planId: change.planId, digest: change.digest })
    vi.spyOn(demo, 'executeMemoryRestore').mockRejectedValue(new Error('Restore service is temporarily unavailable.'))
    render(<MemoryPage transport={demo} />)
    await user.click(await screen.findByRole('tab', { name: 'History' }))
    const opener = await screen.findByRole('button', { name: 'Restore version' })
    await user.click(opener)
    const dialog = await screen.findByRole('dialog', { name: 'Review version restore' })
    await user.click(within(dialog).getByRole('button', { name: 'Restore exact version' }))
    await within(dialog).findByRole('button', { name: 'Retry restore' })

    await user.keyboard('{Escape}')

    expect(screen.queryByRole('dialog', { name: 'Review version restore' })).toBeNull()
    expect(document.activeElement).toBe(opener)
  })

  it('guards a History restore retry against double submit', async () => {
    const demo = transport()
    const record = (await demo.searchMemory({ query: 'card-0001', page: 1, pageSize: 10 })).records[0]!
    const change = await demo.planMemoryChange({ sourceId: record.sourceId, recordId: record.id, operation: 'update', expectedSourceRevision: 4, expectedRecordRevision: record.revision, changes: { title: 'Guarded retry title' } })
    await demo.executeMemoryChange({ planId: change.planId, digest: change.digest })
    const original = demo.executeMemoryRestore.bind(demo)
    let calls = 0
    let releaseRetry: (() => void) | undefined
    vi.spyOn(demo, 'executeMemoryRestore').mockImplementation(async (request) => {
      calls += 1
      if (calls === 1) throw new Error('Restore service is temporarily unavailable.')
      await new Promise<void>((resolve) => { releaseRetry = resolve })
      return original(request)
    })
    render(<MemoryPage transport={demo} />)
    fireEvent.click(await screen.findByRole('tab', { name: 'History' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Restore version' }))
    const dialog = await screen.findByRole('dialog', { name: 'Review version restore' })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Restore exact version' }))
    const retry = await within(dialog).findByRole('button', { name: 'Retry restore' })

    fireEvent.click(retry); fireEvent.click(retry)

    expect(calls).toBe(2)
    releaseRetry?.()
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Review version restore' })).toBeNull())
  })

  it.each([
    ['plan_expired', 'Restore plan expired.'],
    ['conflict', 'Memory record changed after review.'],
    ['plan_replayed', 'Restore plan was already used.'],
    ['outcome_uncertain', 'The restore result could not be confirmed.'],
  ] as const)('does not retry a terminal History %s result with the same plan', async (code, message) => {
    const user = userEvent.setup()
    const demo = transport()
    const record = (await demo.searchMemory({ query: 'card-0001', page: 1, pageSize: 10 })).records[0]!
    const change = await demo.planMemoryChange({ sourceId: record.sourceId, recordId: record.id, operation: 'update', expectedSourceRevision: 4, expectedRecordRevision: record.revision, changes: { title: `Terminal ${code} title` } })
    await demo.executeMemoryChange({ planId: change.planId, digest: change.digest })
    let calls = 0
    vi.spyOn(demo, 'executeMemoryRestore').mockImplementation(async () => {
      calls += 1
      throw new TransportError(code, message)
    })
    render(<MemoryPage transport={demo} />)
    await user.click(await screen.findByRole('tab', { name: 'History' }))
    await user.click(await screen.findByRole('button', { name: 'Restore version' }))
    const dialog = await screen.findByRole('dialog', { name: 'Review version restore' })
    await user.click(within(dialog).getByRole('button', { name: 'Restore exact version' }))

    expect(await within(dialog).findByText(message)).not.toBeNull()
    expect(within(dialog).queryByRole('button', { name: 'Retry restore' })).toBeNull()
    expect(within(dialog).getByRole('button', { name: 'Close and refresh' })).not.toBeNull()
    expect(calls).toBe(1)
  })

  it('does not replay a stale source and query after History restore refresh is superseded', async () => {
    const user = userEvent.setup()
    const demo = transport()
    const record = (await demo.searchMemory({ query: 'card-0001', page: 1, pageSize: 10 })).records[0]!
    const plan = await demo.planMemoryChange({ sourceId: record.sourceId, recordId: record.id, operation: 'update', expectedSourceRevision: 4, expectedRecordRevision: record.revision, changes: { title: 'Restore refresh race' } })
    await demo.executeMemoryChange({ planId: plan.planId, digest: plan.digest })
    const refreshedVault = await demo.getVault()
    render(<MemoryPage transport={demo} />)
    await user.click(await screen.findByRole('tab', { name: 'History' }))
    await user.click(await screen.findByRole('button', { name: 'Restore version' }))

    const vaultGate = deferred<typeof refreshedVault>()
    let refreshStarted = false
    vi.spyOn(demo, 'getVault').mockImplementationOnce(() => { refreshStarted = true; return vaultGate.promise })
    const originalSearch = demo.searchMemory.bind(demo)
    const requests: Array<{ query: string; sourceId?: string }> = []
    vi.spyOn(demo, 'searchMemory').mockImplementation((request) => { requests.push({ query: request.query, sourceId: request.sourceId }); return originalSearch(request) })
    await user.click(screen.getByRole('button', { name: 'Restore exact version' }))
    await waitFor(() => expect(refreshStarted).toBe(true))
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Review version restore' })).toBeNull())

    const sqliteSource = screen.getByRole('button', { name: /Mev BOT SQLite memory/ })
    await user.click(sqliteSource)
    const search = screen.getByRole('searchbox', { name: 'Search memory' })
    await user.type(search, 'sqlite-race')
    await waitFor(() => expect(requests.at(-1)).toEqual({ query: 'sqlite-race', sourceId: 'mev-sqlite' }))
    requests.length = 0
    await act(async () => { vaultGate.resolve(refreshedVault); await new Promise((resolve) => window.setTimeout(resolve, 10)) })

    expect(requests.some((request) => request.sourceId !== 'mev-sqlite' || request.query !== 'sqlite-race')).toBe(false)
    expect(sqliteSource.classList.contains('selected')).toBe(true)
    expect((search as HTMLInputElement).value).toBe('sqlite-race')
    expect(screen.queryByRole('button', { name: /Lightning Drake/ })).toBeNull()
    expect(screen.getByText('No records match this bounded local search.')).not.toBeNull()
  })

  it('captures Escape and closes after async Apply and Restore replace the active control', async () => {
    const user = userEvent.setup()
    async function applyChange() {
      await screen.findAllByText('Lightning Drake')
      await user.click(screen.getByRole('button', { name: 'Edit draft' }))
      const editor = screen.getByRole('textbox', { name: 'Content' })
      await user.clear(editor); await user.type(editor, 'Focus-safe local change.')
      await user.click(screen.getByRole('button', { name: 'Review diff' }))
      await user.click(screen.getByRole('button', { name: 'Apply local change' }))
      await screen.findByRole('heading', { name: 'Change receipt' })
      await waitFor(() => expect((screen.getByRole('button', { name: 'Close Change receipt' }) as HTMLButtonElement).disabled).toBe(false))
      expect(screen.getByRole('dialog').contains(document.activeElement)).toBe(true)
    }

    const first = render(<MemoryPage transport={transport()} />)
    await applyChange()
    document.body.tabIndex = -1; document.body.focus()
    expect(document.activeElement).toBe(document.body)
    fireEvent.keyDown(document, { key: 'Escape' })
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(document.activeElement).toBe(screen.getByRole('heading', { name: 'Memory Vault' }))
    first.unmount()

    render(<MemoryPage transport={transport()} />)
    await applyChange()
    await user.click(screen.getByRole('button', { name: 'Restore snapshot' }))
    await screen.findByText(/restore receipt/i)
    await waitFor(() => expect((screen.getByRole('button', { name: 'Close Change receipt' }) as HTMLButtonElement).disabled).toBe(false))
    expect(screen.getByRole('dialog').contains(document.activeElement)).toBe(true)
    document.body.focus()
    fireEvent.keyDown(document, { key: 'Escape' })
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(document.activeElement).toBe(screen.getByRole('heading', { name: 'Memory Vault' }))
    document.body.removeAttribute('tabindex')
  })

  it('focuses the durable Memory heading after a successful operation disables its opener', async () => {
    const user = userEvent.setup()
    render(<MemoryPage transport={transport()} />)
    const heading = await screen.findByRole('heading', { name: 'Memory Vault' })
    await screen.findAllByText('Lightning Drake')
    await user.click(screen.getByRole('button', { name: 'Exclude from retrieval' }))
    await user.click(screen.getByRole('button', { name: 'Review diff' }))
    await user.click(screen.getByRole('button', { name: 'Apply local change' }))
    await screen.findByRole('heading', { name: 'Change receipt' })
    await user.click(screen.getByRole('button', { name: 'Close Change receipt' }))
    expect(document.activeElement).toBe(heading)
    expect(document.activeElement).not.toBe(document.body)
  })

  it('validates and applies an editable advanced Raw JSON draft with an exact diff', async () => {
    const user = userEvent.setup()
    render(<MemoryPage transport={transport()} />)
    await screen.findAllByText('Lightning Drake')
    await user.click(screen.getByRole('button', { name: 'Edit draft' }))
    const structured = screen.getByRole('tab', { name: 'Structured' })
    structured.focus(); await user.keyboard('{End}')
    expect(document.activeElement).toBe(screen.getByRole('tab', { name: 'Raw JSON' }))
    const raw = screen.getByRole('textbox', { name: 'Raw JSON draft' })
    fireEvent.change(raw, { target: { value: '{"title":"One","title":"Two","content":"safe","tags":[],"collection":"card-search"}' } })
    await user.click(screen.getByRole('button', { name: 'Review diff' }))
    expect(screen.getByRole('alert').textContent).toMatch(/duplicate key/i)
    fireEvent.change(raw, { target: { value: JSON.stringify({ title: 'Lightning Drake revised', content: 'Raw edited safe note.', tags: ['card', 'raw'], collection: 'card-search' }) } })
    await user.click(screen.getByRole('button', { name: 'Review diff' }))
    expect(screen.getByText('title', { selector: 'th' })).not.toBeNull()
    expect(screen.getByText('tags', { selector: 'th' })).not.toBeNull()
  })

  it('redacts sensitive values in plan previews', async () => {
    const user = userEvent.setup()
    render(<MemoryPage transport={transport()} />)
    await screen.findAllByText('Lightning Drake')
    await user.click(screen.getByRole('button', { name: 'Edit draft' }))
    const editor = screen.getByRole('textbox', { name: 'Content' })
    await user.clear(editor); await user.type(editor, ['sk-proj-', 'fixtureabcdefghijklmnopqrstuvwxyz0123456789'].join(''))
    await user.click(screen.getByRole('button', { name: 'Review diff' }))
    const review = screen.getByRole('region', { name: 'Review exact field diff' })
    expect(within(review).queryByText(/sk-proj-/)).toBeNull()
    expect(within(review).getByText('[REDACTED]')).not.toBeNull()
  })

  it('uses centralized URL and path redaction in Memory plan previews', async () => {
    const user = userEvent.setup()
    const syntheticUserInfo = ['fixture-user', 'fixture-pass'].join(':')
    const protocolRelativeUrl = ['', '', `${syntheticUserInfo}@example.test`, 'safe'].join('/')
    const remoteUrl = ['https:', '', 'example.test', 'safe'].join('/')
    const localPath = ['', 'private', 'memory-fixture.json'].join('/')
    render(<MemoryPage transport={transport()} />)
    await screen.findAllByText('Lightning Drake')
    await user.click(screen.getByRole('button', { name: 'Edit draft' }))
    fireEvent.change(screen.getByRole('textbox', { name: 'Title' }), { target: { value: protocolRelativeUrl } })
    fireEvent.change(screen.getByRole('textbox', { name: 'Content' }), { target: { value: `${remoteUrl};cwd=${localPath}` } })
    await user.click(screen.getByRole('button', { name: 'Review diff' }))

    const review = screen.getByRole('region', { name: 'Review exact field diff' })
    expect(within(review).getByText('//[REDACTED]@example.test/safe')).not.toBeNull()
    expect(within(review).getByText('[REDACTED_PATH]')).not.toBeNull()
    expect(review.textContent).not.toContain(syntheticUserInfo)
    expect(review.textContent).not.toContain(localPath)
  })
})
