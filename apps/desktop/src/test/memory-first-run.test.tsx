import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'

import { MemoryPage } from '../features/memory/MemoryPage'
import { TauriTransport } from '../transport/tauri'

const revision = 'a'.repeat(64)
const capabilities = { readable: true, queryable: true, editable: false, snapshot: false, restore: false, reason: null }
const source = { source_id: 'local-json', format: 'json', capabilities, revision }
const record = { record_id: 'record-1', namespace: 'default', content: 'First local memory', metadata: {}, embedding_present: false, source_revision: revision, editable_fields: [] }

function nativeVaultFixture({ registered = false, inventoryReady }: { registered?: boolean; inventoryReady?: Promise<void> } = {}) {
  const requests: Array<{ method: string; payload: Record<string, unknown> }> = []
  const reply = (method: string, result: unknown) => ({ requestId: '11111111-1111-4111-8111-111111111111', method, result })
  const transport = new TauriTransport(async (_command: string, arguments_: unknown) => {
    const request = (arguments_ as { request: { method: string; payload: Record<string, unknown> } }).request
    requests.push(request)
    switch (request.method) {
      case 'doctor': return reply(request.method, { healthy: true, checks: ['vault.list', 'vault.query', 'vault.get', 'vault.register'].map((method) => ({ name: `method:${method}`, ok: true })), warnings: [] })
      case 'vault.list':
        await inventoryReady
        return reply(request.method, { sources: registered ? [source] : [], next_cursor: null, local_only_warning: 'Local only.' })
      case 'vault.register':
        registered = true
        return reply(request.method, { format: 'json', recognized: true, capabilities, reason: null, read_only: true, selected_locally: true, local_only_warning: 'Local only.' })
      case 'vault.query': {
        const text = request.payload.text as string | null
        const records = !text || record.content.toLowerCase().includes(text.toLowerCase()) ? [record] : []
        return reply(request.method, { records, total: records.length, next_cursor: null, local_only_warning: 'Local only.' })
      }
      default: throw new Error(`Unexpected native method ${request.method}`)
    }
  })
  return { transport, requests }
}

describe('native Memory Vault first run', () => {
  it('keeps an empty vault idle when search is attempted and points to source registration', async () => {
    const fixture = nativeVaultFixture()
    const user = userEvent.setup()
    render(<MemoryPage transport={fixture.transport} />)
    await screen.findByRole('complementary', { name: 'Memory sources' })
    const search = screen.getByRole<HTMLInputElement>('searchbox', { name: 'Search memory' })

    await user.type(search, 'anything')

    expect(screen.queryByText('Loading local memory…')).toBeNull()
    expect(search.disabled).toBe(true)
    expect(search.value).toBe('')
    expect(fixture.requests.some((request) => request.method === 'vault.query')).toBe(false)
    expect(screen.getByText(/No local sources are registered\./).textContent).toMatch(/Local source path.*Register local source/)
    expect(screen.getByRole<HTMLInputElement>('textbox', { name: 'Local source path' }).disabled).toBe(false)
  })

  it('does not abandon source loading when search is attempted before inventory arrives', async () => {
    let resolveInventory!: () => void
    const inventoryReady = new Promise<void>((resolve) => { resolveInventory = resolve })
    const fixture = nativeVaultFixture({ registered: true, inventoryReady })
    const user = userEvent.setup()
    render(<MemoryPage transport={fixture.transport} />)
    const search = screen.getByRole<HTMLInputElement>('searchbox', { name: 'Search memory' })

    await user.type(search, 'anything')
    await act(async () => { resolveInventory() })

    await screen.findByText('First local memory')
    expect(search.disabled).toBe(false)
    expect(search.value).toBe('')
    expect(screen.queryByText('Loading local memory…')).toBeNull()
  })

  it('enables bounded search after the first local source is registered', async () => {
    const fixture = nativeVaultFixture()
    const user = userEvent.setup()
    render(<MemoryPage transport={fixture.transport} />)
    await user.type(await screen.findByRole('textbox', { name: 'Local source path' }), 'C:\\fixture\\memory.json')
    await user.click(screen.getByRole('button', { name: 'Register local source' }))
    await screen.findByText('First local memory')
    expect(fixture.requests.find((request) => request.method === 'vault.register')?.payload).toEqual({ path: 'C:\\fixture\\memory.json' })
    const search = screen.getByRole<HTMLInputElement>('searchbox', { name: 'Search memory' })
    expect(search.disabled).toBe(false)
    expect(screen.queryByText(/No local sources are registered\./)).toBeNull()

    await user.type(search, 'missing')

    await waitFor(() => expect(fixture.requests.filter((request) => request.method === 'vault.query').at(-1)?.payload).toEqual({ sourceId: 'local-json', namespace: null, text: 'missing', limit: 25 }))
    expect(await screen.findByText('No records match this bounded local search.')).not.toBeNull()
    expect(screen.queryByText('First local memory')).toBeNull()
    await user.clear(search)
    await screen.findByText('First local memory')
  })
})
