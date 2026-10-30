import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react'

import { Dialog } from '../../components/Dialog'
import { useTabs } from '../../components/useTabs'
import { TransportError } from '../../transport'
import type { EngineTransport, MemoryHistoryEntry, MemoryOperation, MemoryRecord, MemorySource, RestorePlan } from '../../transport'
import { MemoryEditor } from './MemoryEditor'
import { NativeMemoryEditor } from './NativeMemoryEditor'
import { NativeSnapshotHistory } from './NativeSnapshotHistory'

const tabs = ['Content', 'Metadata', 'References', 'History'] as const
function hasNumericRevision(record: MemoryRecord): record is MemoryRecord & { revision: number } { return typeof record.revision === 'number' }
type InspectorTab = (typeof tabs)[number]
interface RestoreFailure { message: string; retryable: boolean; outcomeUncertain: boolean }

const terminalRestoreCodes = new Set(['plan_expired', 'plan_changed', 'plan_replayed', 'conflict', 'source_changed', 'outcome_uncertain'])

function restoreFailure(reason: unknown): RestoreFailure {
  const message = reason instanceof Error ? reason.message : 'Nothing was restored. Refresh and review a new restore plan.'
  if (!(reason instanceof TransportError) || !terminalRestoreCodes.has(reason.code)) return { message, retryable: true, outcomeUncertain: false }
  return { message, retryable: false, outcomeUncertain: reason.code === 'outcome_uncertain' }
}

function searchableSource(sources: MemorySource[], previous?: string) {
  const available = (source: MemorySource) => source.capabilities.includes('search')
  if (previous && sources.some((source) => source.id === previous && available(source))) return previous
  return sources.find(available)?.id
}

export function MemoryPage({ transport }: { transport: EngineTransport }) {
  const [sources, setSources] = useState<MemorySource[]>([])
  const [records, setRecords] = useState<MemoryRecord[]>([])
  const [memoryPage, setMemoryPage] = useState(1)
  const [memoryNextCursor, setMemoryNextCursor] = useState<string | null>(null)
  const [memoryTotal, setMemoryTotal] = useState(0)
  const [selectedSource, setSelectedSource] = useState<string>()
  const [selected, setSelected] = useState<MemoryRecord>()
  const [query, setQuery] = useState('')
  const [tab, setTab] = useState<InspectorTab>('Content')
  const [editing, setEditing] = useState(false)
  const [operation, setOperation] = useState<Exclude<MemoryOperation, 'restore'>>('update')
  const [registrationPath, setRegistrationPath] = useState('')
  const [registering, setRegistering] = useState(false)
  const [history, setHistory] = useState<{ key: string; entries: MemoryHistoryEntry[] }>({ key: '', entries: [] })
  const [historyError, setHistoryError] = useState<{ key: string; message: string }>({ key: '', message: '' })
  const [restorePlan, setRestorePlan] = useState<RestorePlan>()
  const [restoreBusy, setRestoreBusy] = useState(false)
  const [restoreError, setRestoreError] = useState<RestoreFailure | null>(null)
  const [loading, setLoading] = useState(transport.capabilities.vaultRead)
  const [error, setError] = useState(transport.capabilities.vaultRead ? '' : 'Memory Vault reading is unavailable from this transport.')
  const generation = useRef(0)
  const historyGeneration = useRef(0)
  const restoreReviewGeneration = useRef(0)
  const selectedSourceRef = useRef<string | undefined>(undefined)
  const queryRef = useRef('')
  const selectedRef = useRef<MemoryRecord | undefined>(undefined)
  const pageCursors = useRef(new Map<string, Map<number, string | null>>())
  const headingRef = useRef<HTMLHeadingElement>(null)
  const actionOpenerRef = useRef<HTMLElement | null>(null)
  const versionOpenerRef = useRef<HTMLElement | null>(null)
  const restoreRetryRef = useRef<HTMLButtonElement>(null)
  const restorePending = useRef(false)
  const tabUi = useTabs(tabs, tab, setTab)
  const cursorKey = (sourceId: string, queryValue: string, revision: number | string | undefined) => JSON.stringify([sourceId, queryValue, revision ?? null])
  const cursorLedger = (key: string) => {
    const existing = pageCursors.current.get(key)
    if (existing) return existing
    const created = new Map<number, string | null>()
    pageCursors.current.set(key, created)
    while (pageCursors.current.size > 32) pageCursors.current.delete(pageCursors.current.keys().next().value as string)
    return created
  }

  useLayoutEffect(() => {
    if (restoreError && !restoreBusy) restoreRetryRef.current?.focus()
  }, [restoreError, restoreBusy])

  const selectRecord = useCallback((record?: MemoryRecord) => {
    restoreReviewGeneration.current += 1
    historyGeneration.current += 1
    selectedRef.current = record
    setRestorePlan(undefined)
    setRestoreError(null)
    setHistory({ key: '', entries: [] })
    setHistoryError({ key: '', message: '' })
    setSelected(record)
  }, [])

  async function loadSources() {
    if (!transport.capabilities.vaultRead) { setLoading(false); setError('Memory Vault reading is unavailable from this transport.'); return }
    const current = ++generation.current; setLoading(true); setError('')
    try {
      const vault = await transport.getVault()
      if (current !== generation.current) return
      const previous = selectedSourceRef.current
      const next = searchableSource(vault.sources, previous)
      selectedSourceRef.current = next
      setSources(vault.sources); setSelectedSource(next)
    } catch (reason) { if (current === generation.current) setError(reason instanceof Error ? reason.message : 'Memory sources are unavailable.') }
    finally { if (current === generation.current) setLoading(false) }
  }

  async function refreshCurrentView() {
    const current = ++generation.current
    const querySnapshot = queryRef.current
    pageCursors.current.clear()
    setMemoryPage(1); setMemoryNextCursor(null); setMemoryTotal(0)
    let sourceSnapshot = selectedSourceRef.current
    setLoading(true); setError('')
    try {
      const vault = await transport.getVault()
      if (current !== generation.current || queryRef.current !== querySnapshot || selectedSourceRef.current !== sourceSnapshot) return
      const resolvedSource = searchableSource(vault.sources, sourceSnapshot)
      sourceSnapshot = resolvedSource
      selectedSourceRef.current = resolvedSource
      if (!resolvedSource) { setSources(vault.sources); setSelectedSource(resolvedSource); setRecords([]); selectRecord(undefined); return }
      const result = await transport.searchMemory({ query: querySnapshot, sourceId: resolvedSource, page: 1, pageSize: 25 })
      if (current !== generation.current || queryRef.current !== querySnapshot || selectedSourceRef.current !== resolvedSource) return
      const previous = selectedRef.current
      setSources(vault.sources); setSelectedSource(resolvedSource)
      cursorLedger(cursorKey(resolvedSource, querySnapshot, vault.sources.find((item) => item.id === resolvedSource)?.revision)).set(2, result.nextCursor); setMemoryPage(1); setMemoryNextCursor(result.nextCursor); setMemoryTotal(result.total)
      setRecords(result.records); selectRecord(result.records.find((record) => record.id === previous?.id) ?? result.records[0])
    } catch (reason) { if (current === generation.current && queryRef.current === querySnapshot && selectedSourceRef.current === sourceSnapshot) setError(reason instanceof Error ? reason.message : 'Memory refresh failed.'); if (transport.mode === 'native') throw reason }
    finally { if (current === generation.current && queryRef.current === querySnapshot && selectedSourceRef.current === sourceSnapshot) setLoading(false) }
  }

  async function registerSource() {
    if (registering || !registrationPath.trim() || !transport.registerMemorySource) return
    setRegistering(true); setError('')
    try { await transport.registerMemorySource(registrationPath); setRegistrationPath(''); await refreshCurrentView() }
    catch (reason) { setError(reason instanceof Error ? reason.message : 'The selected local source could not be registered.') }
    finally { setRegistering(false) }
  }

  async function loadMemoryPage(page: number, cursor: string | null) {
    if (!selectedSource) return
    const sourceSnapshot = selectedSource
    const querySnapshot = query
    const key = cursorKey(sourceSnapshot, querySnapshot, sources.find((item) => item.id === sourceSnapshot)?.revision)
    const ledger = cursorLedger(key)
    const current = ++generation.current
    setLoading(true); setError('')
    try {
      const result = await transport.searchMemory({ query: querySnapshot, sourceId: sourceSnapshot, page, pageSize: 25, cursor })
      if (current !== generation.current || queryRef.current !== querySnapshot || selectedSourceRef.current !== sourceSnapshot) return
      ledger.set(page + 1, result.nextCursor); setMemoryPage(page); setMemoryNextCursor(result.nextCursor); setMemoryTotal(result.total); setRecords(result.records); selectRecord(result.records[0])
    } catch (reason) {
      if (pageCursors.current.get(key) === ledger) pageCursors.current.delete(key)
      if (current === generation.current && queryRef.current === querySnapshot && selectedSourceRef.current === sourceSnapshot) {
        setMemoryPage(1); setMemoryNextCursor(null); setMemoryTotal(0); setRecords([]); selectRecord(undefined)
        setError(reason instanceof Error ? reason.message : 'Memory search failed.')
      }
    } finally {
      if (current === generation.current && queryRef.current === querySnapshot && selectedSourceRef.current === sourceSnapshot) setLoading(false)
    }
  }

  useEffect(() => {
    if (!transport.capabilities.vaultRead) {
      return
    }
    const current = ++generation.current
    void transport.getVault().then((vault) => {
      if (current !== generation.current) return
      const previous = selectedSourceRef.current
      const next = searchableSource(vault.sources, previous)
      selectedSourceRef.current = next
      setSources(vault.sources); setSelectedSource(next); setLoading(false)
    }).catch((reason: unknown) => { if (current === generation.current) { setError(reason instanceof Error ? reason.message : 'Memory sources are unavailable.'); setLoading(false) } })
    return () => { generation.current += 1 }
  }, [transport])
  useEffect(() => {
    if (!selectedSource) return
    const source = sources.find((item) => item.id === selectedSource)
    if (!source?.capabilities.includes('search')) {
      return
    }
    const current = ++generation.current
    void transport.searchMemory({ query, sourceId: selectedSource, page: 1, pageSize: 25 }).then((result) => {
      if (current !== generation.current || queryRef.current !== query || selectedSourceRef.current !== selectedSource) return
      const previous = selectedRef.current
      cursorLedger(cursorKey(selectedSource, query, source.revision)).set(2, result.nextCursor); setMemoryPage(1); setMemoryNextCursor(result.nextCursor); setMemoryTotal(result.total); setRecords(result.records); selectRecord(result.records.find((record) => record.id === previous?.id) ?? result.records[0]); setLoading(false)
    }).catch((reason: unknown) => { if (current === generation.current && queryRef.current === query && selectedSourceRef.current === selectedSource) { setError(reason instanceof Error ? reason.message : 'Memory search failed.'); setLoading(false) } })
  }, [query, selectedSource, sources, transport, selectRecord])
  useEffect(() => {
    if (!selected) return
    if (transport.mode === 'native') return
    if (!transport.capabilities.memoryHistory) {
      return
    }
    const current = ++historyGeneration.current
    const key = `${selected.sourceId}:${selected.id}`
    void transport.getMemoryHistory(selected.sourceId, selected.id).then((value) => { if (historyGeneration.current === current) setHistory({ key, entries: value }) }).catch((reason: unknown) => { if (historyGeneration.current === current) setHistoryError({ key, message: reason instanceof Error ? reason.message : 'Memory history is unavailable.' }) })
    return () => { historyGeneration.current += 1 }
  }, [selected, transport])

  async function reviewVersionRestore(entry: MemoryHistoryEntry) {
    if (!selected || typeof selected.revision !== 'number' || entry.sourceId !== selected.sourceId || entry.recordId !== selected.id || !entry.receiptId || !entry.snapshotId) return
    const current = ++restoreReviewGeneration.current
    const sourceId = selected.sourceId
    const recordId = selected.id
    const key = `${sourceId}:${recordId}`
    setHistoryError({ key: '', message: '' })
    setRestoreError(null)
    try {
      const next = await transport.planMemoryRestore({ receiptId: entry.receiptId, snapshotId: entry.snapshotId, expectedRecordRevision: selected.revision })
      const active = selectedRef.current
      if (current === restoreReviewGeneration.current && active?.sourceId === sourceId && active.id === recordId && next.sourceId === sourceId && next.recordId === recordId) setRestorePlan(next)
    } catch (reason) { if (current === restoreReviewGeneration.current) setHistoryError({ key, message: reason instanceof Error ? reason.message : 'Version restore review failed.' }) }
  }

  async function restoreVersion() {
    const active = selectedRef.current
    if (!restorePlan || !active || active.sourceId !== restorePlan.sourceId || active.id !== restorePlan.recordId || restorePending.current) return
    restorePending.current = true; setRestoreBusy(true); setHistoryError({ key: '', message: '' })
    try { await transport.executeMemoryRestore({ planId: restorePlan.planId, digest: restorePlan.digest }); versionOpenerRef.current = headingRef.current; setRestorePlan(undefined); await refreshCurrentView() }
    catch (reason) { setRestoreError(restoreFailure(reason)) }
    finally { restorePending.current = false; setRestoreBusy(false) }
  }
  function closeAndRefreshRestore() {
    versionOpenerRef.current = headingRef.current
    setRestoreError(null)
    setRestorePlan(undefined)
    void refreshCurrentView()
  }

  const source = sources.find((item) => item.id === selectedSource)
  const canRegisterSource = transport.mode === 'native' && transport.capabilities.sourceRegistration && Boolean(transport.registerMemorySource)
  const emptyMessage = sources.length === 0
    ? canRegisterSource && !error ? 'No local sources are registered. Enter a JSON or SQLite file path in Local source path above, then select Register local source.' : 'No memory sources are available.'
    : source && !source.capabilities.includes('search') ? 'This source is registered but not queryable.' : 'No records match this bounded local search.'
  const selectedKey = selected ? `${selected.sourceId}:${selected.id}` : ''
  const visibleHistory = history.key === selectedKey ? history.entries : []
  const visibleHistoryError = !transport.capabilities.memoryHistory && selected
    ? 'Version history is unavailable in this native build.'
    : historyError.key === selectedKey ? historyError.message : ''
  return (
    <div className="workspace-page memory-page">
      <header className="workspace-header"><div><p className="eyebrow">Local recovery workspace</p><h1 ref={headingRef} tabIndex={-1} data-route-heading="true">Memory Vault</h1><p>{transport.mode === 'native' ? 'Inspect explicitly registered local sources. Review supported repairs before applying them.' : 'Inspect first, then use verified snapshots and receipts for local records.'}</p></div><span className="demo-pill">{transport.mode === 'native' ? 'LOCAL ENGINE' : 'DEMO LAB'}</span></header>
      <p className="local-warning"><strong>Local-only memory.</strong> {transport.mode === 'native' ? 'Only explicitly registered sources are accessible. Supported scalar repairs require a reviewed plan and verified snapshot; unavailable adapter operations remain read-only.' : 'Records shown here are synthetic demo data. Changes never alter provider moderation, rate limits, credentials, or accounts.'}</p>
      {canRegisterSource && <form className="local-path-form" onSubmit={(event) => { event.preventDefault(); void registerSource() }}><label>Local source path<input aria-label="Local source path" value={registrationPath} maxLength={4096} disabled={registering} onChange={(event) => setRegistrationPath(event.target.value)} placeholder="Enter the exact local JSON or SQLite file path" /></label><button className="secondary-button" type="submit" disabled={registering || !registrationPath.trim()}>{registering ? 'Registering…' : 'Register local source'}</button><p>The engine probes this selected file without modifying it. Registration does not import or upload its contents.</p></form>}
      {error && <div className="error-banner" role="alert"><p>{error}</p><button type="button" className="secondary-button" onClick={() => void loadSources()}>Retry</button></div>}
      <label className="workspace-search"><span>{transport.mode === 'native' ? 'Search the selected source by bounded text query' : 'Search memory by content, ID, tag, collection, source, agent, or time'}</span><input type="search" aria-label="Search memory" value={query} disabled={!transport.capabilities.vaultRead || !source?.capabilities.includes('search')} onChange={(event) => { generation.current += 1; pageCursors.current.clear(); setMemoryPage(1); setMemoryNextCursor(null); setMemoryTotal(0); queryRef.current = event.target.value; selectRecord(undefined); setRecords([]); setLoading(true); setError(''); setQuery(event.target.value) }} /></label>
      {loading && sources.length === 0 ? <p role="status">Loading local memory…</p> : <div className="memory-grid">
        <aside className="memory-sources" aria-label="Memory sources"><h2>Sources</h2><ul>{sources.map((item) => <li key={item.id}><button type="button" className={item.id === selectedSource ? 'selected' : ''} onClick={() => { generation.current += 1; pageCursors.current.clear(); selectedSourceRef.current = item.id; selectRecord(undefined); setMemoryPage(1); setMemoryNextCursor(null); setMemoryTotal(0); setLoading(item.capabilities.includes('search')); setError(''); setRecords([]); setSelectedSource(item.id) }}><strong>{item.name}</strong><span>{item.kind} · {transport.mode === 'native' ? `source digest ${item.revision}` : `rev ${item.revision}`}</span><span>{item.status}</span><small>{item.capabilities.join(', ') || 'Not queryable'}</small></button></li>)}</ul></aside>
        <section className="memory-results" aria-labelledby="results-title"><h2 id="results-title">Records <span>{records.length} of {memoryTotal}</span></h2>{records.length === 0 ? <p className="empty-state">{emptyMessage}</p> : <ul>{records.map((record) => <li key={record.id}><button type="button" className={record.id === selected?.id ? 'selected' : ''} onClick={() => selectRecord(record)}><strong>{record.title}</strong><span>{record.id} · {transport.mode === 'native' ? `source digest ${record.revision}` : `rev ${record.revision}`}</span><small>{record.tags.join(' · ')}</small>{record.syntheticError && <em>Needs re-index</em>}</button></li>)}</ul>}{(memoryTotal > 25 || memoryPage > 1 || Boolean(memoryNextCursor)) && <nav aria-label="Memory pagination"><button type="button" className="secondary-button" disabled={memoryPage <= 1 || loading} onClick={() => void loadMemoryPage(memoryPage - 1, cursorLedger(cursorKey(selectedSource ?? '', query, source?.revision)).get(memoryPage - 1) ?? null)}>Previous page</button><span>Page {memoryPage}</span><button type="button" className="secondary-button" disabled={!memoryNextCursor || loading} onClick={() => void loadMemoryPage(memoryPage + 1, memoryNextCursor)}>Next page</button></nav>}{(memoryPage - 1) * 25 + records.length < memoryTotal && !memoryNextCursor && <p role="alert">More records are available, but the next page cursor was not provided.</p>}</section>
        <section className="memory-inspector" aria-labelledby="inspector-title"><h2 id="inspector-title">Inspector</h2>{selected ? <><div className="record-heading"><div><strong>{selected.title}</strong><span>{selected.id}</span></div><span>{selected.excluded === true ? 'Excluded' : selected.quarantined === true ? 'Quarantined' : selected.excluded === null || selected.quarantined === null ? 'Status not reported' : 'Read-only view'}</span></div><div className="tabs" role="tablist" aria-label="Record inspector">{tabs.map((name, index) => <button key={name} type="button" role="tab" {...tabUi.tabProps(name, index)}>{name}</button>)}</div><div role="tabpanel" tabIndex={0} {...tabUi.panelProps}>
          {tab === 'Content' && <><p>{selected.content}</p><dl><div><dt>Embedding</dt><dd>{selected.embedding}</dd></div></dl></>}
          {tab === 'Metadata' && <dl><div><dt>Writer</dt><dd>{selected.writer ?? 'Not reported'}</dd></div><div><dt>Collection</dt><dd>{selected.collection ?? 'Not reported'}</dd></div><div><dt>Updated</dt><dd>{selected.updatedAt ?? 'Not reported'}</dd></div></dl>}
          {tab === 'References' && <><h3>Referenced sessions</h3>{selected.referencedSessions === null ? <p>Not reported</p> : <ul>{selected.referencedSessions.map((item) => <li key={item}>{item}</li>)}</ul>}<h3>References</h3>{selected.references === null ? <p>Not reported</p> : <ul>{selected.references.map((item) => <li key={item}>{item}</li>)}</ul>}</>}
          {tab === 'History' && (transport.mode === 'native' ? typeof selected.revision === 'string' && transport.capabilities.memoryHistory && source?.capabilities.includes('restore') ? <NativeSnapshotHistory sourceId={selected.sourceId} revision={selected.revision} transport={transport} onChanged={refreshCurrentView} /> : <p>Verified snapshot history and restore are unavailable for this source.</p> : <div className="memory-history"><p>Current revision {selected.revision}. Entries are derived from immutable demo receipts and verified snapshots.</p>{visibleHistoryError && <p role="alert" className="field-error">{visibleHistoryError}</p>}{visibleHistory.length ? <ol>{visibleHistory.map((entry) => <li key={entry.id}><strong>{entry.operation === 'created' ? 'Created' : entry.operation}</strong><span>Revision {entry.revision} · {entry.at}</span><p>{entry.summary}</p>{entry.receiptId && <small>Receipt {entry.receiptId}</small>}{entry.restorable && transport.capabilities.memoryHistory && <button className="secondary-button" type="button" onClick={(event) => { versionOpenerRef.current = event.currentTarget; void reviewVersionRestore(entry) }}>Restore version</button>}</li>)}</ol> : transport.capabilities.memoryHistory ? <p role="status">Loading version history…</p> : null}</div>)}
        </div><div className="record-actions"><button className="primary-button" type="button" disabled={!transport.capabilities.vaultMutation || !source?.capabilities.includes('edit') || (transport.mode === 'native' && !selected.editableFields?.length)} onClick={(event) => { actionOpenerRef.current = event.currentTarget; setOperation('update'); setEditing(true) }}>Edit draft</button>{transport.mode === 'demo' && <><button className="secondary-button" type="button" disabled={!transport.capabilities.vaultMutation || !source?.capabilities.includes('edit') || Boolean(selected.excluded)} onClick={(event) => { actionOpenerRef.current = event.currentTarget; setOperation('exclude'); setEditing(true) }}>Exclude from retrieval</button><button className="secondary-button" type="button" disabled={!transport.capabilities.vaultMutation || !source?.capabilities.includes('edit') || Boolean(selected.quarantined)} onClick={(event) => { actionOpenerRef.current = event.currentTarget; setOperation('quarantine'); setEditing(true) }}>Quarantine record</button></>}</div></> : <p className="empty-state">Select a record.</p>}</section>
      </div>}
      {editing && transport.capabilities.vaultMutation && selected && source && typeof source.revision === 'number' && hasNumericRevision(selected) && <MemoryEditor operation={operation} record={selected} sourceRevision={source.revision} transport={transport} restoreFocusRef={actionOpenerRef} completionFocusRef={headingRef} onClose={() => setEditing(false)} onChanged={refreshCurrentView} />}
      {editing && transport.mode === 'native' && transport.capabilities.vaultMutation && selected && typeof selected.revision === 'string' && <NativeMemoryEditor record={selected} transport={transport} restoreFocusRef={actionOpenerRef} onClose={() => setEditing(false)} onChanged={refreshCurrentView} />}
      {restorePlan && selected?.sourceId === restorePlan.sourceId && selected.id === restorePlan.recordId && <Dialog title="Review version restore" restoreFocusRef={versionOpenerRef} closeDisabled={restoreBusy || Boolean(restoreError && !restoreError.retryable)} onClose={() => { setRestoreError(null); setRestorePlan(undefined) }}><p className="local-warning"><strong>Local-only.</strong> Restore requires the exact receipt and verified snapshot and never overwrites a concurrent change.</p><dl><div><dt>Record</dt><dd>{restorePlan.recordId}</dd></div><div><dt>Snapshot</dt><dd>{restorePlan.snapshotId}</dd></div><div><dt>Expected record revision</dt><dd>{restorePlan.expectedRecordRevision}</dd></div><div><dt>Expected source revision</dt><dd>{restorePlan.expectedSourceRevision}</dd></div></dl>{restoreError && <div className="error-banner" role="alert"><strong>{restoreError.outcomeUncertain ? 'Restore outcome uncertain' : restoreError.retryable ? 'Restore failed' : 'Restore review is no longer current'}</strong><p>{restoreError.message}</p>{restoreError.retryable ? <button ref={restoreRetryRef} className="secondary-button" type="button" aria-disabled={restoreBusy} onClick={() => { if (!restoreBusy) void restoreVersion() }}>{restoreBusy ? 'Retrying…' : 'Retry restore'}</button> : <><p>{restoreError.outcomeUncertain ? 'Do not issue this restore again until the current record state has been refreshed.' : 'This exact plan cannot be retried. Refresh the record state before reviewing another restore.'}</p><button ref={restoreRetryRef} className="secondary-button" type="button" onClick={closeAndRefreshRestore}>Close and refresh</button></>}</div>}<div className="dialog__actions"><button className="primary-button" type="button" disabled={restoreBusy || Boolean(restoreError && !restoreError.retryable)} onClick={() => void restoreVersion()}>{restoreBusy ? 'Restoring…' : 'Restore exact version'}</button><button className="secondary-button" type="button" disabled={restoreBusy || Boolean(restoreError && !restoreError.retryable)} onClick={() => { setRestoreError(null); setRestorePlan(undefined) }}>Cancel</button></div></Dialog>}
    </div>
  )
}
