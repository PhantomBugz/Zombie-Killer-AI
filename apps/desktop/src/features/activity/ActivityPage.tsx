import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'

import { Dialog } from '../../components/Dialog'
import { LocalWorkflowReview } from '../../components/LocalWorkflowReview'
import { useTabs } from '../../components/useTabs'
import { isVerifiedLocalSuccess, TransportError } from '../../transport'
import type { ActivityResult, EngineTransport, GraveyardPlan } from '../../transport'
import { buildSanitizedExport, copyText } from './export'

type ActivityTab = 'Events' | 'Receipts' | 'Quarantine'
const activityTabs: readonly ActivityTab[] = ['Events', 'Receipts', 'Quarantine']
interface FilterRow { timestamp: string; actor: string; project: string; target: string; action: string; result: string; correlationId: string; detail: string; key: string; restoreRef?: string; partialFailures?: readonly string[] }
interface RestoreFailure { message: string; retryable: boolean; outcomeUncertain: boolean }

const terminalRestoreCodes = new Set(['plan_expired', 'plan_changed', 'plan_replayed', 'conflict', 'source_changed', 'outcome_uncertain'])

function restoreFailure(reason: unknown): RestoreFailure {
  const message = reason instanceof Error ? reason.message : 'Nothing was restored.'
  if (!(reason instanceof TransportError) || !terminalRestoreCodes.has(reason.code)) return { message, retryable: true, outcomeUncertain: false }
  return { message, retryable: false, outcomeUncertain: reason.code === 'outcome_uncertain' }
}

function includesFilters(row: FilterRow, filters: { search: string; project: string; actor: string; result: string; date: string }) {
  const haystack = Object.values(row).join(' ').toLowerCase()
  return (!filters.search || haystack.includes(filters.search.toLowerCase())) && (filters.project === 'All' || row.project === filters.project) && (filters.actor === 'All' || row.actor === filters.actor) && (filters.result === 'All' || row.result === filters.result) && (!filters.date || row.timestamp.slice(0, 10) === filters.date)
}

function processReceiptResult(receipt: ActivityResult['receipts'][number], native: boolean) {
  if (receipt.certainty === 'uncertain') return 'Partial'
  if (receipt.certainty === 'failed_before_issue') return 'Failed'
  if (receipt.partialFailures.length > 0) return 'Partial'
  if (!native && !receipt.outcome) return 'Succeeded'
  switch (receipt.outcome) {
    case 'completed': return 'Succeeded'
    case 'requested':
    case 'pending':
    case 'disappeared': return 'Partial'
    case 'interrupted': return 'Interrupted'
    case 'access_denied':
    case 'identity_mismatch':
    case 'failed': return 'Failed'
    default: return 'Not reported'
  }
}

export function ActivityPage({ transport }: { transport: EngineTransport }) {
  const native = transport.mode === 'native'
  const [activity, setActivity] = useState<ActivityResult>()
  const [tab, setTab] = useState<ActivityTab>('Events')
  const [search, setSearch] = useState('')
  const [project, setProject] = useState('All')
  const [actor, setActor] = useState('All')
  const [result, setResult] = useState('All')
  const [date, setDate] = useState('')
  const [error, setError] = useState(transport.capabilities.activity ? '' : 'Activity is unavailable from this transport.')
  const [plan, setPlan] = useState<GraveyardPlan>()
  const [preview, setPreview] = useState('')
  const [copyStatus, setCopyStatus] = useState('')
  const [restoreBusy, setRestoreBusy] = useState(false)
  const [restoreError, setRestoreError] = useState<RestoreFailure | null>(null)
  const restoreRetryRef = useRef<HTMLButtonElement>(null)
  const generation = useRef(0)
  const headingRef = useRef<HTMLHeadingElement>(null)
  const restoreOpenerRef = useRef<HTMLElement | null>(null)
  const restorePending = useRef(false)
  const tabUi = useTabs(activityTabs, tab, (next) => { setTab(next); setPlan(undefined) })

  useLayoutEffect(() => {
    if (restoreError && !restoreBusy) restoreRetryRef.current?.focus()
  }, [restoreError, restoreBusy])

  async function refresh(requireSuccess = false) {
    if (!transport.capabilities.activity) { setError('Activity is unavailable from this transport.'); return }
    const current = ++generation.current; setError('')
    try { const next = await transport.getActivity(); if (current === generation.current) setActivity(next) }
    catch (reason) { if (current === generation.current) setError(reason instanceof Error ? reason.message : 'Activity is unavailable.'); if (requireSuccess) throw reason }
  }
  useEffect(() => {
    if (!transport.capabilities.activity) {
      return
    }
    const current = ++generation.current
    void transport.getActivity().then((next) => { if (current === generation.current) setActivity(next) }).catch((reason: unknown) => { if (current === generation.current) setError(reason instanceof Error ? reason.message : 'Activity is unavailable.') })
    return () => { generation.current += 1 }
  }, [transport])

  const receiptRows = useMemo<FilterRow[]>(() => {
    if (!activity) return []
    const eventFor = (correlation: string) => activity.events.find((event) => event.correlationId === correlation || event.detail.includes(correlation))
    return [
      ...activity.receipts.map((receipt) => { const event = eventFor(receipt.receiptId); return { key: receipt.receiptId, timestamp: receipt.completedAt, actor: native ? 'Not reported' : 'Local user', project: event?.project ?? (native ? 'Not reported' : 'Demo project'), target: receipt.agentId ?? 'Not reported', action: receipt.title, result: processReceiptResult(receipt, native), correlationId: native ? 'Not reported' : receipt.receiptId, detail: receipt.diagnostics, partialFailures: receipt.partialFailures, restoreRef: receipt.fileCount ? 'Available in Quarantine' : receipt.fileCount === 0 ? 'No files' : 'Not reported' } }),
      ...activity.memoryReceipts.map((receipt) => { const event = eventFor(receipt.correlationId); return { key: receipt.receiptId, timestamp: receipt.completedAt, actor: 'Local user', project: event?.project ?? 'Memory Vault', target: receipt.recordId, action: `Memory ${receipt.operation}`, result: 'Succeeded', correlationId: receipt.correlationId, detail: `Audit receipt ${receipt.receiptId}`, restoreRef: receipt.snapshotId } }),
      ...activity.graveyardReceipts.map((receipt) => { const event = eventFor(receipt.correlationId); return { key: receipt.receiptId, timestamp: receipt.completedAt, actor: 'Local user', project: event?.project ?? 'Local recovery', target: receipt.entryId, action: 'Quarantine restore', result: receipt.result, correlationId: receipt.correlationId, detail: `Audit receipt ${receipt.receiptId}`, restoreRef: receipt.entryId } }),
      ...(activity.localReceipts ?? []).map((receipt) => ({ key: receipt.receiptId, timestamp: receipt.createdAt, actor: 'Not reported', project: 'Not reported', target: 'Not reported', action: receipt.kind === 'memory' ? 'Memory operation' : receipt.kind === 'quarantine' ? 'Quarantine operation' : 'Diagnostics export', result: receipt.certainty === 'uncertain' || receipt.partialFailures.length > 0 ? 'Partial' : receipt.certainty === 'failed_before_issue' ? 'Failed' : isVerifiedLocalSuccess(receipt) ? 'Succeeded' : receipt.outcome, correlationId: 'Not reported', detail: `Plan ${receipt.planId}; outcome ${receipt.outcome}; certainty ${receipt.certainty}; action issued ${receipt.actionIssued === null ? 'Not reported' : String(receipt.actionIssued)}.`, partialFailures: receipt.partialFailures })),
    ]
  }, [activity, native])
  const quarantineRows = useMemo<FilterRow[]>(() => (activity?.quarantine ?? []).map((entry) => {
    const event = activity?.events.find((item) => item.correlationId === entry.receiptId)
    const receipt = activity?.receipts.find((item) => item.receiptId === entry.receiptId)
    return { key: entry.id, timestamp: event?.timestamp ?? receipt?.completedAt ?? entry.createdAt, actor: native ? 'Not reported' : 'Local user', project: event?.project ?? (native ? 'Not reported' : 'Local recovery'), target: entry.basename ?? entry.agentId ?? 'Entry unavailable', action: 'Quarantine entry', result: entry.state, correlationId: entry.receiptId ?? 'Not reported', detail: `${entry.displayPath ?? 'Path unavailable'} ${entry.size ?? 'size unavailable'} ${entry.hashPrefix ?? 'hash unavailable'} ${entry.digest ?? 'digest unavailable'} agent ${entry.agentId ?? 'not reported'} resource ${entry.resourceType} created ${entry.createdAt} retained until ${entry.retainedUntil ?? 'not reported'}` }
  }), [activity, native])
  const filters = { search, project, actor, result, date }
  const events = (activity?.events ?? []).filter((event) => includesFilters({ ...event, project: event.project ?? 'Project unavailable', key: event.id }, filters))
  const visibleReceipts = receiptRows.filter((row) => includesFilters(row, filters))
  const visibleQuarantine = (activity?.quarantine ?? []).filter((entry) => quarantineRows.some((row) => row.key === entry.id && includesFilters(row, filters)))
  const filterRows = [...(activity?.events ?? []).map((event) => ({ ...event, project: event.project ?? 'Project unavailable', key: event.id })), ...receiptRows, ...quarantineRows]
  const projects = Array.from(new Set(filterRows.map((row) => row.project)))
  const actors = Array.from(new Set(filterRows.map((row) => row.actor)))
  const results = Array.from(new Set(['Succeeded', 'Partial', 'Failed', ...filterRows.map((row) => row.result)]))

  async function reviewRestore(entryId: string) {
    setError(''); setRestoreError(null)
    try { setPlan(await transport.planGraveyardRestore(entryId)) }
    catch (reason) { setError(reason instanceof Error ? reason.message : 'Restore review failed.') }
  }
  async function restore() {
    if (!plan || restorePending.current) return
    restorePending.current = true; setRestoreBusy(true)
    try { await transport.executeGraveyardRestore({ planId: plan.planId, digest: plan.digest }); restoreOpenerRef.current = headingRef.current; setPlan(undefined); await refresh() }
    catch (reason) { setRestoreError(restoreFailure(reason)) }
    finally { restorePending.current = false; setRestoreBusy(false) }
  }
  function closeAndRefreshRestore() {
    restoreOpenerRef.current = headingRef.current
    setRestoreError(null)
    setPlan(undefined)
    void refresh()
  }
  function createPreview(format: 'jsonl' | 'csv') { try { setPreview(buildSanitizedExport(events, format)); setCopyStatus('') } catch (reason) { setError(reason instanceof Error ? reason.message : 'Export rejected.') } }
  function downloadPreview() {
    const url = URL.createObjectURL(new Blob([preview], { type: 'text/plain;charset=utf-8' }))
    const anchor = document.createElement('a'); anchor.href = url; anchor.download = 'zombie-killer-sanitized-activity.txt'; anchor.click(); URL.revokeObjectURL(url)
  }

  return <div className="workspace-page activity-page">
    <header className="workspace-header"><div><p className="eyebrow">Audit and recovery</p><h1 ref={headingRef} tabIndex={-1} data-route-heading="true">Activity</h1><p>{native ? 'Durable local-engine receipts and reviewed Graveyard recovery.' : 'Durable demo events, receipts, and reversible quarantine recovery.'}</p></div><span className="demo-pill">{native ? 'LOCAL ENGINE · PARTIAL' : 'DEMO LAB'}</span></header>
    {native && <p className="local-warning"><strong>{transport.capabilities.quarantineRestore ? 'Reviewed native recovery.' : 'Read-only native activity.'}</strong> Restore is enabled only for eligible entries and confirmed engine methods; absent actor, project, target, and correlation values remain Not reported. Local diagnostics export is available from Settings when supported.</p>}
    <p className="local-warning"><strong>Local-only audit.</strong> Display paths are redacted. Exports never include raw memory, commands, secrets, or full paths.</p>
    {activity?.pagination.activityTruncated && <div className="error-banner" role="alert"><strong>Activity results truncated.</strong><p>The native engine reported more receipt pages than this bounded view can safely load.</p></div>}
    {activity?.pagination.quarantineTruncated && <div className="error-banner" role="alert"><strong>Quarantine results truncated.</strong><p>The native engine reported more quarantine pages than this bounded view can safely load.</p></div>}
    {error && <div className="error-banner" role="alert"><p>{error}</p><button className="secondary-button" type="button" onClick={() => void refresh()}>Retry</button></div>}
    <div className="tabs" role="tablist" aria-label="Activity views">{activityTabs.map((name, index) => <button key={name} type="button" role="tab" {...tabUi.tabProps(name, index)}>{name}</button>)}</div>
    <div className="activity-filters"><label><span>Search activity</span><input type="search" aria-label="Search activity" value={search} onChange={(event) => { setSearch(event.target.value); setPreview(''); setCopyStatus('') }} /></label><label><span>Project</span><select value={project} onChange={(event) => { setProject(event.target.value); setPreview(''); setCopyStatus('') }}><option>All</option>{projects.map((item) => <option key={item}>{item}</option>)}</select></label><label><span>Actor</span><select value={actor} onChange={(event) => { setActor(event.target.value); setPreview(''); setCopyStatus('') }}><option>All</option>{actors.map((item) => <option key={item}>{item}</option>)}</select></label><label><span>Result</span><select value={result} onChange={(event) => { setResult(event.target.value); setPreview(''); setCopyStatus('') }}><option>All</option>{results.map((item) => <option key={item}>{item}</option>)}</select></label><label><span>Date</span><input type="date" value={date} onChange={(event) => { setDate(event.target.value); setPreview(''); setCopyStatus('') }} /></label></div>
    {!activity ? <p role="status">Loading local activity…</p> : tab === 'Events' ? <section role="tabpanel" {...tabUi.panelProps}><div className="table-scroll" role="region" aria-label="Activity events table" tabIndex={0}><table><thead><tr><th>Timestamp</th><th>Actor</th><th>Target</th><th>Action</th><th>Result</th><th>Correlation</th></tr></thead><tbody>{events.map((event) => <tr key={event.id}><td>{event.timestamp}</td><td>{event.actor}</td><td>{event.target}</td><td><strong>{event.action}</strong><small>{event.detail}</small></td><td>{event.result}</td><td>{event.correlationId}</td></tr>)}</tbody></table></div>{transport.capabilities.diagnosticsExport ? <div className="export-tools"><button className="secondary-button" type="button" onClick={() => createPreview('jsonl')}>Preview sanitized JSONL</button><button className="secondary-button" type="button" onClick={() => createPreview('csv')}>Preview sanitized CSV</button>{preview && <><p>Included data: timestamp, actor, project, target ID, action, result, correlation ID. Values are bounded and sanitized before preview.</p><textarea aria-label="Sanitized export preview" readOnly value={preview} /><button className="secondary-button" type="button" onClick={() => void copyText(preview).then((copied) => setCopyStatus(copied ? 'Copied' : 'Clipboard unavailable'))}>Copy preview</button><button className="secondary-button" type="button" onClick={downloadPreview}>Download preview</button><span role="status">{copyStatus}</span></>}</div> : <p className="muted">Diagnostics export is unavailable in this build.</p>}</section>
      : tab === 'Receipts' ? <section role="tabpanel" {...tabUi.panelProps}>{visibleReceipts.length ? <ul className="receipt-list">{visibleReceipts.map((receipt) => <li key={receipt.key}><strong>{receipt.action}</strong><span>{receipt.timestamp}</span><dl><div><dt>Actor</dt><dd>{receipt.actor}</dd></div><div><dt>Project</dt><dd>{receipt.project}</dd></div><div><dt>Target</dt><dd>{receipt.target}</dd></div><div><dt>Result</dt><dd>{receipt.result}</dd></div><div><dt>Correlation ID</dt><dd>{receipt.correlationId}</dd></div><div><dt>Audit receipt</dt><dd>{receipt.key}</dd></div><div><dt>Detail</dt><dd>{receipt.detail}</dd></div><div><dt>Partial failures</dt><dd>{receipt.partialFailures?.length ? <ul>{receipt.partialFailures.map((failure, index) => <li key={`${receipt.key}-partial-${index}`}>{failure}</li>)}</ul> : 'None'}</dd></div><div><dt>Restore reference</dt><dd>{receipt.restoreRef ?? 'None'}</dd></div></dl></li>)}</ul> : <p className="empty-state">No receipts match these filters.</p>}</section>
      : <section role="tabpanel" {...tabUi.panelProps}>{visibleQuarantine.length ? <ul className="quarantine-list">{visibleQuarantine.map((entry) => <li key={entry.id}><div><strong>{entry.basename ?? 'Name not reported'}</strong><span>{entry.displayPath ?? 'Path not exposed'}</span></div><dl><div><dt>Agent</dt><dd>{entry.agentId ?? 'Not reported'}</dd></div><div><dt>Resource type</dt><dd>{entry.resourceType}</dd></div><div><dt>Created</dt><dd>{entry.createdAt}</dd></div><div><dt>Size</dt><dd>{entry.size === null ? 'Not reported' : `${entry.size} bytes`}</dd></div><div><dt>Hash</dt><dd>{entry.hashPrefix ?? 'Not reported'}</dd></div><div><dt>Retained until</dt><dd>{entry.retainedUntil ?? 'Not reported'}</dd></div><div><dt>State</dt><dd>{entry.state}</dd></div><div><dt>Restore</dt><dd>{entry.restorable === true && entry.state === 'Quarantined' ? 'Available' : entry.state === 'Partial' || entry.state === 'Interrupted' ? 'Unavailable — quarantine did not complete' : 'Unavailable'}</dd></div></dl>{transport.capabilities.quarantineRestore && entry.state === 'Quarantined' && entry.restorable === true && <button className="secondary-button" type="button" onClick={(event) => { restoreOpenerRef.current = event.currentTarget; void reviewRestore(entry.id) }}>Review restore</button>}</li>)}</ul> : <p className="empty-state">No quarantine entries match these filters.</p>}{plan && !native && <Dialog title="Review quarantine restore" className="restore-review" restoreFocusRef={restoreOpenerRef} closeDisabled={restoreBusy || Boolean(restoreError && !restoreError.retryable)} onClose={() => { setRestoreError(null); setPlan(undefined) }}><p>Entry {plan.entryId}</p><p>Digest {plan.entryDigest}</p><p>No existing file will be overwritten. The revision is revalidated at execution.</p>{restoreError && <div className="error-banner" role="alert"><strong>{restoreError.outcomeUncertain ? 'Restore outcome uncertain' : restoreError.retryable ? 'Restore failed' : 'Restore review is no longer current'}</strong><p>{restoreError.message}</p>{restoreError.retryable ? <button ref={restoreRetryRef} className="secondary-button" type="button" aria-disabled={restoreBusy} onClick={() => { if (!restoreBusy) void restore() }}>{restoreBusy ? 'Retrying…' : 'Retry restore'}</button> : <><p>{restoreError.outcomeUncertain ? 'Do not issue this restore again until the current quarantine state has been refreshed.' : 'This exact plan cannot be retried. Refresh the quarantine state before reviewing another restore.'}</p><button ref={restoreRetryRef} className="secondary-button" type="button" onClick={closeAndRefreshRestore}>Close and refresh</button></>}</div>}<div className="dialog__actions"><button className="primary-button" type="button" disabled={restoreBusy || Boolean(restoreError && !restoreError.retryable)} onClick={() => void restore()}>{restoreBusy ? 'Restoring…' : 'Restore exact entry'}</button><button className="secondary-button" type="button" disabled={restoreBusy || Boolean(restoreError && !restoreError.retryable)} onClick={() => { setRestoreError(null); setPlan(undefined) }}>Cancel</button></div></Dialog>}</section>}
    {plan && native && transport.executeNativeGraveyardRestore && <LocalWorkflowReview title="Review quarantine restore" subject={plan.entryId} confirmLabel="Restore exact entry" plan={{ planId: plan.planId, digest: plan.digest, expiresAt: plan.expiresAt, consequences: plan.consequences ?? [], warnings: plan.warnings ?? [] }} execute={(request) => transport.executeNativeGraveyardRestore!(request)} onSettled={() => refresh(true)} onClose={() => setPlan(undefined)} restoreFocusRef={restoreOpenerRef} />}
  </div>
}
