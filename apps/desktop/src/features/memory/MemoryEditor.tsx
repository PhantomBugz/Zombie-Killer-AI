import { useLayoutEffect, useRef, useState } from 'react'

import { Dialog } from '../../components/Dialog'
import { useTabs } from '../../components/useTabs'
import type { EngineTransport, MemoryOperation, MemoryPlan, MemoryReceipt, MemoryRecord } from '../../transport'
import { safeDisplayValue } from '../activity/redaction'
import { parseMemoryDraft, serializeMemoryDraft, type EditableMemoryFields } from './memoryDraft'

interface MemoryEditorProps {
  record: MemoryRecord & { revision: number }
  sourceRevision: number
  transport: EngineTransport
  onClose: () => void
  onChanged: () => Promise<void>
  restoreFocusRef?: React.RefObject<HTMLElement | null>
  completionFocusRef?: React.RefObject<HTMLElement | null>
  operation?: Exclude<MemoryOperation, 'restore'>
}

export function MemoryEditor({ record, sourceRevision, transport, onClose, onChanged, restoreFocusRef, completionFocusRef, operation = 'update' }: MemoryEditorProps) {
  const [draft, setDraft] = useState<EditableMemoryFields>({ title: record.title, content: record.content, tags: record.tags, collection: record.collection })
  const [editorMode, setEditorMode] = useState<'structured' | 'raw'>('structured')
  const [raw, setRaw] = useState(() => serializeMemoryDraft(record))
  const [rawError, setRawError] = useState('')
  const [plan, setPlan] = useState<MemoryPlan | null>(null)
  const [receipt, setReceipt] = useState<MemoryReceipt | null>(null)
  const [restoreReceipt, setRestoreReceipt] = useState<MemoryReceipt | null>(null)
  const [error, setError] = useState('')
  const [reviewing, setReviewing] = useState(false)
  const [mutating, setMutating] = useState(false)
  const contentRef = useRef<HTMLTextAreaElement>(null)
  const applyRef = useRef<HTMLButtonElement>(null)
  const receiptRef = useRef<HTMLElement>(null)
  const restoreStatusRef = useRef<HTMLParagraphElement>(null)
  const reviewGeneration = useRef(0)
  const reviewSnapshot = useRef<string | null>(null)
  const acceptedPlanSnapshot = useRef<string | null>(null)
  const targetContext = JSON.stringify([record.sourceId, record.id, record.revision, sourceRevision, operation])
  const targetContextRef = useRef(targetContext)
  const busy = reviewing || mutating
  const editorModes = ['structured', 'raw'] as const

  function invalidateReview() {
    reviewGeneration.current += 1
    reviewSnapshot.current = null
    acceptedPlanSnapshot.current = null
    setPlan(null)
    setReviewing(false)
  }

  function selectEditorMode(mode: typeof editorModes[number]) {
    if (mode === 'structured') { const parsed = parseMemoryDraft(raw); if (parsed.value) setDraft(parsed.value) }
    else setRaw(serializeMemoryDraft(draft))
    invalidateReview(); setEditorMode(mode); setRawError('')
  }
  const editorTabs = useTabs(editorModes, editorMode, selectEditorMode)

  useLayoutEffect(() => {
    if (targetContextRef.current === targetContext) return
    targetContextRef.current = targetContext
    reviewGeneration.current += 1
    reviewSnapshot.current = null
    acceptedPlanSnapshot.current = null
    setPlan(null)
    setReviewing(false)
  }, [targetContext])

  useLayoutEffect(() => {
    if (restoreReceipt) restoreStatusRef.current?.focus()
    else if (receipt) receiptRef.current?.focus()
    else if (plan && !reviewing && !mutating) applyRef.current?.focus()
  }, [mutating, plan, receipt, restoreReceipt, reviewing])

  async function review() {
    setError('')
    try {
      let changes: EditableMemoryFields = draft
      if (operation === 'update' && editorMode === 'raw') {
        const parsed = parseMemoryDraft(raw)
        if (!parsed.value) { setRawError(parsed.error ?? 'Raw JSON validation failed.'); return }
        changes = parsed.value
      }
      setRawError('')
      const snapshot = JSON.stringify({ draft: serializeMemoryDraft(changes), editorMode, operation, sourceId: record.sourceId, recordId: record.id, sourceRevision, recordRevision: record.revision })
      const current = ++reviewGeneration.current
      reviewSnapshot.current = snapshot
      acceptedPlanSnapshot.current = null
      setPlan(null); setReviewing(true)
      try {
        const next = await transport.planMemoryChange({ sourceId: record.sourceId, recordId: record.id, operation, expectedSourceRevision: sourceRevision, expectedRecordRevision: record.revision, changes: operation === 'update' ? changes : {} })
        if (current !== reviewGeneration.current || reviewSnapshot.current !== snapshot) return
        if (next.operation !== operation || next.sourceId !== record.sourceId || next.recordId !== record.id || next.expectedSourceRevision !== sourceRevision || next.expectedRecordRevision !== record.revision) throw new Error('Memory review response did not match the current draft target.')
        acceptedPlanSnapshot.current = snapshot
        setPlan(next)
      } catch (reason) {
        if (current === reviewGeneration.current && reviewSnapshot.current === snapshot) setError(reason instanceof Error ? reason.message : 'Draft validation failed.')
      } finally {
        if (current === reviewGeneration.current && reviewSnapshot.current === snapshot) setReviewing(false)
      }
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Draft validation failed.') }
  }

  async function apply() {
    if (!plan || !acceptedPlanSnapshot.current || acceptedPlanSnapshot.current !== reviewSnapshot.current) return
    setMutating(true); setError('')
    try { setReceipt(await transport.executeMemoryChange({ planId: plan.planId, digest: plan.digest })); await onChanged(); if (completionFocusRef?.current && restoreFocusRef) restoreFocusRef.current = completionFocusRef.current }
    catch (reason) { setError(reason instanceof Error ? reason.message : 'Nothing was applied.') }
    finally { setMutating(false) }
  }

  async function restore() {
    if (!receipt) return
    setMutating(true); setError('')
    try {
      const restorePlan = await transport.planMemoryRestore({ receiptId: receipt.receiptId, snapshotId: receipt.snapshotId, expectedRecordRevision: receipt.afterRevision })
      setRestoreReceipt(await transport.executeMemoryRestore({ planId: restorePlan.planId, digest: restorePlan.digest })); await onChanged(); if (completionFocusRef?.current && restoreFocusRef) restoreFocusRef.current = completionFocusRef.current
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Nothing was restored.') }
    finally { setMutating(false) }
  }

  return (
    <Dialog title={receipt ? 'Change receipt' : 'Edit memory draft'} onClose={onClose} initialFocusRef={contentRef} restoreFocusRef={restoreFocusRef} closeDisabled={busy} className="memory-editor">
      <p className="local-warning"><strong>Local-only.</strong> This changes one user-controlled demo memory record. It does not change provider behavior, moderation, accounts, or rate limits.</p>
      {error && <div className="error-banner" role="alert"><strong>Source changed or validation failed</strong><p>{error}</p><p>Refresh the record and create a new draft. No overwrite was attempted.</p></div>}
      {!receipt ? (
        <>
          {operation === 'update' ? <><div className="tabs" role="tablist" aria-label="Memory editor format">{editorModes.map((mode, index) => <button key={mode} type="button" role="tab" disabled={mutating} {...editorTabs.tabProps(mode, index)}>{mode === 'structured' ? 'Structured' : 'Raw JSON'}</button>)}</div>
          {editorMode === 'structured' ? <div role="tabpanel" {...editorTabs.panelProps} className="memory-editor-fields"><label className="field"><span>Title</span><input disabled={mutating} value={draft.title} onChange={(event) => { invalidateReview(); setDraft({ ...draft, title: event.target.value }) }} /></label><label className="field"><span>Content</span><textarea ref={contentRef} disabled={mutating} value={draft.content} onChange={(event) => { invalidateReview(); setDraft({ ...draft, content: event.target.value }) }} /></label><label className="field"><span>Tags (comma separated)</span><input disabled={mutating} value={draft.tags.join(', ')} onChange={(event) => { invalidateReview(); setDraft({ ...draft, tags: event.target.value.split(',').map((tag) => tag.trim()).filter(Boolean) }) }} /></label><label className="field"><span>Collection</span><input disabled={mutating} value={draft.collection} onChange={(event) => { invalidateReview(); setDraft({ ...draft, collection: event.target.value }) }} /></label></div> : <div role="tabpanel" {...editorTabs.panelProps}><p className="muted">Advanced local draft. Strict schema and size validation run before review. Embedding values are never included.</p><label className="field"><span>Raw JSON draft</span><textarea aria-label="Raw JSON draft" aria-invalid={Boolean(rawError)} aria-describedby={rawError ? 'raw-json-error' : undefined} disabled={mutating} value={raw} onChange={(event) => { invalidateReview(); setRaw(event.target.value); setRawError('') }} /></label>{rawError && <p id="raw-json-error" className="field-error" role="alert">{rawError}</p>}</div>}</> : <p>This draft will mark <strong>{record.id}</strong> as {operation === 'exclude' ? 'excluded from local retrieval' : 'quarantined in the local demo vault'}. Content is not rewritten.</p>}
          {plan && <section className="plan-review" aria-labelledby="memory-diff-title"><h3 id="memory-diff-title">Review exact field diff</h3><p><strong>Verified snapshot</strong> · {plan.snapshot.id}</p><p>Expected revision {plan.expectedRecordRevision}; source revision {plan.expectedSourceRevision}</p><table><thead><tr><th>Field</th><th>Old redacted preview</th><th>New redacted preview</th></tr></thead><tbody>{plan.diff.map((change) => <tr key={change.field}><th>{change.field}</th><td>{safeDisplayValue(change.oldValue, 90)}</td><td>{safeDisplayValue(change.newValue, 90)}</td></tr>)}</tbody></table></section>}
          <div className="dialog__actions">{!plan ? <button className="primary-button" type="button" disabled={reviewing || mutating} onClick={() => void review()}>Review diff</button> : <button ref={applyRef} className="primary-button" type="button" disabled={mutating} onClick={() => void apply()}>Apply local change</button>}<button className="secondary-button" type="button" disabled={busy} onClick={onClose}>Cancel</button></div>
        </>
      ) : (
        <section ref={receiptRef} className="receipt" aria-label="Receipt details" tabIndex={-1}><dl><div><dt>Audit receipt</dt><dd>{receipt.receiptId}</dd></div><div><dt>Correlation ID</dt><dd>{receipt.correlationId}</dd></div><div><dt>Snapshot</dt><dd>{receipt.snapshotId}</dd></div><div><dt>Revision</dt><dd>{receipt.beforeRevision} → {receipt.afterRevision}</dd></div></dl>{restoreReceipt ? <p ref={restoreStatusRef} role="status" tabIndex={-1}><strong>Restore receipt:</strong> {restoreReceipt.receiptId}. Exact snapshot restored without overwrite.</p> : <button className="secondary-button" type="button" disabled={busy} onClick={() => void restore()}>Restore snapshot</button>}</section>
      )}
    </Dialog>
  )
}
