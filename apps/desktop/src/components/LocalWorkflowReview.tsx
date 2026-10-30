import { useLayoutEffect, useRef, useState } from 'react'

import type { LocalWorkflowPlan, LocalWorkflowReceipt, PlanExecutionRequest } from '../transport'
import { isVerifiedLocalSuccess, TransportError } from '../transport'
import { safeDisplayValue } from '../features/activity/redaction'
import { Dialog } from './Dialog'

interface Props {
  title: string
  subject?: string
  confirmLabel: string
  plan: LocalWorkflowPlan
  execute: (request: PlanExecutionRequest) => Promise<LocalWorkflowReceipt>
  onSettled?: () => Promise<void>
  onExecutionAttempt?: () => void
  onClose: () => void
  restoreFocusRef?: React.RefObject<HTMLElement | null>
}

export function LocalWorkflowReview({ title, subject, confirmLabel, plan, execute, onSettled, onExecutionAttempt, onClose, restoreFocusRef }: Props) {
  const [receipt, setReceipt] = useState<LocalWorkflowReceipt>()
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [executionAttempted, setExecutionAttempted] = useState(false)
  const [uncertain, setUncertain] = useState(false)
  const pending = useRef(false)
  const statusRef = useRef<HTMLElement>(null)

  useLayoutEffect(() => { if (receipt || error) statusRef.current?.focus() }, [receipt, error])

  async function apply() {
    if (pending.current || executionAttempted) return
    pending.current = true; setBusy(true); setExecutionAttempted(true); setError('')
    try {
      onExecutionAttempt?.()
      const result = await execute({ planId: plan.planId, digest: plan.digest })
      setReceipt(result)
      setUncertain(result.certainty === 'uncertain')
      try { await onSettled?.() }
      catch (reason) { setError(reason instanceof Error ? reason.message : 'Refresh failed. Reload local state before another operation.') }
    } catch (reason) {
      setUncertain(reason instanceof TransportError && (reason.code === 'outcome_uncertain' || reason.details?.reconcileRequired === true))
      setError(reason instanceof Error ? reason.message : 'The local operation did not return a receipt.')
    } finally { pending.current = false; setBusy(false) }
  }

  async function reconcileAndClose() {
    if (pending.current) return
    pending.current = true; setBusy(true)
    try { await onSettled?.(); onClose() }
    catch (reason) { setError(reason instanceof Error ? reason.message : 'Local state could not be refreshed.') }
    finally { pending.current = false; setBusy(false) }
  }

  const closeReview = () => { if ((uncertain || error) && executionAttempted && onSettled) void reconcileAndClose(); else onClose() }
  return <Dialog title={receipt ? 'Local operation receipt' : title} closeDisabled={busy} onClose={closeReview} restoreFocusRef={restoreFocusRef} className="local-workflow-review">
    <p className="local-warning">The local engine revalidates the immutable plan before changing the selected resource. No automatic action runs.</p>
    {subject && <p>Selected target: <code>{subject}</code></p>}
    {!receipt && plan.beforeRevision && <p>Reviewed source revision <code>{plan.beforeRevision}</code></p>}
    {!receipt && plan.sourceId && <p>Source <code>{plan.sourceId}</code></p>}
    {!receipt && plan.snapshotId && <p>Snapshot <code>{plan.snapshotId}</code></p>}
    {!receipt && plan.backupVerified !== undefined && <p>{plan.backupVerified ? 'The engine reports a verified recovery snapshot for this plan.' : 'A verified backup has not yet been reported for this plan. Execution must create and verify its recovery snapshot before committing.'}</p>}
    {!receipt && <><dl><div><dt>Plan</dt><dd><code>{plan.planId}</code></dd></div><div><dt>Digest</dt><dd><code>{plan.digest}</code></dd></div><div><dt>Expires</dt><dd>{plan.expiresAt}</dd></div></dl><ul>{plan.consequences.map((item, index) => <li key={index}>{safeDisplayValue(item, 2_048)}</li>)}</ul>{plan.warnings.length > 0 && <ul className="local-warning">{plan.warnings.map((item, index) => <li key={index}>{safeDisplayValue(item, 2_048)}</li>)}</ul>}{plan.diff && <table><thead><tr><th>Field</th><th>Old hash</th><th>New hash</th><th>Old preview</th><th>Proposed preview</th></tr></thead><tbody>{plan.diff.map((item) => <tr key={item.field}><th>{item.field}</th><td><code>{item.oldHash}</code></td><td><code>{item.newHash}</code></td><td><pre>{safeDisplayValue(item.oldPreview, 4_096)}</pre></td><td><pre>{safeDisplayValue(item.newPreview, 4_096)}</pre></td></tr>)}</tbody></table>}</>}
    {(receipt || error) && <section ref={statusRef} tabIndex={-1} className="receipt" aria-label="Local receipt details">{receipt && <><h3>{isVerifiedLocalSuccess(receipt) ? 'Local operation completed' : receipt.certainty === 'uncertain' ? 'Outcome uncertain' : 'Local operation needs review'}</h3><dl><div><dt>Receipt</dt><dd>{receipt.receiptId}</dd></div><div><dt>Outcome</dt><dd>{receipt.outcome}</dd></div><div><dt>Certainty</dt><dd>{receipt.certainty}</dd></div><div><dt>Action issued</dt><dd>{receipt.actionIssued === true ? 'Yes' : receipt.actionIssued === false ? 'No' : 'Unknown'}</dd></div>{receipt.snapshotId && <div><dt>Snapshot</dt><dd>{receipt.snapshotId}</dd></div>}{receipt.beforeRevision && <div><dt>Before revision</dt><dd><code>{receipt.beforeRevision}</code></dd></div>}{receipt.afterRevision && <div><dt>After revision</dt><dd><code>{receipt.afterRevision}</code></dd></div>}</dl><ul>{receipt.partialFailures.map((item, index) => <li key={index}>{safeDisplayValue(item, 2_048)}</li>)}</ul></>}{error && <p role="alert">{error}</p>}{uncertain && <p>Do not issue the action again. Refresh local state and inspect the durable receipt.</p>}</section>}
    <div className="dialog__actions">{!executionAttempted && <button className="primary-button" type="button" disabled={busy} onClick={() => void apply()}>{confirmLabel}</button>}{executionAttempted && (uncertain || error) && onSettled && <button className="secondary-button" type="button" disabled={busy} onClick={() => void reconcileAndClose()}>Refresh local state</button>}<button className="secondary-button" type="button" disabled={busy} onClick={closeReview}>Close review</button></div>
  </Dialog>
}
