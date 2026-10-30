import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react'

import { Dialog } from '../../components/Dialog'
import type { ActionKind, ActionPlan, AgentDetail, ContainmentReceipt, EngineTransport } from '../../transport/types'
import { TransportError } from '../../transport/types'

interface Props { agent: AgentDetail; transport: EngineTransport; initialKind: ActionKind; onClose: () => void; onComplete: (receipt: ContainmentReceipt) => Promise<void> | void; onUncertain: () => Promise<void>; onReturn: () => void; restoreFocusRef: React.RefObject<HTMLElement | null> }

const missingProcessInstanceMessage = 'The reviewed agent has no stable process instance. Refresh the swarm before planning an action.'

export function ContainmentDialog({ agent, transport, initialKind, onClose, onComplete, onUncertain, onReturn, restoreFocusRef }: Props) {
  const hasStableTarget = agent.pid !== null && agent.processInstanceId !== null
  const [kind, setKind] = useState(initialKind)
  const [plan, setPlan] = useState<ActionPlan | null>(null)
  const [loading, setLoading] = useState(hasStableTarget)
  const [confirmed, setConfirmed] = useState(false)
  const [typedPid, setTypedPid] = useState('')
  const [executing, setExecuting] = useState(false)
  const [receipt, setReceipt] = useState<ContainmentReceipt | null>(null)
  const [error, setError] = useState<string | null>(hasStableTarget ? null : missingProcessInstanceMessage)
  const [reconcileError, setReconcileError] = useState<string | null>(null)
  const [reconciling, setReconciling] = useState(false)
  const [reconciled, setReconciled] = useState(false)
  const [copyStatus, setCopyStatus] = useState('')
  const [outcomeUncertain, setOutcomeUncertain] = useState(false)
  const [outcomeReconciling, setOutcomeReconciling] = useState(false)
  const [outcomeReconciled, setOutcomeReconciled] = useState(false)
  const [outcomeReconcileError, setOutcomeReconcileError] = useState<string | null>(null)
  const confirmRef = useRef<HTMLInputElement>(null)
  const receiptHeadingRef = useRef<HTMLHeadingElement>(null)
  const reconcileStatusRef = useRef<HTMLParagraphElement>(null)
  const reconcileRetryRef = useRef<HTMLButtonElement>(null)
  const outcomeStatusRef = useRef<HTMLParagraphElement>(null)
  const outcomeRetryRef = useRef<HTMLButtonElement>(null)
  const returnRef = useRef<HTMLButtonElement>(null)
  const requestGeneration = useRef(0)
  const planAbort = useRef<AbortController | null>(null)
  const outcomeReconcileInFlight = useRef(false)

  const requestTarget = useCallback(() => {
    if (agent.pid === null || !agent.processInstanceId) return null
    return { pid: agent.pid, processInstanceId: agent.processInstanceId }
  }, [agent.pid, agent.processInstanceId])

  const planMatchesRequest = useCallback((next: ActionPlan, nextKind: ActionKind) => {
    const target = requestTarget()
    return target !== null
      && next.kind === nextKind
      && next.agentId === agent.id
      && next.target.pid === target.pid
      && next.target.processInstanceId === target.processInstanceId
  }, [agent.id, requestTarget])

  async function loadPlan(nextKind: ActionKind) {
    if (executing || outcomeUncertain) return
    planAbort.current?.abort()
    const controller = new AbortController()
    planAbort.current = controller
    const generation = ++requestGeneration.current
    setKind(nextKind); setLoading(true); setPlan(null); setConfirmed(false); setTypedPid(''); setError(null)
    const target = requestTarget()
    if (!target) { setError(missingProcessInstanceMessage); setLoading(false); return }
    try {
      const next = await transport.planAction({ agentId: agent.id, kind: nextKind, target })
      if (!controller.signal.aborted && generation === requestGeneration.current) {
        if (planMatchesRequest(next, nextKind)) setPlan(next)
        else setError('The returned engine plan target did not match the reviewed process instance. Refresh before trying again.')
      }
    } catch (cause) {
      if (!controller.signal.aborted && generation === requestGeneration.current) setError(cause instanceof Error ? cause.message : 'The plan could not be prepared.')
    } finally { if (!controller.signal.aborted && generation === requestGeneration.current) setLoading(false) }
  }
  useEffect(() => {
    const controller = new AbortController()
    planAbort.current = controller
    const generation = ++requestGeneration.current
    const target = requestTarget()
    if (!target) {
      return () => { controller.abort(); requestGeneration.current += 1 }
    }
    void transport.planAction({ agentId: agent.id, kind: initialKind, target }).then(
      (value) => {
        if (!controller.signal.aborted && generation === requestGeneration.current) {
          if (planMatchesRequest(value, initialKind)) setPlan(value)
          else setError('The returned engine plan target did not match the reviewed process instance. Refresh before trying again.')
        }
      },
      (cause: unknown) => { if (!controller.signal.aborted && generation === requestGeneration.current) setError(cause instanceof Error ? cause.message : 'The plan could not be prepared.') },
    ).finally(() => { if (!controller.signal.aborted && generation === requestGeneration.current) setLoading(false) })
    return () => { controller.abort(); planAbort.current?.abort(); requestGeneration.current += 1 }
  }, [agent.id, initialKind, planMatchesRequest, requestTarget, transport])

  useLayoutEffect(() => {
    if (receipt) {
      if (reconciled) returnRef.current?.focus()
      else receiptHeadingRef.current?.focus()
      const dialog = receiptHeadingRef.current?.closest<HTMLElement>('.dialog')
      if (dialog) dialog.scrollTop = 0
    }
  }, [receipt, reconciled])

  useLayoutEffect(() => {
    if (reconcileError && !reconciling) reconcileRetryRef.current?.focus()
  }, [reconcileError, reconciling])

  useLayoutEffect(() => {
    if (receipt && reconciling) reconcileStatusRef.current?.focus()
  }, [receipt, reconcileError, reconciling])

  useLayoutEffect(() => {
    if (!outcomeUncertain) return
    if (outcomeReconciling || outcomeReconciled) outcomeStatusRef.current?.focus()
    else if (outcomeReconcileError) outcomeRetryRef.current?.focus()
  }, [outcomeReconcileError, outcomeReconciled, outcomeReconciling, outcomeUncertain])

  async function copyDiagnostics(value: string) {
    try {
      if (navigator.clipboard?.writeText) await navigator.clipboard.writeText(value)
      else {
        const field = document.createElement('textarea')
        field.value = value; field.setAttribute('readonly', ''); field.className = 'clipboard-fallback'; document.body.append(field); field.select()
        let copied = false
        try { copied = typeof document.execCommand === 'function' && document.execCommand('copy') }
        finally { field.remove() }
        if (!copied) throw new Error('Copy command was rejected.')
      }
      setCopyStatus('Diagnostics copied.')
    } catch { setCopyStatus('Copy unavailable. Select the receipt ID and include it with support diagnostics.') }
  }

  async function reconcileUncertainOutcome() {
    if (outcomeReconcileInFlight.current) return
    outcomeReconcileInFlight.current = true
    setOutcomeReconciling(true)
    setOutcomeReconcileError(null)
    try {
      await onUncertain()
      setOutcomeReconciled(true)
    } catch (cause) {
      setOutcomeReconcileError(`Reconciliation failed. ${cause instanceof Error ? cause.message : 'Fresh swarm state is unavailable.'}`)
    } finally {
      outcomeReconcileInFlight.current = false
      setOutcomeReconciling(false)
    }
  }

  async function lockAndReconcileUncertain(message: string) {
    setPlan(null)
    setOutcomeUncertain(true)
    setOutcomeReconciled(false)
    setError(message)
    setExecuting(false)
    await reconcileUncertainOutcome()
  }

  async function execute() {
    if (!plan || plan.kind !== kind) return
    setExecuting(true); setError(null)
    let result: ContainmentReceipt
    try { result = await transport.executeAction({ planId: plan.planId, digest: plan.digest }) }
    catch (cause) {
      if (cause instanceof TransportError && (cause.code === 'outcome_uncertain' || cause.details?.reconcileRequired === true)) {
        await lockAndReconcileUncertain(`${cause.message} Do not repeat the action. The reviewed plan is permanently locked while fresh swarm state is reconciled.`)
      } else setError(cause instanceof TransportError ? cause.message : 'Containment did not complete. Review a fresh plan.')
      if (!(cause instanceof TransportError && (cause.code === 'outcome_uncertain' || cause.details?.reconcileRequired === true))) setExecuting(false)
      return
    }
    if (result.planId !== plan.planId || result.agentId !== plan.agentId) {
      await lockAndReconcileUncertain('The execution receipt did not match the reviewed plan and agent. Do not repeat the action. The reviewed plan is permanently locked while fresh swarm state is reconciled.')
      return
    }
    setReceipt(result); setExecuting(false)
    await reconcile(result)
  }

  async function reconcile(result: ContainmentReceipt) {
    setReconciling(true)
    try { await onComplete(result); setReconcileError(null); setReconciled(true) }
    catch (cause) { setReconcileError(`Reconciliation pending. ${cause instanceof Error ? cause.message : 'The latest agent state could not be loaded.'}`) }
    finally { setReconciling(false) }
  }

  const title = receipt ? 'Containment receipt' : `Review ${kind === 'graceful-stop' ? 'graceful stop' : 'force stop'}`
  const native = transport.mode === 'native'
  return (
    <Dialog title={title} onClose={onClose} closeDisabled={executing || (receipt !== null && !reconciled) || (outcomeUncertain && !outcomeReconciled)} restoreFocusRef={restoreFocusRef} className="containment-dialog">
      {receipt ? (
        <div className="receipt" aria-live="polite">
          <p className="receipt__success">{receipt.certainty === 'uncertain' ? '?' : receipt.certainty === 'failed_before_issue' ? '×' : receipt.partialFailures.length > 0 ? '!' : '✓'}</p><h3 ref={receiptHeadingRef} tabIndex={-1}>{receipt.title}</h3>
          <p>{native ? 'This receipt came from the local engine. Unknown values remain explicitly unreported.' : 'This Demo lab receipt records a synthetic state transition. No operating-system process was changed.'}</p>
          {native ? <ul><li>Processes handled: {receipt.processCount ?? 'Not reported'}</li><li>Ports released: {receipt.portCount ?? 'Not reported'}</li><li>Files quarantined: {receipt.fileCount ?? 'Not reported'}</li><li>Memory unchanged</li></ul> : <ul><li>{receipt.processCount} process{receipt.processCount === 1 ? '' : 'es'} handled</li><li>{receipt.portCount} port{receipt.portCount === 1 ? '' : 's'} released</li><li>{receipt.fileCount} files quarantined</li><li>Memory unchanged</li></ul>}
          {receipt.partialFailures.length > 0 && <div className="local-warning"><strong>Containment only partially completed.</strong><p>{receipt.certainty === 'verified' ? 'The action issuance is verified, but these follow-up results were incomplete:' : 'The receipt contains these incomplete results:'}</p><ul>{receipt.partialFailures.map((failure, index) => <li key={`${receipt.receiptId}-partial-${index}`}>{failure}</li>)}</ul></div>}
          {receipt.outcome && <p><strong>Engine outcome:</strong> {receipt.outcome}{receipt.certainty ? ` · certainty ${receipt.certainty.replaceAll('_', ' ')}` : ''}</p>}
          <p><strong>Plan ID</strong> <code>{receipt.planId}</code></p>
          <p><strong>Target agent</strong> <code>{receipt.agentId ?? 'Not reported'}</code></p>
          <p><strong>Receipt ID</strong> <code>{receipt.receiptId}</code></p>
          {reconciling && !reconcileError && <p ref={reconcileStatusRef} role="status" tabIndex={-1}>Reconciling the latest dashboard and inspector state…</p>}
          {reconcileError && <div className="error-banner" role="alert"><strong>{reconcileError}</strong>{reconciling && <p ref={reconcileStatusRef} role="status" tabIndex={-1}>Retrying reconciliation…</p>}<button ref={reconcileRetryRef} type="button" className="secondary-button" aria-disabled={reconciling} onClick={() => { if (!reconciling) void reconcile(receipt) }}>{reconciling ? 'Retrying…' : 'Retry reconciliation'}</button></div>}
          <div className="dialog__actions"><button ref={returnRef} type="button" className="primary-button" disabled={!reconciled} onClick={native ? onClose : onReturn}>{native ? 'Return to swarm' : 'Return to inspector'}</button><button type="button" className="secondary-button" onClick={() => void copyDiagnostics(receipt.diagnostics)}>Copy receipt summary</button></div>
          <p className="muted">The audit receipt is available on the Activity page.</p>
          {copyStatus && <p role="status">{copyStatus}</p>}
          <p className="muted">{native ? transport.capabilities.quarantineRestore ? 'Eligible quarantined resources can be reviewed for restore in Activity.' : 'Quarantine restore is unavailable from this engine.' : 'Restore files is available later in Activity.'}</p>
        </div>
      ) : (
        <>
          <div className="action-kind-picker" role="group" aria-label="Containment method">
            <button type="button" aria-pressed={kind === 'graceful-stop'} disabled={executing || outcomeUncertain} className={kind === 'graceful-stop' ? 'selected' : ''} onClick={() => void loadPlan('graceful-stop')}>Choose graceful stop</button>
            <button type="button" aria-pressed={kind === 'force-stop'} disabled={executing || outcomeUncertain} className={kind === 'force-stop' ? 'selected danger-outline' : 'danger-outline'} onClick={() => void loadPlan('force-stop')}>Choose force stop</button>
          </div>
          {loading && <p role="status">Preparing immutable review plan…</p>}
          {error && <div className="error-banner" role="alert"><strong>{outcomeUncertain ? 'Outcome uncertain' : 'Action not completed'}</strong><p>{error}</p>{outcomeUncertain && <>{outcomeReconciling && <p ref={outcomeStatusRef} role="status" tabIndex={-1}>Refreshing the swarm before this dialog can close…</p>}{outcomeReconcileError && <><p>{outcomeReconcileError}</p><button ref={outcomeRetryRef} type="button" className="secondary-button" onClick={() => void reconcileUncertainOutcome()}>Retry swarm reconciliation</button></>}{outcomeReconciled && <p ref={outcomeStatusRef} role="status" tabIndex={-1}>Latest swarm state refreshed. The original action remains locked and cannot be repeated.</p>}</>}</div>}
          {plan?.kind === kind && <div className="plan-review">
            <p className="demo-label">{native ? 'Local engine' : 'Demo lab'} · {plan.engineMode} · expires {new Date(plan.expiresAt).toLocaleTimeString()}</p>
            <p className="local-warning"><strong>Engine-bound identity.</strong> Confirm only the PID and process-instance digest returned by this immutable plan.</p>
            <dl><div><dt>Target</dt><dd>PID {plan.target.pid}</dd></div><div><dt>Process instance</dt><dd><code>{plan.target.processInstanceId}</code></dd></div><div><dt>Planned state</dt><dd>{plan.target.state}</dd></div><div><dt>Strategy</dt><dd>{plan.strategy}</dd></div><div><dt>Timeout</dt><dd>{plan.timeoutSeconds === null ? 'Not reported' : `${plan.timeoutSeconds}s`}</dd></div><div><dt>Ports expected to release</dt><dd>{plan.expectedPortsReleased === null ? 'Not reported' : plan.expectedPortsReleased.join(', ') || 'None observed'}</dd></div><div><dt>Files</dt><dd>{plan.eligibleQuarantineFiles === null ? 'Not reported' : <>{plan.eligibleQuarantineFiles.length} eligible quarantine files<ul className="quarantine-file-list">{plan.eligibleQuarantineFiles.map((path) => <li key={path}><code>{path}</code></li>)}</ul></>}</dd></div><div><dt>Memory</dt><dd>Memory unchanged</dd></div></dl>
            <h3>Irreversible consequences</h3><ul>{plan.irreversibleConsequences.map((item) => <li key={item}>{item}</li>)}</ul>
            {kind === 'force-stop' ? <label className="confirm-field">Type {`${plan.target.pid}:${plan.target.processInstanceId.slice(0, 12)}`} to confirm<input ref={confirmRef} value={typedPid} onChange={(event) => setTypedPid(event.target.value)} aria-label={`Type ${plan.target.pid}:${plan.target.processInstanceId.slice(0, 12)} to confirm`} /></label> : <label className="confirm-check"><input ref={confirmRef} type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} /> Confirm this exact plan for engine-bound PID {plan.target.pid} and process instance {plan.target.processInstanceId.slice(0, 12)}</label>}
            <div className="dialog__actions"><button type="button" className={kind === 'force-stop' ? 'danger-button' : 'primary-button'} disabled={executing || (kind === 'force-stop' ? typedPid !== `${plan.target.pid}:${plan.target.processInstanceId.slice(0, 12)}` : !confirmed)} onClick={() => void execute()}>{executing ? 'Executing…' : `Execute ${kind === 'force-stop' ? 'force stop' : 'graceful stop'}`}</button><button type="button" className="secondary-button" disabled={executing} onClick={onClose}>Cancel</button></div>
          </div>}
        </>
      )}
    </Dialog>
  )
}
