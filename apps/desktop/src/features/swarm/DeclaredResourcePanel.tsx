import { useEffect, useRef, useState } from 'react'

import { LocalWorkflowReview } from '../../components/LocalWorkflowReview'
import type { AgentDetail, DeclaredResource, EngineTransport, LocalWorkflowPlan } from '../../transport'

export function DeclaredResourcePanel({ detail, transport }: { detail: AgentDetail; transport: EngineTransport }) {
  const [resources, setResources] = useState<DeclaredResource[]>([])
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [reviewing, setReviewing] = useState(false)
  const [plan, setPlan] = useState<LocalWorkflowPlan>()
  const [reviewTarget, setReviewTarget] = useState('')
  const generation = useRef(0)
  const pending = useRef(false)
  const opener = useRef<HTMLElement | null>(null)
  const expected = { id: detail.id, revision: detail.revision, pid: detail.pid, processInstanceId: detail.processInstanceId }

  async function refresh() {
    if (!transport.getDeclaredResources) return
    const current = ++generation.current
    setLoading(true); setError('')
    try { const next = await transport.getDeclaredResources(detail.id, expected); if (current === generation.current) setResources(next) }
    catch (reason) { if (current === generation.current) { setError(reason instanceof Error ? reason.message : 'Declared resources are unavailable.'); throw reason } }
    finally { if (current === generation.current) setLoading(false) }
  }

  useEffect(() => {
    const current = ++generation.current
    if (!transport.getDeclaredResources) return
    void transport.getDeclaredResources(detail.id, { id: detail.id, revision: detail.revision, pid: detail.pid, processInstanceId: detail.processInstanceId }).then((next) => { if (current === generation.current) { setResources(next); setLoading(false) } }).catch((reason: unknown) => { if (current === generation.current) { setError(reason instanceof Error ? reason.message : 'Declared resources are unavailable.'); setLoading(false) } })
    return () => { generation.current += 1 }
  }, [detail.id, detail.pid, detail.processInstanceId, detail.revision, transport])

  async function review(resource: DeclaredResource) {
    if (pending.current || !resource.eligible || !transport.planResourceCleanup) return
    const current = generation.current
    pending.current = true; setReviewing(true); setError('')
    try { const next = await transport.planResourceCleanup(detail.id, resource.id, expected); if (current === generation.current) { setReviewTarget(`${detail.id} / ${resource.label}`); setPlan(next) } }
    catch (reason) { if (current === generation.current) setError(reason instanceof Error ? reason.message : 'Cleanup review failed.') }
    finally { pending.current = false; if (current === generation.current) setReviewing(false) }
  }

  return <section className="declared-resources"><h3>Declared temporary resources</h3><p>Only resources declared by this managed lease can be reviewed. The engine checks owner liveness and file identity; no path is supplied by the renderer.</p>{error && <div className="error-banner" role="alert"><p>{error}</p><button type="button" className="secondary-button" onClick={() => void refresh().catch(() => undefined)}>Refresh resources</button></div>}{loading ? <p role="status">Loading declared resources…</p> : resources.length ? <ul>{resources.map((resource) => <li key={resource.id}><strong>{resource.label}</strong><p>{resource.reason}</p><button className="secondary-button" type="button" disabled={!resource.eligible || reviewing} onClick={(event) => { opener.current = event.currentTarget; void review(resource) }}>Review resource cleanup</button></li>)}</ul> : <p>No declared temporary resources are available.</p>}{plan && transport.executeResourceCleanup && <LocalWorkflowReview title="Review declared resource cleanup" subject={reviewTarget} confirmLabel="Quarantine declared resource" plan={plan} execute={(request) => transport.executeResourceCleanup!(request)} onSettled={refresh} onClose={() => setPlan(undefined)} restoreFocusRef={opener} />}</section>
}
