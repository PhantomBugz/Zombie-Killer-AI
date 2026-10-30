import { useEffect, useRef, useState } from 'react'

import { LocalWorkflowReview } from '../../components/LocalWorkflowReview'
import type { EngineTransport, LocalWorkflowPlan, NativeSnapshot } from '../../transport'

interface Props { sourceId: string; revision: string; transport: EngineTransport; onChanged: () => Promise<void> }
export function NativeSnapshotHistory({ sourceId, revision, transport, onChanged }: Props) {
  const key = JSON.stringify([sourceId, revision])
  const [loaded, setLoaded] = useState<{ key: string; snapshots: NativeSnapshot[] }>({ key: '', snapshots: [] })
  const [reviewState, setReviewState] = useState<{ key: string; plan?: LocalWorkflowPlan; executionStarted: boolean }>({ key, executionStarted: false })
  if (reviewState.key !== key && !reviewState.executionStarted) setReviewState({ key, executionStarted: false })
  const plan = reviewState.plan
  const [failure, setFailure] = useState<{ key: string; message: string }>({ key: '', message: '' })
  const [attempt, setAttempt] = useState(0)
  const [busy, setBusy] = useState(false)
  const generation = useRef(0)
  const opener = useRef<HTMLElement | null>(null)
  const snapshots = loaded.key === key ? loaded.snapshots : []
  const error = failure.key === key ? failure.message : ''
  useEffect(() => {
    const current = ++generation.current
    void transport.getNativeSnapshots?.(sourceId).then((result) => { if (generation.current === current) { setLoaded({ key, snapshots: result }); setFailure({ key, message: '' }) } }).catch((reason: unknown) => { if (generation.current === current) setFailure({ key, message: reason instanceof Error ? reason.message : 'Snapshots are unavailable.' }) })
    return () => { generation.current += 1 }
  }, [sourceId, key, transport, attempt])
  async function review(snapshot: NativeSnapshot) {
    const current = generation.current
    setBusy(true); setFailure({ key, message: '' })
    try {
      const result = await transport.planNativeMemoryRestore?.({ sourceId, snapshotId: snapshot.id, snapshotDigest: snapshot.digest, expectedRevision: revision })
      if (current === generation.current && result) setReviewState({ key, plan: result, executionStarted: false })
    } catch (reason) { if (current === generation.current) setFailure({ key, message: reason instanceof Error ? reason.message : 'Snapshot restore review failed.' }) }
    finally { if (current === generation.current) setBusy(false) }
  }
  return <div className="memory-history"><p>Snapshots cover the entire source. Restore replaces that source with the verified snapshot and refuses a concurrent revision change. At most 500 snapshots are shown.</p>{error && <div role="alert"><p>{error}</p><button className="secondary-button" type="button" onClick={() => setAttempt((value) => value + 1)}>Refresh snapshots</button></div>}{snapshots.length ? <ol>{snapshots.map((snapshot) => <li key={snapshot.id}><strong>{snapshot.id}</strong><span>{snapshot.createdAt} · {snapshot.size} bytes · {snapshot.status}</span><code>{snapshot.sourceRevision}</code>{snapshot.status === 'verified' && transport.planNativeMemoryRestore && <button className="secondary-button" type="button" disabled={busy} onClick={(event) => { opener.current = event.currentTarget; void review(snapshot) }}>Review snapshot restore</button>}</li>)}</ol> : loaded.key === key ? <p>No verified snapshots have been reported for this source.</p> : !error && <p role="status">Loading verified snapshots…</p>}{plan && transport.executeNativeMemoryRestore && <LocalWorkflowReview title="Review source snapshot restore" confirmLabel="Restore verified snapshot" plan={plan} execute={transport.executeNativeMemoryRestore.bind(transport)} onSettled={onChanged} onExecutionAttempt={() => setReviewState((current) => ({ ...current, executionStarted: true }))} onClose={() => setReviewState({ key, executionStarted: false })} restoreFocusRef={opener} />}</div>
}
