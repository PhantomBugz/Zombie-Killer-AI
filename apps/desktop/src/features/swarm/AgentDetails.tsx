import { useEffect, useLayoutEffect, useRef, useState, type KeyboardEvent } from 'react'

import { Dialog } from '../../components/Dialog'
import { StatusBadge } from '../../components/StatusBadge'
import type { ActionKind, AgentDetail, AgentSummary, EngineTransport } from '../../transport/types'
import { DeclaredResourcePanel } from './DeclaredResourcePanel'

const tabs = ['Overview', 'Process', 'Artifacts', 'Memory', 'Activity'] as const
type Tab = (typeof tabs)[number]

interface Props { agent: AgentSummary; transport: EngineTransport; onClose: () => void; onReview: (agent: AgentDetail, kind: ActionKind) => void }

export function AgentDetails({ agent, transport, onClose, onReview }: Props) {
  const [detail, setDetail] = useState<AgentDetail | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [attempt, setAttempt] = useState(0)
  const [activeTab, setActiveTab] = useState<Tab>('Overview')
  const firstTabRef = useRef<HTMLButtonElement>(null)
  const focusTabsAfterRetry = useRef(false)

  useEffect(() => {
    let current = true
    void transport.getAgentDetail(agent.id, { id: agent.id, revision: agent.revision, pid: agent.pid, processInstanceId: agent.processInstanceId }).then(
      (value) => { if (current) { setDetail(value); setError(null); setLoading(false) } },
      (cause: unknown) => { if (current) { setDetail(null); setError(cause instanceof Error ? cause.message : 'Agent details could not be loaded.'); setLoading(false) } },
    )
    return () => { current = false }
  }, [agent.id, agent.pid, agent.processInstanceId, agent.revision, attempt, transport])

  useLayoutEffect(() => {
    if (detail && focusTabsAfterRetry.current) {
      firstTabRef.current?.focus()
      focusTabsAfterRetry.current = false
    }
  }, [detail])

  function retry() { setDetail(null); setLoading(true); focusTabsAfterRetry.current = true; setAttempt((value) => value + 1) }

  function onTabKeyDown(event: KeyboardEvent<HTMLButtonElement>, index: number) {
    let next: number
    if (event.key === 'ArrowRight') next = (index + 1) % tabs.length
    else if (event.key === 'ArrowLeft') next = (index - 1 + tabs.length) % tabs.length
    else if (event.key === 'Home') next = 0
    else if (event.key === 'End') next = tabs.length - 1
    else return
    event.preventDefault(); setActiveTab(tabs[next]); document.getElementById(`agent-tab-${next}`)?.focus()
  }

  return (
    <Dialog title={agent.role ?? 'Agent details'} onClose={onClose} initialFocusRef={firstTabRef} className="agent-details">
      <div className="agent-details__heading">
        <div><p>{agent.project ?? 'Project not reported'} · {agent.provider ?? 'Provider not reported'} · {agent.pid === null ? 'PID unavailable' : `PID ${agent.pid}`}</p>{detail && <StatusBadge state={detail.state} confidence={detail.confidence} />}</div>
        <p>{detail?.diagnosis ?? (error ? 'Diagnosis unavailable.' : 'Loading diagnosis…')}</p>
      </div>
      {error ? <div className="error-banner" role="alert"><strong>Agent details unavailable</strong><p>{error}</p>{loading && <p role="status">Retrying agent details…</p>}<div className="dialog__actions"><button type="button" className="secondary-button" aria-disabled={loading} onClick={() => { if (!loading) retry() }}>{loading ? 'Retrying…' : 'Retry details'}</button><button type="button" className="secondary-button" onClick={onClose}>Close inspector</button></div></div> : <><div className="tabs" role="tablist" aria-label="Agent evidence">
        {tabs.map((tab, index) => <button key={tab} ref={index === 0 ? firstTabRef : undefined} id={`agent-tab-${index}`} type="button" role="tab" aria-selected={activeTab === tab} aria-controls={`agent-panel-${index}`} tabIndex={activeTab === tab ? 0 : -1} onClick={() => setActiveTab(tab)} onKeyDown={(event) => onTabKeyDown(event, index)}>{tab}</button>)}
      </div>
      <section className="tab-panel" id={`agent-panel-${tabs.indexOf(activeTab)}`} role="tabpanel" aria-labelledby={`agent-tab-${tabs.indexOf(activeTab)}`} tabIndex={0}>
        {!detail ? <p role="status">Loading agent evidence…</p> : <><TabContent tab={activeTab} detail={detail} native={transport.mode === 'native'} />{activeTab === 'Artifacts' && transport.mode === 'native' && transport.capabilities.resourceCleanup && !detail.id.startsWith('unmanaged:') && <DeclaredResourcePanel detail={detail} transport={transport} />}</>}
      </section>
      {detail && <div className="agent-actions">
        {detail.actionable && transport.capabilities.processActions ? <><button type="button" className="primary-button" onClick={() => onReview(detail, 'graceful-stop')}>Request graceful stop</button><button type="button" className="secondary-button" onClick={() => onReview(detail, 'graceful-stop')}>Review containment</button><div className="agent-actions__danger"><span>Immediate termination</span><button type="button" className="danger-button" onClick={() => onReview(detail, 'force-stop')}>Force stop</button></div></> : <p className="non-actionable"><strong>Containment unavailable.</strong> {transport.capabilities.processActions ? detail.actionReason : transport.capabilities.processActionsUnavailableReason ?? 'This transport does not expose process actions.'}</p>}
      </div>}
      </>}
    </Dialog>
  )
}

function Empty({ children }: { children: string }) { return <p className="empty-state">{children}</p> }

function TabContent({ tab, detail, native }: { tab: Tab; detail: AgentDetail; native: boolean }) {
  const unavailable = (label: string, demo: string) => native ? `${label} is not exposed by the local engine.` : demo
  if (tab === 'Overview') return <><h3>Current task</h3><p>{detail.currentTask ?? unavailable('Current task', 'No current task was observed.')}</p><h3>Evidence stack</h3><ol className="evidence-stack">{detail.evidence.map((item) => <li key={item.id}><strong>{item.label}</strong><span>{item.source} · {new Date(item.observedAt).toLocaleString()} · {item.grade}</span><p>{item.detail}</p></li>)}</ol>{detail.partialSections.length > 0 && <p className="partial-note">Partial data: {detail.partialSections.join(', ')}.</p>}</>
  if (tab === 'Process') return <><h3>Process tree</h3>{detail.processTree.length ? <ul>{detail.processTree.map((process) => <li key={process.pid}><code>{process.name}</code> · PID {process.pid} · {process.relationship} · {process.status}</li>)}</ul> : <Empty>{unavailable('Process tree', 'No process tree was observed.')}</Empty>}<h3>Redacted command line</h3><code className="code-block">{detail.commandLine ?? (native ? 'Not exposed' : 'Not available')}</code><h3>Network and ports</h3>{detail.ports.length ? <ul>{detail.ports.map((port) => <li key={`${port.protocol}-${port.port}`}>{port.protocol} {port.port} · {port.status}</li>)}</ul> : <Empty>{unavailable('Port detail', 'No ports were observed.')}</Empty>}</>
  if (tab === 'Artifacts') return <><h3>File writes</h3>{detail.fileWrites.length ? <ul>{detail.fileWrites.map((file) => <li key={file.path}><code>{file.path}</code> · {file.status}</li>)}</ul> : <Empty>{unavailable('File-write detail', 'No file writes were observed.')}</Empty>}</>
  if (tab === 'Memory') return <><h3>Resource history</h3>{detail.resources.length ? <ul>{detail.resources.map((point) => <li key={point.observedAt}>{new Date(point.observedAt).toLocaleTimeString()} · {point.ramMb} MB RAM · {point.cpuPercent}% CPU</li>)}</ul> : <Empty>{unavailable('Resource history', 'No memory samples were observed.')}</Empty>}<h3>Heartbeat history</h3>{detail.heartbeatHistory.length ? <ul>{detail.heartbeatHistory.map((beat) => <li key={beat.at}>{new Date(beat.at).toLocaleTimeString()} · {beat.result}</li>)}</ul> : <Empty>{unavailable('Heartbeat history', 'No managed heartbeat history is available.')}</Empty>}</>
  return <><h3>Status timeline</h3>{detail.timeline.length ? <ol>{detail.timeline.map((event) => <li key={event.id}><strong>{event.title}</strong> · {new Date(event.at).toLocaleString()}<p>{event.detail}</p></li>)}</ol> : <Empty>{unavailable('Status timeline', 'No managed activity is available.')}</Empty>}</>
}
