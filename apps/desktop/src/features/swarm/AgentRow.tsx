import { StatusBadge } from '../../components/StatusBadge'
import type { AgentSummary } from '../../transport/types'

function heartbeatLabel(value: string | null, now: string, native: boolean) {
  if (!value) return native ? 'Heartbeat not exposed' : 'Heartbeat not observed'
  const seconds = Math.max(0, Math.round((Date.parse(now) - Date.parse(value)) / 1000))
  return `Heartbeat ${seconds < 60 ? `${seconds}s` : `${Math.floor(seconds / 60)}m ${seconds % 60}s`} ago`
}

export function AgentRow({ agent, capturedAt, native = false, onInspect }: { agent: AgentSummary; capturedAt: string; native?: boolean; onInspect: (agent: AgentSummary, trigger: HTMLButtonElement) => void }) {
  return (
    <li className="agent-row">
      <div className="agent-row__identity">
        <strong>{agent.role ?? 'Role not reported'}</strong><span>{agent.project ?? 'Project not reported'}</span>
      </div>
      <StatusBadge state={agent.state} confidence={agent.confidence} />
      <dl className="agent-row__meta">
        <div><dt>Provider</dt><dd>{agent.provider ?? 'Not reported'}</dd></div>
        <div><dt>Runtime</dt><dd>{agent.runtime ?? 'Not reported'}</dd></div>
        <div><dt>Process</dt><dd>{agent.pid === null ? 'PID not available' : `PID ${agent.pid}`} · {agent.host ?? 'Host not reported'}</dd></div>
        <div><dt>Memory</dt><dd>{agent.ramMb === null ? 'Not available' : `${agent.ramMb} MB RAM`}</dd></div>
        <div><dt>Network</dt><dd>{agent.network === 'observed' ? 'Observed' : agent.network === 'not-observed' ? 'Not observed' : 'Unknown'}</dd></div>
      </dl>
      <ul className="signal-list" aria-label={`Strongest evidence for ${agent.role ?? 'agent'}`}>
        {agent.evidence.slice(0, 2).map((signal) => <li key={signal.id}>{signal.label}</li>)}
      </ul>
      <div className="agent-row__tail">
        <span>{heartbeatLabel(agent.heartbeatAt, capturedAt, native)}</span>
        <button type="button" className="secondary-button" onClick={(event) => onInspect(agent, event.currentTarget)} aria-label={`Inspect ${agent.role ?? 'agent'}`}>Inspect</button>
      </div>
    </li>
  )
}
