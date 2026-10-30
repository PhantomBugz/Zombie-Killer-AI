import type { AgentState, Confidence } from '../transport/types'

const stateLabels: Record<AgentState, string> = {
  healthy: 'Healthy', idle: 'Idle', stale: 'Stale', orphaned: 'Orphaned', unresponsive: 'Unresponsive',
  unmanaged: 'Unmanaged', interrupted: 'Interrupted', defunct: 'Defunct', completed: 'Completed',
  failed: 'Failed', cancelled: 'Cancelled', unknown: 'Unknown',
}

const stateIcons: Record<AgentState, string> = {
  healthy: '●', idle: '◷', stale: '△', orphaned: '!', unresponsive: '×', unmanaged: '?',
  interrupted: '■', defunct: '†', completed: '✓', failed: '×', cancelled: '■', unknown: '◇',
}

export function StatusBadge({ state, confidence }: { state: AgentState; confidence: Confidence }) {
  return (
    <span className={`status-badge status-badge--${state}`}>
      <span aria-hidden="true">{stateIcons[state]}</span>
      <span>{stateLabels[state]}</span>
      <span className="status-badge__confidence">{confidence} confidence</span>
    </span>
  )
}
