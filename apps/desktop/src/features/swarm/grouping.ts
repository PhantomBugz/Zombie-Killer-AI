import type { AgentState } from '../../transport/types'

export type GroupKey = 'attention' | 'active' | 'terminal' | 'unmanaged' | 'unknown'

export function groupForState(state: AgentState): GroupKey {
  switch (state) {
    case 'healthy':
    case 'idle':
      return 'active'
    case 'completed':
    case 'cancelled':
      return 'terminal'
    case 'stale':
    case 'orphaned':
    case 'unresponsive':
    case 'interrupted':
    case 'defunct':
    case 'failed':
      return 'attention'
    case 'unmanaged':
      return 'unmanaged'
    case 'unknown':
      return 'unknown'
    default: {
      const exhaustive: never = state
      return exhaustive
    }
  }
}
