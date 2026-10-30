import { useMemo, useRef, useState, type KeyboardEvent } from 'react'

import type { RouteId } from './AppShell'
import { Dialog } from './Dialog'
import type { TransportMode } from '../transport'

const demoCommands: Array<{ label: string; detail: string; route: RouteId; shortcut?: string }> = [
  { label: 'Open Swarm', detail: 'Agents and projects', route: 'swarm', shortcut: 'G S' },
  { label: 'Open scan review', detail: 'Review demo coverage; does not execute containment', route: 'swarm' },
  { label: 'Open Memory Vault', detail: 'MTGA JSON memory and Mev BOT SQLite memory', route: 'memory', shortcut: 'G M' },
  { label: 'Search local memory', detail: 'Open read-only memory search', route: 'memory' },
  { label: 'Open Activity', detail: 'Events, receipts, and quarantine', route: 'activity', shortcut: 'G A' },
  { label: 'Open Settings', detail: 'Privacy, appearance, accessibility, retention, and About', route: 'settings', shortcut: 'G ,' },
]

interface CommandPaletteProps { mode?: TransportMode; onClose: () => void; onNavigate: (route: RouteId) => void; restoreFocusRef: React.RefObject<HTMLElement | null> }

export function CommandPalette({ mode = 'demo', onClose, onNavigate, restoreFocusRef }: CommandPaletteProps) {
  const [query, setQuery] = useState('')
  const [active, setActive] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)
  const commands = useMemo(() => mode === 'demo' ? demoCommands : demoCommands.map((command) => {
    if (command.label === 'Open scan review') return { ...command, detail: 'Review local-engine coverage; no action is executed' }
    if (command.label === 'Open Memory Vault') return { ...command, detail: 'Registered local sources and reviewed scalar repair' }
    return command
  }), [mode])
  const filtered = useMemo(() => commands.filter((command) => `${command.label} ${command.detail}`.toLowerCase().includes(query.toLowerCase())), [commands, query])
  const index = Math.min(active, Math.max(0, filtered.length - 1))

  function select(command = filtered[index]) {
    if (!command) return
    restoreFocusRef.current = null
    onNavigate(command.route)
    onClose()
  }
  function keyDown(event: KeyboardEvent<HTMLInputElement>) {
    if (event.key === 'ArrowDown') { event.preventDefault(); setActive((value) => Math.min(filtered.length - 1, value + 1)) }
    else if (event.key === 'ArrowUp') { event.preventDefault(); setActive((value) => Math.max(0, value - 1)) }
    else if (event.key === 'Home') { event.preventDefault(); setActive(0) }
    else if (event.key === 'End') { event.preventDefault(); setActive(Math.max(0, filtered.length - 1)) }
    else if (event.key === 'Enter') { event.preventDefault(); select() }
  }

  return <Dialog title="Command palette" onClose={onClose} initialFocusRef={inputRef} restoreFocusRef={restoreFocusRef} className="command-palette">
    <label className="field"><span>Search routes, agents, projects, or memory sources</span><input ref={inputRef} type="search" value={query} aria-controls="command-list" aria-activedescendant={filtered[index] ? `command-${commands.indexOf(filtered[index])}` : undefined} onChange={(event) => { setQuery(event.target.value); setActive(0) }} onKeyDown={keyDown} /></label>
    <p className="muted">Navigation and review only. Commands cannot execute containment, apply memory changes, restore, or purge.</p>
    <div id="command-list" role="listbox" aria-label="Commands">{filtered.map((command, itemIndex) => <button key={command.label} id={`command-${commands.indexOf(command)}`} role="option" aria-selected={itemIndex === index} type="button" onClick={() => select(command)}><span><strong>{command.label}</strong><small>{command.detail}</small></span>{command.shortcut && <kbd>{command.shortcut}</kbd>}</button>)}</div>
    {!filtered.length && <p className="empty-state">No navigation command found.</p>}
  </Dialog>
}
