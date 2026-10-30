import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react'

import { AppShell, type RouteId } from './components/AppShell'
import { CommandPalette } from './components/CommandPalette'
import { ActivityPage } from './features/activity/ActivityPage'
import { MemoryPage } from './features/memory/MemoryPage'
import { SettingsPage } from './features/settings/SettingsPage'
import { useSettingsController } from './features/settings/useSettingsController'
import { SwarmPage } from './features/swarm/SwarmPage'
import { createTransport } from './transport'
import type { EngineTransport, ScanResult } from './transport'

interface AppProps { transport?: EngineTransport }

export default function App({ transport: suppliedTransport }: AppProps = {}) {
  const [transport] = useState(() => suppliedTransport ?? createTransport())
  const [activeRoute, setActiveRoute] = useState<RouteId>('swarm')
  const [paletteOpen, setPaletteOpen] = useState(false)
  const [latestGlobalScan, setLatestGlobalScan] = useState<ScanResult | null>(null)
  const commandButtonRef = useRef<HTMLButtonElement>(null)
  const paletteOpenerRef = useRef<HTMLElement | null>(null)
  const routeFocusPending = useRef(false)
  const startupRetryRef = useRef<HTMLButtonElement>(null)
  const settingsController = useSettingsController(transport)
  const { reload: reloadSettings, settings } = settingsController

  const runGlobalScan = useCallback(async () => {
    const persistedSettings = settings ?? await reloadSettings()
    const scan = await transport.scan({
      includeUnmanagedCandidates: persistedSettings.includeUnmanagedCandidates !== false,
    })
    setLatestGlobalScan(scan)
  }, [reloadSettings, settings, transport])

  const openPalette = useCallback((opener: HTMLElement | null) => {
    if (document.querySelector('[role="dialog"][aria-modal="true"]')) return
    paletteOpenerRef.current = opener
    setPaletteOpen(true)
  }, [])

  useEffect(() => {
    function handleKeyDown(event: KeyboardEvent) {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') { event.preventDefault(); openPalette(document.activeElement instanceof HTMLElement ? document.activeElement : null) }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [openPalette])

  useLayoutEffect(() => {
    if (paletteOpen || !routeFocusPending.current) return
    const main = document.querySelector<HTMLElement>('#main-content')
    if (!main) return
    const focusDurableHeading = () => {
      const heading = main.querySelector<HTMLElement>('[data-route-heading="true"]')
      if (!heading) return false
      routeFocusPending.current = false
      heading.tabIndex = -1
      heading.focus()
      return true
    }
    if (focusDurableHeading()) return
    const observer = new MutationObserver(() => {
      if (focusDurableHeading()) observer.disconnect()
    })
    observer.observe(main, { childList: true, subtree: true })
    return () => observer.disconnect()
  }, [activeRoute, paletteOpen, settings])

  useLayoutEffect(() => {
    if (!settings && settingsController.error) startupRetryRef.current?.focus()
  }, [settings, settingsController.error, settingsController.loading])

  return (
    <AppShell
      activeRoute={activeRoute}
      onNavigate={setActiveRoute}
      onScan={runGlobalScan}
      onOpenCommand={() => openPalette(commandButtonRef.current)}
      commandButtonRef={commandButtonRef}
      mode={transport.mode}
    >
      {!settingsController.settings ? (
        <div className="workspace-page startup-settings">
          <h1>{activeRoute === 'swarm' ? 'Swarm' : activeRoute === 'memory' ? 'Memory Vault' : activeRoute === 'activity' ? 'Activity' : 'Settings'}</h1>
          {settingsController.error
            ? <div className="error-banner" role="alert"><p>{settingsController.error}</p><button ref={startupRetryRef} className="secondary-button" type="button" onClick={() => { routeFocusPending.current = true; void settingsController.reload().catch(() => undefined) }}>Retry settings</button></div>
            : <p>Loading local settings…</p>}
        </div>
      ) : activeRoute === 'swarm' ? (
        <SwarmPage
          externalScan={latestGlobalScan}
          includeUnmanagedCandidates={settingsController.settings.includeUnmanagedCandidates !== false}
          refreshIntervalMs={settingsController.settings.autoRefreshSeconds * 1_000}
          transport={transport}
        />
      ) : activeRoute === 'memory' ? <MemoryPage transport={transport} />
        : activeRoute === 'activity' ? <ActivityPage transport={transport} />
          : <SettingsPage controller={settingsController} transport={transport} />}
      {paletteOpen && <CommandPalette mode={transport.mode} onClose={() => setPaletteOpen(false)} onNavigate={(route) => { routeFocusPending.current = true; setActiveRoute(route) }} restoreFocusRef={paletteOpenerRef} />}
    </AppShell>
  )
}
