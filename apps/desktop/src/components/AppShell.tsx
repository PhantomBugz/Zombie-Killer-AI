import {
  useEffect,
  useRef,
  useState,
  type KeyboardEvent,
  type MouseEvent,
  type ReactNode,
} from 'react'

import { BrandMark } from './BrandMark'
import { Icon, type IconName } from './Icon'
import { useBodyScrollLock } from './useBodyScrollLock'
import type { TransportMode } from '../transport'

export type RouteId = 'swarm' | 'memory' | 'activity' | 'settings'

interface RouteDefinition {
  id: RouteId
  label: string
  icon: IconName
}

const routes: readonly RouteDefinition[] = [
  { id: 'swarm', label: 'Swarm', icon: 'swarm' },
  { id: 'memory', label: 'Memory Vault', icon: 'memory' },
  { id: 'activity', label: 'Activity', icon: 'activity' },
  { id: 'settings', label: 'Settings', icon: 'settings' },
]

const creatorAttribution = 'Made by PhantomBugz'
const mobileNavigationQuery = '(max-width: 899px)'

interface AppShellProps {
  activeRoute: RouteId
  children: ReactNode
  onNavigate: (route: RouteId) => void
  onScan?: () => Promise<void>
  onOpenCommand?: () => void
  commandButtonRef?: React.RefObject<HTMLButtonElement | null>
  mode?: TransportMode
}

export function AppShell({ activeRoute, children, onNavigate, onScan, onOpenCommand, commandButtonRef, mode = 'demo' }: AppShellProps) {
  const [navigationOpen, setNavigationOpen] = useState(false)
  const [isMobile, setIsMobile] = useState(
    () => window.matchMedia?.(mobileNavigationQuery).matches ?? true,
  )
  const [scanStatus, setScanStatus] = useState<'idle' | 'running' | 'complete' | 'error'>('idle')
  const [scanError, setScanError] = useState('')
  const mainRef = useRef<HTMLElement>(null)
  const navigationRef = useRef<HTMLDivElement>(null)
  const navigationToggleRef = useRef<HTMLButtonElement>(null)
  const pendingFocusRef = useRef<'main' | 'toggle' | null>(null)
  const activeRouteName = routes.find((route) => route.id === activeRoute)?.label ?? 'Workspace'
  const modalNavigationOpen = isMobile && navigationOpen

  useBodyScrollLock(modalNavigationOpen)

  useEffect(() => {
    if (modalNavigationOpen) {
      navigationRef.current?.querySelector<HTMLAnchorElement>('a[href]')?.focus()
      return
    }

    if (pendingFocusRef.current === 'toggle') {
      navigationToggleRef.current?.focus()
    } else if (pendingFocusRef.current === 'main') {
      mainRef.current?.focus()
    }
    pendingFocusRef.current = null
  }, [modalNavigationOpen])

  useEffect(() => {
    if (!window.matchMedia) {
      return
    }

    const mediaQuery = window.matchMedia(mobileNavigationQuery)
    const updateViewport = (event: Pick<MediaQueryListEvent, 'matches'>) => {
      setIsMobile(event.matches)
      if (!event.matches) {
        setNavigationOpen(false)
        if (document.activeElement === navigationToggleRef.current) {
          mainRef.current?.focus()
        }
      }
    }

    updateViewport(mediaQuery)
    mediaQuery.addEventListener('change', updateViewport)
    return () => mediaQuery.removeEventListener('change', updateViewport)
  }, [])

  function navigate(event: MouseEvent<HTMLAnchorElement>, route: RouteId) {
    event.preventDefault()
    onNavigate(route)
    if (modalNavigationOpen) {
      pendingFocusRef.current = 'main'
      setNavigationOpen(false)
    } else {
      mainRef.current?.focus()
    }
  }

  function handleNavigationKeyDown(event: KeyboardEvent<HTMLElement>) {
    if (!modalNavigationOpen) {
      return
    }

    if (event.key === 'Escape') {
      event.preventDefault()
      closeNavigationToToggle()
      return
    }

    if (event.key !== 'Tab') {
      return
    }

    const focusable = Array.from(
      navigationRef.current?.querySelectorAll<HTMLElement>('a[href], button:not([disabled])') ?? [],
    )
    const first = focusable.at(0)
    const last = focusable.at(-1)

    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault()
      last?.focus()
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault()
      first?.focus()
    }
  }

  function closeNavigationToToggle() {
    pendingFocusRef.current = 'toggle'
    setNavigationOpen(false)
  }

  function toggleNavigation() {
    if (isMobile) {
      setNavigationOpen((open) => !open)
    }
  }

  async function refreshCoverage() {
    if (scanStatus === 'running') {
      return
    }

    setScanError('')
    setScanStatus('running')
    try {
      if (!onScan) throw new Error('Global Scan is unavailable from this workspace.')
      await onScan()
      setScanStatus('complete')
    } catch (reason) {
      setScanError(reason instanceof Error ? reason.message : 'Global Scan failed.')
      setScanStatus('error')
    }
  }

  const scanStatusMessage =
    scanStatus === 'running'
      ? `Refreshing the ${mode === 'native' ? 'local engine' : 'demo view'}…`
      : scanStatus === 'complete'
        ? mode === 'native' ? 'Local-engine scan refreshed.' : 'Demo coverage refreshed. No host scan was run.'
        : scanStatus === 'error'
          ? `Global Scan failed. ${scanError}`
          : mode === 'native' ? 'Local-engine scan is available from every workspace.' : 'Demo preview only. No host scan will run.'

  return (
    <>
      <a
        className="skip-link"
        href="#main-content"
        aria-hidden={modalNavigationOpen || undefined}
        inert={modalNavigationOpen || undefined}
      >
        Skip to main content
      </a>

      <div className="app-shell">
        {modalNavigationOpen && (
          <div
            className="drawer-backdrop"
            data-navigation-backdrop="true"
            aria-hidden="true"
            onClick={closeNavigationToToggle}
          />
        )}
        <div
          ref={navigationRef}
          className={modalNavigationOpen ? 'sidebar sidebar--open' : 'sidebar'}
          aria-label="Application navigation"
          aria-modal={modalNavigationOpen ? true : undefined}
          data-mobile-drawer="true"
          role={modalNavigationOpen ? 'dialog' : 'complementary'}
          onKeyDown={handleNavigationKeyDown}
        >
          <div className="sidebar__brand">
            <BrandMark />
          </div>

          <nav className="primary-nav" aria-label="Primary navigation" id="primary-navigation">
            <ul>
              {routes.map((route) => (
                <li key={route.id}>
                  <a
                    className="primary-nav__link"
                    href={`#${route.id}`}
                    aria-current={route.id === activeRoute ? 'page' : undefined}
                    onClick={(event) => navigate(event, route.id)}
                  >
                    <Icon name={route.icon} />
                    <span>{route.label}</span>
                  </a>
                </li>
              ))}
            </ul>
          </nav>

          <div className="attribution" role="group" aria-label={creatorAttribution}>
            <span className="attribution__full-copy" aria-hidden="true">
              {creatorAttribution}
            </span>
            <span className="attribution__compact" aria-hidden="true">
              PB
            </span>
          </div>
        </div>

        <header
          className="topbar"
          aria-hidden={modalNavigationOpen || undefined}
          inert={modalNavigationOpen || undefined}
        >
          <div className="topbar__identity">
            <button
              ref={navigationToggleRef}
              className="icon-button navigation-toggle"
              type="button"
              aria-label={modalNavigationOpen ? 'Close navigation' : 'Open navigation'}
              aria-controls="primary-navigation"
              aria-expanded={modalNavigationOpen}
              onClick={toggleNavigation}
            >
              <Icon name="menu" />
            </button>
            <span className="topbar__product-name">Zombie Killer</span>
          </div>

          <div className="topbar__context" role="group" aria-label="Host and coverage">
            <div className="context-item">
              <Icon name="host" />
              <span>
                <span className="context-item__label">Host</span>
                <strong>{mode === 'native' ? 'Local host' : 'Demo host'}</strong>
              </span>
            </div>
            <div className="context-item">
              <span className="coverage-indicator" aria-hidden="true" />
              <span>
                <span className="context-item__label">Radar coverage</span>
                <strong>{mode === 'native' ? 'Local-engine coverage' : 'Demo coverage'}</strong>
              </span>
            </div>
          </div>

          <div className="topbar__actions">
            <button ref={commandButtonRef} className="command-button" type="button" aria-label="Command menu" onClick={onOpenCommand}>
              <Icon name="command" />
              <span className="command-button__label">Command</span>
              <kbd>Ctrl/⌘ K</kbd>
            </button>
            <button
              className="scan-button"
              type="button"
              aria-label={scanStatus === 'running' ? `Refreshing ${mode === 'native' ? 'local engine' : 'demo view'}` : 'Scan now'}
              aria-busy={scanStatus === 'running' ? true : undefined}
              disabled={scanStatus === 'running'}
              onClick={() => void refreshCoverage()}
            >
              <Icon name="scan" />
              <span>{scanStatus === 'running' ? 'Refreshing…' : 'Scan now'}</span>
            </button>
          </div>
          <p className="scan-status visually-hidden" role="status" aria-live="polite">
            {scanStatusMessage}
          </p>
        </header>

        <main
          ref={mainRef}
          id="main-content"
          className="main-content"
          aria-label={`${activeRouteName} workspace`}
          aria-hidden={modalNavigationOpen || undefined}
          inert={modalNavigationOpen || undefined}
          tabIndex={-1}
        >
          {scanError && <div className="error-banner global-scan-error" role="alert"><strong>Global Scan failed</strong><p>{scanError}</p></div>}
          {children}
        </main>
      </div>
    </>
  )
}
