import axe from 'axe-core'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import App from '../App'
import { AppShell } from '../components/AppShell'
import { BrandMark } from '../components/BrandMark'
import { DemoTransport } from '../transport'
import type { ScanRequest, ScanResult } from '../transport'

const stylesDirectory = path.join(process.cwd(), 'src', 'styles')
const globalStyles = readFileSync(path.join(stylesDirectory, 'global.css'), 'utf8')
const navigationStyles = readFileSync(path.join(stylesDirectory, 'navigation.css'), 'utf8')
const responsiveStyles = readFileSync(path.join(stylesDirectory, 'responsive.css'), 'utf8')
const shellStyles = readFileSync(path.join(stylesDirectory, 'shell.css'), 'utf8')
const tokens = readFileSync(path.join(stylesDirectory, 'tokens.css'), 'utf8')
const authoredStyles = `${tokens}\n${globalStyles}\n${navigationStyles}\n${shellStyles}\n${responsiveStyles}`
const packageRoot = path.join(stylesDirectory, '..', '..')

const originalMatchMedia = window.matchMedia

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason?: unknown) => void
  const promise = new Promise<T>((resolvePromise, rejectPromise) => { resolve = resolvePromise; reject = rejectPromise })
  return { promise, reject, resolve }
}

function installMobileViewport(initiallyMobile = true) {
  const listeners = new Set<(event: MediaQueryListEvent) => void>()
  const mediaQueryList = {
    matches: initiallyMobile,
    media: '(max-width: 899px)',
    onchange: null,
    addEventListener: (_type: string, listener: (event: MediaQueryListEvent) => void) => {
      listeners.add(listener)
    },
    removeEventListener: (_type: string, listener: (event: MediaQueryListEvent) => void) => {
      listeners.delete(listener)
    },
    addListener: () => undefined,
    removeListener: () => undefined,
    dispatchEvent: () => true,
  } as MediaQueryList

  Object.defineProperty(window, 'matchMedia', {
    configurable: true,
    value: vi.fn(() => mediaQueryList),
  })

  return {
    setMobile(matches: boolean) {
      Object.defineProperty(mediaQueryList, 'matches', { configurable: true, value: matches })
      const event = { matches, media: mediaQueryList.media } as MediaQueryListEvent
      listeners.forEach((listener) => listener(event))
    },
  }
}

afterEach(() => {
  Object.defineProperty(window, 'matchMedia', {
    configurable: true,
    value: originalMatchMedia,
  })
  document.body.removeAttribute('style')
  document.body.classList.remove('modal-scroll-locked')
  vi.restoreAllMocks()
})

function relativeLuminance(hex: string) {
  const channels = hex
    .slice(1)
    .match(/.{2}/g)
    ?.map((channel) => Number.parseInt(channel, 16) / 255)
    .map((channel) =>
      channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4,
    )

  if (!channels || channels.length !== 3) {
    throw new Error(`Invalid hex color: ${hex}`)
  }
  return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2]
}

function contrastRatio(first: string, second: string) {
  const firstLuminance = relativeLuminance(first)
  const secondLuminance = relativeLuminance(second)
  return (Math.max(firstLuminance, secondLuminance) + 0.05) /
    (Math.min(firstLuminance, secondLuminance) + 0.05)
}

describe('Containment Console shell', () => {
  it('renders the primary navigation, host coverage, and attribution', () => {
    render(<App />)

    const navigation = screen.getByRole('navigation', { name: /primary/i })
    expect(navigation).not.toBeNull()
    for (const name of ['Swarm', 'Memory Vault', 'Activity', 'Settings']) {
      expect(screen.getByRole('link', { name })).not.toBeNull()
    }
    expect(screen.getByText('Demo host')).not.toBeNull()
    expect(screen.getByText('Demo coverage')).not.toBeNull()
    expect(screen.getByRole('button', { name: 'Scan now' })).not.toBeNull()
    expect(screen.getByText('Made by PhantomBugz')).not.toBeNull()
  })

  it('groups host and coverage context under its accessible name', () => {
    render(<App />)

    expect(screen.getByRole('group', { name: 'Host and coverage' })).not.toBeNull()
  })

  it.each([
    ['demo', 'Demo host', 'Local host'],
    ['native', 'Local host', 'Demo host'],
  ] as const)('identifies the %s host without implying a different data source', (mode, label, otherLabel) => {
    render(<AppShell activeRoute="swarm" mode={mode} onNavigate={() => undefined}><h1>Swarm</h1></AppShell>)

    const context = screen.getByRole('group', { name: 'Host and coverage' })
    expect(context.textContent).toContain(label)
    expect(context.textContent).not.toContain(otherLabel)
  })

  it('provides a skip link and a named main landmark', () => {
    render(<App />)

    expect(screen.getByRole('link', { name: 'Skip to main content' }).getAttribute('href')).toBe(
      '#main-content',
    )
    expect(screen.getByRole('main', { name: 'Swarm workspace' }).id).toBe('main-content')
  })

  it('keeps navigation in a predictable keyboard order', async () => {
    const user = userEvent.setup()
    render(<App />)

    await user.tab()
    expect(document.activeElement).toBe(
      screen.getByRole('link', { name: 'Skip to main content' }),
    )

    for (const name of ['Swarm', 'Memory Vault', 'Activity', 'Settings']) {
      await user.tab()
      expect(document.activeElement).toBe(screen.getByRole('link', { name }))
    }
  })

  it('marks and updates the active route without a router dependency', async () => {
    const user = userEvent.setup()
    render(<App />)

    expect(screen.getByRole('link', { name: 'Swarm' }).getAttribute('aria-current')).toBe('page')
    await user.click(screen.getByRole('link', { name: 'Memory Vault' }))
    expect(
      screen.getByRole('link', { name: 'Memory Vault' }).getAttribute('aria-current'),
    ).toBe('page')
    expect(screen.getByRole('main', { name: 'Memory Vault workspace' })).not.toBeNull()
  })

  it('exposes a drawer-ready mobile navigation control', async () => {
    const user = userEvent.setup()
    render(<App />)

    const toggle = screen.getByRole('button', { name: 'Open navigation' })
    expect(toggle.getAttribute('aria-expanded')).toBe('false')
    await user.click(toggle)
    expect(toggle.getAttribute('aria-label')).toBe('Close navigation')
    expect(toggle.getAttribute('aria-expanded')).toBe('true')
  })

  it('moves focus into the drawer, traps tab order, and restores focus on Escape', async () => {
    const user = userEvent.setup()
    render(<App />)

    const toggle = screen.getByRole('button', { name: 'Open navigation' })
    await user.click(toggle)
    expect(document.activeElement).toBe(screen.getByRole('link', { name: 'Swarm' }))

    await user.tab({ shift: true })
    expect(document.activeElement).toBe(screen.getByRole('link', { name: 'Settings' }))
    await user.tab()
    expect(document.activeElement).toBe(screen.getByRole('link', { name: 'Swarm' }))

    await user.keyboard('{Escape}')
    expect(toggle.getAttribute('aria-expanded')).toBe('false')
    expect(document.activeElement).toBe(toggle)
    expect(document.activeElement).not.toBe(document.body)
  })

  it('closes route selection into the newly selected main workspace', async () => {
    const user = userEvent.setup()
    render(<App />)
    const main = screen.getByRole('main', { name: 'Swarm workspace' })
    const focusMain = main.focus.bind(main)
    vi.spyOn(main, 'focus').mockImplementation(() => {
      if (!main.hasAttribute('inert')) {
        focusMain()
      }
    })

    await user.click(screen.getByRole('button', { name: 'Open navigation' }))
    await user.click(screen.getByRole('link', { name: 'Memory Vault' }))

    expect(screen.getByRole('button', { name: 'Open navigation' }).getAttribute('aria-expanded')).toBe(
      'false',
    )
    const selectedMain = screen.getByRole('main', { name: 'Memory Vault workspace' })
    expect(document.activeElement).toBe(selectedMain)
    expect(document.activeElement).not.toBe(document.body)
  })

  it('closes an open drawer from its pointer backdrop and restores the toggle', async () => {
    const user = userEvent.setup()
    const { container } = render(<App />)
    const toggle = screen.getByRole('button', { name: 'Open navigation' })
    const focusToggle = toggle.focus.bind(toggle)
    vi.spyOn(toggle, 'focus').mockImplementation(() => {
      if (!toggle.closest('[inert]')) {
        focusToggle()
      }
    })

    await user.click(toggle)
    const backdrop = container.querySelector<HTMLElement>('[data-navigation-backdrop]')
    expect(backdrop).not.toBeNull()
    await user.click(backdrop as HTMLElement)

    expect(toggle.getAttribute('aria-expanded')).toBe('false')
    expect(document.activeElement).toBe(toggle)
  })

  it('isolates the page and preserves scroll while the mobile drawer is modal', async () => {
    installMobileViewport()
    const user = userEvent.setup()
    Object.defineProperty(window, 'scrollY', { configurable: true, value: 184 })
    document.body.style.paddingRight = '3px'
    const { container, unmount } = render(<App />)

    await user.click(screen.getByRole('button', { name: 'Open navigation' }))

    expect(screen.getByRole('dialog', { name: 'Application navigation' })).not.toBeNull()
    expect(container.querySelector('.skip-link')?.hasAttribute('inert')).toBe(true)
    expect(container.querySelector('.skip-link')?.getAttribute('aria-hidden')).toBe('true')
    expect(container.querySelector('.topbar')?.hasAttribute('inert')).toBe(true)
    expect(container.querySelector('.topbar')?.getAttribute('aria-hidden')).toBe('true')
    const hiddenMain = screen.getByRole('main', { hidden: true })
    expect(hiddenMain.hasAttribute('inert')).toBe(true)
    expect(hiddenMain.getAttribute('aria-hidden')).toBe('true')
    expect(document.body.classList.contains('modal-scroll-locked')).toBe(true)
    expect(document.body.style.position).toBe('')
    expect(document.body.style.overflow).toBe('')
    expect(responsiveStyles).toMatch(
      /\.drawer-backdrop\s*\{[^}]*overscroll-behavior:\s*contain[^}]*touch-action:\s*none/is,
    )

    unmount()
    expect(document.body.classList.contains('modal-scroll-locked')).toBe(false)
    expect(document.body.style.paddingRight).toBe('3px')
  })

  it('resets drawer modal state when the viewport crosses to desktop', async () => {
    const viewport = installMobileViewport()
    const user = userEvent.setup()
    const { container } = render(<App />)

    await user.click(screen.getByRole('button', { name: 'Open navigation' }))
    expect(container.querySelector('.sidebar')?.getAttribute('aria-modal')).toBe('true')

    act(() => viewport.setMobile(false))

    expect(screen.getByRole('button', { name: 'Open navigation' }).getAttribute('aria-expanded')).toBe(
      'false',
    )
    expect(container.querySelector('.sidebar')?.hasAttribute('aria-modal')).toBe(false)
    expect(container.querySelector('.sidebar')?.getAttribute('role')).not.toBe('dialog')
    expect(container.querySelector('.topbar')?.hasAttribute('inert')).toBe(false)
    expect(document.body.classList.contains('modal-scroll-locked')).toBe(false)
  })

  it('runs an honest demo refresh with busy and polite status feedback', async () => {
    const user = userEvent.setup()
    render(<App />)
    const scan = screen.getByRole('button', { name: 'Scan now' }) as HTMLButtonElement
    const liveStatus = screen.getByRole('status')

    expect(liveStatus.textContent).toBe('Demo preview only. No host scan will run.')
    expect(liveStatus.classList.contains('visually-hidden')).toBe(true)

    await user.click(scan)

    const refreshing = screen.getByRole('button', { name: 'Refreshing demo view' })
    expect(refreshing.textContent).toContain('Refreshing…')
    expect((refreshing as HTMLButtonElement).disabled).toBe(true)
    expect(refreshing.getAttribute('aria-busy')).toBe('true')
    expect(liveStatus.textContent).toBe('Refreshing the demo view…')
    expect(await screen.findByText('Demo coverage refreshed. No host scan was run.')).not.toBeNull()
    const ready = screen.getByRole('button', { name: 'Scan now' }) as HTMLButtonElement
    expect(ready.textContent).toContain('Scan now')
    expect(ready.disabled).toBe(false)
    expect(ready.hasAttribute('aria-busy')).toBe(false)
  })

  it('loads persisted settings before scanning and applies theme, motion, unmanaged inclusion, and refresh cadence centrally', async () => {
    class PersistedSettingsTransport extends DemoTransport {
      scanRequests: ScanRequest[] = []
      override async getSettings() {
        return { ...(await super.getSettings()), theme: 'dark' as const, motion: 'reduce' as const, autoRefreshSeconds: 15, includeUnmanagedCandidates: false }
      }
      override async scan(request: ScanRequest = {}) {
        this.scanRequests.push(request)
        return super.scan(request)
      }
    }
    const intervalSpy = vi.spyOn(window, 'setInterval')
    const transport = new PersistedSettingsTransport({ latencyMs: 0 })
    render(<App transport={transport} />)

    await screen.findByText('ScreenShot Coordinator')
    expect(document.documentElement.dataset.theme).toBe('dark')
    expect(document.documentElement.dataset.motion).toBe('reduce')
    expect(transport.scanRequests[0]).toEqual({ includeUnmanagedCandidates: false })
    expect(screen.queryByText('Unattributed Python process')).toBeNull()
    expect(intervalSpy).toHaveBeenCalledWith(expect.any(Function), 15_000)
    intervalSpy.mockRestore()
  })

  it('keeps real App startup retry focus durable and moves it to the active route only after retry succeeds', async () => {
    const retryGate = deferred<void>()
    class InitiallyUnavailableSettingsTransport extends DemoTransport {
      settingsCalls = 0

      override async getSettings() {
        this.settingsCalls += 1
        if (this.settingsCalls === 1) throw new Error('Startup settings are temporarily unavailable.')
        if (this.settingsCalls === 2) await retryGate.promise
        return super.getSettings()
      }
    }
    const transport = new InitiallyUnavailableSettingsTransport({ latencyMs: 0 })
    const user = userEvent.setup()
    render(<App transport={transport} />)

    const retry = await screen.findByRole('button', { name: 'Retry settings' })
    await waitFor(() => expect(document.activeElement).toBe(retry))
    await user.click(retry)
    await waitFor(() => expect(transport.settingsCalls).toBe(2))
    expect(document.activeElement).toBe(retry)
    expect(screen.getByRole('main', { name: 'Swarm workspace' }).contains(document.activeElement)).toBe(true)
    expect(document.activeElement).not.toBe(document.body)

    await act(async () => retryGate.resolve())
    await screen.findByText('ScreenShot Coordinator')
    const heading = screen.getByRole('heading', { name: 'Swarm', level: 1 })
    expect(heading.getAttribute('data-route-heading')).toBe('true')
    expect(document.activeElement).toBe(heading)
  })

  it('does not move focus on an ordinary successful startup settings load', async () => {
    render(<App transport={new DemoTransport({ latencyMs: 0 })} />)

    await screen.findByText('ScreenShot Coordinator')
    expect(document.activeElement).toBe(document.body)
    expect(document.activeElement).not.toBe(screen.getByRole('heading', { name: 'Swarm', level: 1 }))
  })

  it('runs Global Scan from another route, stays pending until real completion, and announces errors before success', async () => {
    const secondScan = deferred<ScanResult>()
    class GlobalScanTransport extends DemoTransport {
      scanCount = 0
      override async scan(request: ScanRequest = {}) {
        this.scanCount += 1
        if (this.scanCount === 2) return secondScan.promise
        return super.scan(request)
      }
    }
    const transport = new GlobalScanTransport({ latencyMs: 0 })
    const user = userEvent.setup()
    render(<App transport={transport} />)
    await screen.findByText('ScreenShot Coordinator')
    await user.click(screen.getByRole('link', { name: 'Activity' }))
    const scan = screen.getByRole('button', { name: 'Scan now' }) as HTMLButtonElement
    expect(scan.disabled).toBe(false)

    await user.click(scan)
    expect(screen.getByRole('button', { name: 'Refreshing demo view' })).not.toBeNull()
    expect(screen.getByRole('status').textContent).toBe('Refreshing the demo view…')
    secondScan.reject(new Error('Global scan failed at the local engine.'))
    expect((await screen.findByRole('alert')).textContent).toMatch(/Global scan failed/i)
    expect(screen.queryByText('Demo coverage refreshed. No host scan was run.')).toBeNull()

    await user.click(screen.getByRole('button', { name: 'Scan now' }))
    expect(await screen.findByText('Demo coverage refreshed. No host scan was run.')).not.toBeNull()
    await waitFor(() => expect(transport.scanCount).toBe(3))
  })

  it('keeps the command affordance discoverable and enabled', () => {
    render(<App />)

    expect((screen.getByRole('button', { name: 'Command menu' }) as HTMLButtonElement).disabled).toBe(false)
    expect(screen.getByText('Ctrl/⌘ K')).not.toBeNull()
  })

  it('uses a fresh scan when returning to Swarm after an earlier Global Scan', async () => {
    class ReturningScanTransport extends DemoTransport {
      scanCount = 0
      override async getSettings() {
        return { ...(await super.getSettings()), autoRefreshSeconds: 0 }
      }
      override async scan(request: ScanRequest = {}) {
        const result = await super.scan(request)
        this.scanCount += 1
        const role = this.scanCount === 1 ? 'Initial scan worker'
          : this.scanCount === 2 ? 'Global scan worker' : 'Current scan worker'
        return { ...result, agents: result.agents.map((agent, index) => index === 0 ? { ...agent, role, revision: this.scanCount } : agent) }
      }
    }
    const user = userEvent.setup()
    render(<App transport={new ReturningScanTransport({ latencyMs: 0 })} />)
    await screen.findByText('Initial scan worker')

    await user.click(screen.getByRole('button', { name: 'Scan now' }))
    await screen.findByText('Demo coverage refreshed. No host scan was run.')
    await user.click(screen.getByRole('link', { name: 'Activity' }))
    await user.click(screen.getByRole('link', { name: 'Swarm' }))

    expect(await screen.findByText('Current scan worker')).not.toBeNull()
    expect(screen.queryByText('Global scan worker')).toBeNull()
  })

  it('has no automated accessibility violations', async () => {
    installMobileViewport()
    const user = userEvent.setup()
    const { container } = render(<App />)
    const axeOptions = {
      rules: {
        // JSDOM has no canvas implementation; token contrast is verified below.
        'color-contrast': { enabled: false },
      },
    }

    const closedResults = await axe.run(container, axeOptions)
    await user.click(screen.getByRole('button', { name: 'Open navigation' }))
    const openResults = await axe.run(container, axeOptions)

    expect(closedResults.violations).toEqual([])
    expect(openResults.violations).toEqual([])
  })
})

describe('visual foundation contracts', () => {
  it('uses a stroked chip, disconnected traces, and a negative-space pulse', () => {
    const { container } = render(<BrandMark />)

    expect(screen.getByText('Zombie Killer')).not.toBeNull()
    const svg = container.querySelector('svg')
    expect(svg?.getAttribute('aria-hidden')).toBe('true')
    expect(svg?.hasAttribute('role')).toBe(false)

    const outline = svg?.querySelector('[data-mark-part="chip-outline"]')
    expect(outline?.getAttribute('fill')).toBe('none')
    expect(outline?.getAttribute('stroke')).toBe('currentColor')
    expect(outline?.getAttribute('x')).toBe('10')
    expect(outline?.getAttribute('y')).toBe('9')
    expect(svg?.querySelector('[data-mark-part="chip-body"]')).toBeNull()

    const traces = svg?.querySelector('[data-mark-part="exterior-traces"]')
    expect(traces?.getAttribute('fill')).toBe('none')
    expect(traces?.getAttribute('d')).toContain('M17 3v4')
    expect(traces?.getAttribute('d')).toContain('M4 17h4')

    const pulse = svg?.querySelector('[data-mark-part="negative-space-pulse"]')
    expect(pulse?.getAttribute('stroke')).toBe('black')
    expect(svg?.querySelector('[data-mark-part="signal-field"]')?.getAttribute('mask')).toMatch(
      /^url\(#.+\)$/,
    )
  })

  it('keeps the exact creator attribution accessible in full and compact layouts', () => {
    const { container } = render(<App />)
    const exactAttribution = 'Made by PhantomBugz'
    const attribution = screen.getByLabelText(exactAttribution)

    expect(attribution.tagName).toBe('DIV')
    expect(attribution.getAttribute('role')).toBe('group')
    expect(attribution.getAttribute('aria-label')).toBe(exactAttribution)
    expect(attribution.querySelector('.attribution__full-copy')?.textContent).toBe(exactAttribution)
    expect(attribution.querySelector('.attribution__compact')?.textContent?.trim()).toBe('PB')
    expect(container.innerHTML).not.toMatch(/Created by|SC · PB/i)
    expect(attribution.querySelector('.attribution__compact')?.getAttribute('aria-hidden')).toBe(
      'true',
    )
    expect(responsiveStyles).not.toMatch(/\.attribution__label\s*\{[^}]*display:\s*inline/is)
  })

  it('defines dark, light, and system-aware theme tokens', () => {
    expect(tokens).toContain('--color-canvas: #0a0e0d')
    expect(tokens).toMatch(/\[data-theme=['"]light['"]\]/)
    expect(tokens).toContain('prefers-color-scheme: light')
    expect(tokens).toContain('font-variant-numeric: tabular-nums')
  })

  it('keeps representative dark and light text pairs at WCAG AA contrast', () => {
    const pairs = [
      ['#eaf2ee', '#0a0e0d'],
      ['#a0b3aa', '#111715'],
      ['#58d9b0', '#111715'],
      ['#07110e', '#58d9b0'],
      ['#17211d', '#f1f0e9'],
      ['#52635b', '#faf9f4'],
      ['#087659', '#faf9f4'],
      ['#ffffff', '#087659'],
      ['#aa3933', '#faf9f4'],
    ] as const

    for (const [foreground, background] of pairs) {
      expect(tokens).toContain(foreground)
      expect(tokens).toContain(background)
      expect(contrastRatio(foreground, background)).toBeGreaterThanOrEqual(4.5)
    }
  })

  it('includes reflow, reduced-motion, and forced-color accommodations', () => {
    expect(responsiveStyles).toContain('@media (max-width: 320px)')
    expect(globalStyles).toContain('prefers-reduced-motion: reduce')
    expect(responsiveStyles).toContain('forced-colors: active')
    expect(authoredStyles).not.toMatch(/scanline|linear-gradient|radial-gradient|backdrop-filter/i)
  })

  it('keeps scan progress out of the topbar layout', () => {
    expect(shellStyles).toMatch(/\.scan-button\s*\{[^}]*white-space:\s*nowrap/is)
    expect(shellStyles).toMatch(/\.scan-button\[aria-busy=['"]true['"]\][^{]*\.icon/is)
    expect(shellStyles).not.toMatch(/\.scan-status\s*\{[^}]*(?:flex-basis|order):/is)
  })

  it('shows the navigation toggle only below the desktop breakpoint', () => {
    expect(responsiveStyles).toMatch(
      /@media \(max-width: 899px\)[\s\S]*?\.navigation-toggle\s*\{[^}]*display:\s*inline-flex/is,
    )
    expect(responsiveStyles).toMatch(
      /@media \(min-width: 900px\)[\s\S]*?\.navigation-toggle\s*\{[^}]*display:\s*none/is,
    )
  })

  it('contains no external asset URL in authored HTML or styles', async () => {
    const indexHtml = (await import('../../index.html?raw')).default
    const indexWithoutCsp = indexHtml.replace(/<meta[^>]+http-equiv="Content-Security-Policy"[^>]*>/i, '')
    const authoredAssets = `${indexWithoutCsp}\n${authoredStyles}`

    expect(authoredAssets).not.toMatch(/(?:https?:)?\/\//i)
  })

  it('ships a restrictive local-preview content security policy', async () => {
    const indexHtml = (await import('../../index.html?raw')).default

    expect(indexHtml).toContain('http-equiv="Content-Security-Policy"')
    expect(indexHtml).toContain("default-src 'self'")
    expect(indexHtml).toContain("script-src 'self'")
    expect(indexHtml).toContain("style-src 'self';")
    expect(indexHtml).toContain("object-src 'none'")
    expect(indexHtml).toContain("connect-src 'self' ipc: http://ipc.localhost ws://127.0.0.1:* ws://localhost:*")
    expect(indexHtml).not.toContain("script-src 'unsafe-inline'")
    expect(indexHtml).not.toContain("style-src 'self' 'unsafe-inline'")
  })

  it('uses class-based runtime presentation so style-src unsafe-inline is unnecessary', () => {
    const modalSource = readFileSync(path.join(packageRoot, 'src', 'components', 'modalOwnership.ts'), 'utf8')
    const containmentSource = readFileSync(path.join(packageRoot, 'src', 'features', 'swarm', 'ContainmentDialog.tsx'), 'utf8')

    expect(`${modalSource}\n${containmentSource}`).not.toMatch(/\.style\.|setAttribute\(['"]style/)
    expect(globalStyles).toMatch(/body\.modal-scroll-locked\s*\{[^}]*overflow:\s*hidden/is)
    expect(globalStyles).toMatch(/\.clipboard-fallback\s*\{[^}]*position:\s*fixed/is)
  })

  it('does not force the document wider than a scrollbar-adjusted 320px viewport', () => {
    expect(globalStyles).not.toMatch(/(?:html|body)\s*\{[^}]*min-width:\s*320px/is)
  })

  it('checks public vectors and built JavaScript as well as HTML and CSS', () => {
    const checker = readFileSync(
      path.join(packageRoot, 'scripts', 'check-no-remote-assets.mjs'),
      'utf8',
    )

    expect(checker).toContain("path.join(packageRoot, 'public')")
    expect(checker).toMatch(/builtFiles[\s\S]*\.js/)
    expect(checker).toMatch(/authoredFiles[\s\S]*\.svg/)
    expect(checker).toContain('allowedNonAssetLiterals')
    expect(checker).toContain('replaceAll(`${quote}${url}${quote}`')
    expect(checker).not.toContain('content.replace(allowedPattern')
  })

  it('separates production browser types from test and Node environments', () => {
    const productionConfig = JSON.parse(
      readFileSync(path.join(packageRoot, 'tsconfig.json'), 'utf8'),
    ) as {
      compilerOptions: { types: string[] }
      exclude?: string[]
    }
    const testConfigPath = path.join(packageRoot, 'tsconfig.test.json')
    const eslintConfig = readFileSync(path.join(packageRoot, 'eslint.config.js'), 'utf8')
    const packageJson = readFileSync(path.join(packageRoot, 'package.json'), 'utf8')

    expect(productionConfig.compilerOptions.types).toEqual(['vite/client'])
    expect(productionConfig.exclude).toContain('src/test')
    expect(() => readFileSync(testConfigPath, 'utf8')).not.toThrow()
    expect(readFileSync(testConfigPath, 'utf8')).toContain('vitest/globals')
    expect(packageJson).toContain('tsc --noEmit -p tsconfig.test.json')
    expect(eslintConfig).toContain("files: ['src/**/*.{ts,tsx}']")
    expect(eslintConfig).toContain("ignores: ['src/test/**']")
    expect(eslintConfig).toContain("files: ['src/test/**/*.{ts,tsx}']")
    expect(eslintConfig).toContain("files: ['public/**/*.js']")
    expect(eslintConfig).toContain("files: ['eslint.config.js', 'scripts/**/*.{js,mjs}']")
    expect(eslintConfig).not.toContain("files: ['**/*.{js,mjs}']")
    expect(eslintConfig).not.toContain('globals.browser, globals.node, globals.vitest')
  })

  it('declares a bundled project icon instead of triggering a favicon request', async () => {
    const indexHtml = (await import('../../index.html?raw')).default

    expect(indexHtml).toContain(
      '<link rel="icon" type="image/svg+xml" href="/zombie-killer-mark.svg" />',
    )
  })
})
