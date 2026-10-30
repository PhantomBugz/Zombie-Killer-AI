import { useLayoutEffect, useRef, useState } from 'react'

import { LocalWorkflowReview } from '../../components/LocalWorkflowReview'
import type { DetectionPreset, EngineTransport, LocalWorkflowPlan, MotionPreference, ThemePreference } from '../../transport'
import { copyText } from '../activity/export'
import { type SettingsController, useSettingsController } from './useSettingsController'

const thresholds: Record<DetectionPreset, string> = {
  Conservative: '4 corroborating signals; verified identity required; never auto-kill.',
  Balanced: '3 corroborating signals; verified or corroborated identity; never auto-kill.',
  Aggressive: '3 corroborating signals with shorter stale windows; never auto-kill.',
}

const donations = [
  ['Ethereum (ETH, Ethereum)', '0x34566329186f1ec2498017879fB362d8071B28e5'],
  ['Bitcoin (BTC, Bitcoin)', 'bc1q24vhcxytz7fwaqllrwjf6vjmkx795c92t7q4q6'],
  ['Solana (SOL, Solana)', 'GoGJqR6AP9ERZkx2UksDH9rFV8ysYoKVXJRGExvs6j7S'],
] as const

interface SettingsPageProps {
  controller?: SettingsController
  transport: EngineTransport
}

export function SettingsPage({ controller, transport }: SettingsPageProps) {
  if (controller) return <SettingsPageView controller={controller} transport={transport} />
  return <StandaloneSettingsPage transport={transport} />
}

function StandaloneSettingsPage({ transport }: { transport: EngineTransport }) {
  const controller = useSettingsController(transport)
  return <SettingsPageView controller={controller} transport={transport} />
}

function SettingsPageView({ controller, transport }: { controller: SettingsController; transport: EngineTransport }) {
  const native = transport.mode === 'native'
  const nativeCleanupDescription = transport.capabilities.processActions
    ? 'Cleanup paths are not accepted from the WebView. Process actions are reviewed and sent to the local engine without renderer-selected paths.'
    : transport.capabilities.processActionsUnavailableReason ?? 'This transport does not expose process actions.'
  const [copyStatus, setCopyStatus] = useState('')
  const [destination, setDestination] = useState('')
  const [exportPlan, setExportPlan] = useState<LocalWorkflowPlan>()
  const [exportBusy, setExportBusy] = useState(false)
  const [exportError, setExportError] = useState('')
  const exportOpener = useRef<HTMLElement | null>(null)
  const exportPending = useRef(false)
  const retryRef = useRef<HTMLButtonElement>(null)
  const headingRef = useRef<HTMLHeadingElement>(null)
  const focusHeadingAfterRetry = useRef(false)
  const { discardPending, error, loading, retryPending, reload, reset, saveStatus, settings, update } = controller

  async function reviewExport() {
    if (exportPending.current || !destination.trim() || !transport.planDiagnosticsExport) return
    exportPending.current = true; setExportBusy(true); setExportError('')
    try { setExportPlan(await transport.planDiagnosticsExport(destination)) }
    catch (reason) { setExportError(reason instanceof Error ? reason.message : 'The local export could not be reviewed.') }
    finally { exportPending.current = false; setExportBusy(false) }
  }

  useLayoutEffect(() => {
    if (error && (!settings || retryPending || discardPending)) retryRef.current?.focus()
  }, [discardPending, error, retryPending, settings])

  useLayoutEffect(() => {
    if (settings && focusHeadingAfterRetry.current) {
      focusHeadingAfterRetry.current = false
      headingRef.current?.focus()
    }
  }, [settings])

  if (!settings) return <div className="workspace-page settings-page"><h1>Settings</h1>{error ? <div className="error-banner" role="alert"><p>{error}</p><button ref={retryRef} className="secondary-button" type="button" onClick={() => { focusHeadingAfterRetry.current = true; void reload().catch(() => undefined) }}>Retry settings</button></div> : <p role="status">{loading ? 'Loading local settings…' : 'Settings are unavailable.'}</p>}</div>
  return <div className="workspace-page settings-page">
    <header className="workspace-header"><div><p className="eyebrow">Local preferences</p><h1 ref={headingRef} data-route-heading="true" tabIndex={-1}>Settings</h1><p>{native ? 'Revisioned preferences are stored by the local engine.' : 'Revisioned demo preferences live only in memory for this session.'}</p></div><span className="demo-pill">{native ? 'LOCAL ENGINE' : 'LOCAL DEMO'}</span></header>
    {native && <p className="local-warning"><strong>Native capability.</strong> Detection presets and dense mode are not exposed by the engine. Other operations are enabled only after the local engine reports their finite methods.</p>}
    <p className="settings-save-status" role="status">{saveStatus === 'saving' ? 'Saving local settings…' : saveStatus === 'saved' ? 'All local settings saved.' : ''}</p>
    {error && <div className="error-banner" role="alert"><p>{error}</p>{retryPending && <button ref={retryRef} className="secondary-button" type="button" onClick={() => { focusHeadingAfterRetry.current = true; void reload().catch(() => undefined) }}>Reload settings and retry pending changes</button>}{discardPending && <button ref={retryRef} className="secondary-button" type="button" onClick={() => { focusHeadingAfterRetry.current = true; void reload().catch(() => undefined) }}>Reload durable settings and discard pending changes</button>}</div>}
    <nav className="settings-index" aria-label="Settings sections">{['General', 'Detection', 'Cleanup', 'Memory sources', 'SDK & integrations', 'Privacy & network', 'Appearance', 'Accessibility', 'Audit & retention', 'About'].map((name) => <a key={name} href={`#settings-${name.toLowerCase().replaceAll(/[^a-z]+/g, '-')}`}>{name}</a>)}</nav>
    <div className="settings-sections">
      <section id="settings-general"><h2>General</h2><label><span>{native ? 'Stored engine scan interval' : 'Auto-refresh'}</span><select disabled={!transport.capabilities.settingsUpdate} value={settings.autoRefreshSeconds} onChange={(event) => void update({ autoRefreshSeconds: Number(event.target.value) })}>{!native && <option value="0">Paused</option>}{Array.from(new Set([settings.autoRefreshSeconds, 15, 30, 60])).filter((seconds) => !native || seconds >= 5).sort((a, b) => a - b).map((seconds) => <option key={seconds} value={seconds}>{seconds} seconds</option>)}</select></label><p>{native ? 'This persists the local engine scan interval and controls automatic Swarm refresh.' : 'Pausing affects demo refresh only and makes no host changes.'}</p></section>
      <section id="settings-detection"><h2>Detection</h2>{settings.detectionPreset === null ? <p>Detection presets are not exposed by the local engine in this build.</p> : <><label><span>Detection preset</span><select disabled={!transport.capabilities.settingsUpdate} aria-label="Detection preset" value={settings.detectionPreset} onChange={(event) => void update({ detectionPreset: event.target.value as DetectionPreset })}><option>Conservative</option><option>Balanced</option><option>Aggressive</option></select></label><p><strong>Evidence threshold:</strong> {thresholds[settings.detectionPreset]}</p></>}{native && settings.includeUnmanagedCandidates !== undefined && <label className="check-field"><input type="checkbox" disabled={!transport.capabilities.settingsUpdate} checked={settings.includeUnmanagedCandidates} onChange={(event) => void update({ includeUnmanagedCandidates: event.target.checked })} /> Include unmanaged detections</label>}{native && settings.heartbeatGraceSeconds !== undefined && <label><span>Heartbeat grace (seconds)</span><select disabled={!transport.capabilities.settingsUpdate} value={settings.heartbeatGraceSeconds} onChange={(event) => void update({ heartbeatGraceSeconds: Number(event.target.value) })}>{Array.from(new Set([settings.heartbeatGraceSeconds, 30, 60, 120, 300])).sort((a, b) => a - b).map((seconds) => <option key={seconds} value={seconds}>{seconds}</option>)}</select></label>}</section>
      <section id="settings-cleanup"><h2>Cleanup</h2><p>{native ? nativeCleanupDescription : <>Allowed demo roots (display only): <code>[demo-root]\captures</code> and <code>[demo-root]\state</code>.</>}</p><p>Exclusions: source databases, provider configuration, credentials, and unverified paths. No automatic killing.</p></section>
      <section id="settings-memory-sources"><h2>Memory sources</h2><p>{native ? 'Use Memory Vault to register an explicit local file. Each adapter reports its supported scalar repairs, verified snapshots, and restore capabilities; unsupported sources stay read-only.' : 'MTGA JSON memory supports verified local snapshots. Mev BOT SQLite memory remains read-only while its demo backup is missing.'}</p></section>
      <section id="settings-sdk-integrations"><h2>SDK &amp; integrations</h2><p>No provider keys, credential inputs, plugins, or remote integrations are available in v0.1.</p></section>
      <section id="settings-privacy-network"><h2>Privacy &amp; network</h2><ul><li>Local-first and no telemetry.</li><li>No provider credentials.</li><li>No automatic killing.</li><li>No environment or prompt collection.</li><li>{native ? 'The desktop invokes a fixed local engine process over bounded standard I/O; it opens no network listener.' : 'Browser demo data is synthetic and performs no host actions.'}</li></ul></section>
      <section id="settings-appearance"><h2>Appearance</h2><label><span>Theme</span><select disabled={!transport.capabilities.settingsUpdate} aria-label="Theme" value={settings.theme} onChange={(event) => void update({ theme: event.target.value as ThemePreference })}><option value="system">System</option><option value="light">Light</option><option value="dark">Dark</option></select></label>{settings.denseMode === null ? <p>Dense mode is unavailable from the local engine.</p> : <label className="check-field"><input type="checkbox" disabled={!transport.capabilities.settingsUpdate} checked={settings.denseMode} onChange={(event) => void update({ denseMode: event.target.checked })} /> Dense mode</label>}</section>
      <section id="settings-accessibility"><h2>Accessibility</h2><label><span>Motion</span><select disabled={!transport.capabilities.settingsUpdate} value={settings.motion} onChange={(event) => void update({ motion: event.target.value as MotionPreference })}>{!native && <option value="system">Follow operating system</option>}<option value="reduce">Reduce motion</option><option value="full">Allow interface motion</option></select></label><p>{native ? 'The local engine stores an explicit reduced-motion preference.' : 'The accessible default follows the operating system.'} Critical controls remain at least 44 CSS pixels.</p></section>
      <section id="settings-audit-retention"><h2>Audit &amp; retention</h2><label><span>Quarantine retention metadata</span><select disabled={!transport.capabilities.settingsUpdate} value={settings.quarantineRetentionDays} onChange={(event) => void update({ quarantineRetentionDays: Number(event.target.value) })}>{Array.from(new Set([settings.quarantineRetentionDays, 7, 14, 30, 90])).sort((a, b) => a - b).map((days) => <option key={days} value={days}>{days} days</option>)}</select></label><p>{native ? 'This retention setting applies to newly quarantined resources. Purge remains unavailable; existing entries keep their recorded deadline.' : 'This controls demo metadata only. Purge is not available.'}</p></section>
      <section id="settings-about"><h2>About</h2><dl><div><dt>Attribution</dt><dd>Made by PhantomBugz</dd></div><div><dt>Version</dt><dd>0.1.0-alpha.1</dd></div><div><dt>Code license</dt><dd>Apache-2.0</dd></div><div><dt>Artwork license</dt><dd>Zombie Killer mark by PhantomBugz · CC BY 4.0</dd></div></dl><h3>Optional donations</h3><p>Optional donations support future PhantomBugz open-source projects. They unlock nothing and provide no governance, support, warranty, or tax claim.</p><p>Public blockchain transactions are irreversible. Verify the address from an official source. Never share a seed phrase or private key. QR codes are intentionally absent until independently verified later.</p><ul className="donation-list">{donations.map(([label, address]) => <li key={label}><strong>{label}</strong><code>{address}</code><button className="secondary-button" type="button" onClick={() => void copyText(address).then((copied) => setCopyStatus(copied ? `${label} address copied` : 'Clipboard unavailable'))}>Copy {label} address</button></li>)}</ul><p role="status">{copyStatus}</p></section>
    </div>
    {native && transport.capabilities.diagnosticsExport && transport.planDiagnosticsExport && <section className="local-export-section"><h2>Local diagnostics export</h2><p>Export reviewed local diagnostics and receipts to the exact destination you enter. Secrets, raw memory contents, and command lines are excluded by default. The engine refuses to overwrite an existing destination.</p><form className="local-path-form" onSubmit={(event) => { event.preventDefault(); void reviewExport() }}><label>Diagnostics destination<input aria-label="Diagnostics destination" value={destination} maxLength={4096} disabled={exportBusy} onChange={(event) => setDestination(event.target.value)} placeholder="Enter the exact local export file path" /></label><button ref={(element) => { if (element) exportOpener.current = element }} className="secondary-button" type="submit" disabled={exportBusy || !destination.trim()}>{exportBusy ? 'Reviewing…' : 'Review diagnostics export'}</button></form>{exportError && <p className="field-error" role="alert">{exportError}</p>}</section>}
    {exportPlan && transport.executeDiagnosticsExport && <LocalWorkflowReview title="Review local diagnostics export" subject={destination} confirmLabel="Export local diagnostics" plan={exportPlan} execute={(request) => transport.executeDiagnosticsExport!(request)} onClose={() => setExportPlan(undefined)} restoreFocusRef={exportOpener} />}
    <button className="secondary-button reset-settings" type="button" disabled={!transport.capabilities.settingsUpdate} onClick={() => void reset()}>Reset defaults</button>
  </div>
}
