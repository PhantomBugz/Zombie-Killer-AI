import { useCallback, useEffect, useMemo, useRef, useState } from 'react'

import type { ActionKind, AgentDetail, AgentSummary, ContainmentReceipt, EngineTransport, ScanResult } from '../../transport/types'
import { AgentDetails } from './AgentDetails'
import { AgentRow } from './AgentRow'
import { ContainmentDialog } from './ContainmentDialog'
import { groupForState } from './grouping'

interface Props { transport: EngineTransport; externalScan?: ScanResult | null; refreshIntervalMs?: number; includeUnmanagedCandidates?: boolean; registerRefresh?: (refresh: (() => Promise<void>) | null) => void }

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'undefined'
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`
  const record = value as Record<string, unknown>
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(record[key])}`).join(',')}}`
}

function semanticEvidence(signal: AgentSummary['evidence'][number]) {
  const { id: _id, observedAt: _observedAt, ...content } = signal
  return content
}

function semanticAgent(agent: AgentSummary) {
  const { revision: _revision, evidence, ...content } = agent
  return { ...content, evidence: evidence.map(semanticEvidence) }
}

function verifiedAgentSummary(agent: AgentSummary) {
  return {
    id: agent.id,
    role: agent.role,
    project: agent.project,
    provider: agent.provider,
    runtime: agent.runtime,
    pid: agent.pid,
    processInstanceId: agent.processInstanceId,
    host: agent.host,
    processStartedAt: agent.processStartedAt,
    executable: agent.executable,
    state: agent.state,
    confidence: agent.confidence,
    evidenceGrade: agent.evidenceGrade,
    diagnosis: agent.diagnosis,
    actionable: agent.actionable,
    actionReason: agent.actionReason,
    heartbeatAt: agent.heartbeatAt,
    ramMb: agent.ramMb,
    network: agent.network,
    evidence: agent.evidence.map(({ observedAt: _observedAt, ...content }) => content),
  }
}

function scanContentFingerprint(scan: ScanResult) {
  return stableStringify({
    mode: scan.mode,
    coverage: scan.coverage,
    agents: scan.agents.map(semanticAgent),
    metrics: scan.metrics,
    usage: scan.usage,
    resources: scan.resources.map(({ observedAt: _observedAt, ...point }) => point),
    timeline: scan.timeline.map(({ id: _id, ...event }) => event),
    receipts: scan.receipts.map(({ receiptId: _receiptId, planId: _planId, ...receipt }) => receipt),
  })
}

function changedAgentCount(current: ScanResult, next: ScanResult) {
  const currentAgents = new Map(current.agents.map((agent) => [agent.id, stableStringify(semanticAgent(agent))]))
  const nextAgents = new Map(next.agents.map((agent) => [agent.id, stableStringify(semanticAgent(agent))]))
  const ids = new Set([...currentAgents.keys(), ...nextAgents.keys()])
  return [...ids].filter((id) => currentAgents.get(id) !== nextAgents.get(id)).length
}

function updateLabel(current: ScanResult, next: ScanResult) {
  const count = changedAgentCount(current, next)
  return count === 0 ? 'Updates available — apply updates' : `${count} result${count === 1 ? '' : 's'} changed — apply updates`
}

export function SwarmPage({ transport, externalScan = null, refreshIntervalMs = 30_000, includeUnmanagedCandidates = true, registerRefresh }: Props) {
  const [scan, setScan] = useState<ScanResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [inFlight, setInFlight] = useState(0)
  const [paused, setPaused] = useState(false)
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState<AgentSummary | null>(null)
  const [containment, setContainment] = useState<{ agent: AgentDetail; kind: ActionKind } | null>(null)
  const [returnAgent, setReturnAgent] = useState<AgentSummary | null>(null)
  const [pendingScan, setPendingScan] = useState<ScanResult | null>(null)
  const orderedIds = useRef<string[]>([])
  const inspectTriggerRef = useRef<HTMLElement | null>(null)
  const scanRef = useRef<ScanResult | null>(null)
  const requestGeneration = useRef(0)
  const mandatoryGeneration = useRef(0)
  const containmentOpenRef = useRef(false)
  const mandatoryActiveRef = useRef(false)
  const mandatoryPromiseRef = useRef<Promise<void> | null>(null)
  const genericInFlightRef = useRef(0)
  const deferredDependencyScanRef = useRef(false)
  const deferredExternalScanRef = useRef<ScanResult | null>(null)
  const lastExternalScanRef = useRef(externalScan)
  const mountedRef = useRef(true)

  const refresh = useCallback(async () => {
    if (containmentOpenRef.current || mandatoryActiveRef.current) return
    const generation = ++requestGeneration.current
    genericInFlightRef.current += 1
    setInFlight((count) => count + 1); setError(null)
    try {
      const next = await transport.scan({ includeUnmanagedCandidates })
      if (!mountedRef.current || containmentOpenRef.current || mandatoryActiveRef.current || generation !== requestGeneration.current) return
      const current = scanRef.current
      const nextIds = next.agents.map((agent) => agent.id)
      if (current && scanContentFingerprint(next) !== scanContentFingerprint(current)) setPendingScan(next)
      else { orderedIds.current = nextIds; scanRef.current = next; setPendingScan(null); setScan(next) }
    } catch (cause) {
      if (mountedRef.current && generation === requestGeneration.current) setError(cause instanceof Error ? cause.message : 'The local scan could not be refreshed.')
      throw cause
    }
    finally {
      genericInFlightRef.current = Math.max(0, genericInFlightRef.current - 1)
      if (mountedRef.current) setInFlight((count) => Math.max(0, count - 1))
    }
  }, [includeUnmanagedCandidates, transport])

  useEffect(() => {
    mountedRef.current = true
    return () => {
      mountedRef.current = false
      requestGeneration.current += 1
      mandatoryGeneration.current += 1
    }
  }, [])

  useEffect(() => {
    let current = true
    if (containmentOpenRef.current || mandatoryActiveRef.current) {
      deferredDependencyScanRef.current = true
      return () => { current = false }
    }
    deferredDependencyScanRef.current = false
    const generation = ++requestGeneration.current
    genericInFlightRef.current += 1
    void transport.scan({ includeUnmanagedCandidates }).then(
      (value) => { if (current && !containmentOpenRef.current && !mandatoryActiveRef.current && generation === requestGeneration.current) { orderedIds.current = value.agents.map((agent) => agent.id); scanRef.current = value; setScan(value) } },
      (cause: unknown) => { if (current && generation === requestGeneration.current) setError(cause instanceof Error ? cause.message : 'The local scan could not be refreshed.') },
    ).finally(() => { genericInFlightRef.current = Math.max(0, genericInFlightRef.current - 1) })
    return () => { current = false }
  }, [includeUnmanagedCandidates, transport])
  useEffect(() => { registerRefresh?.(refresh); return () => registerRefresh?.(null) }, [refresh, registerRefresh])
  useEffect(() => {
    // A retained global result predates this mount's fresh scan. Only a new
    // global scan may supersede the startup request.
    if (!externalScan || externalScan === lastExternalScanRef.current) return
    lastExternalScanRef.current = externalScan
    if (containmentOpenRef.current || mandatoryActiveRef.current) {
      deferredExternalScanRef.current = externalScan
      return
    }
    requestGeneration.current += 1
    const current = scanRef.current
    if (current && scanContentFingerprint(externalScan) !== scanContentFingerprint(current)) {
      setPendingScan(externalScan)
      return
    }
    orderedIds.current = externalScan.agents.map((agent) => agent.id)
    scanRef.current = externalScan
    setPendingScan(null)
    setScan(externalScan)
    setError(null)
  }, [externalScan])
  useEffect(() => {
    if (paused || refreshIntervalMs <= 0) return
    const timer = window.setInterval(() => { void refresh().catch(() => undefined) }, refreshIntervalMs)
    return () => window.clearInterval(timer)
  }, [paused, refresh, refreshIntervalMs])

  const visibleAgents = useMemo(() => {
    const needle = query.trim().toLocaleLowerCase()
    return (scan?.agents ?? []).filter((agent) => !needle || [agent.role, agent.project, agent.provider, agent.runtime, agent.state, agent.host, String(agent.pid ?? '')].some((value) => String(value ?? '').toLocaleLowerCase().includes(needle)))
  }, [query, scan])
  const groups = [
    { title: 'Needs attention', agents: visibleAgents.filter((agent) => groupForState(agent.state) === 'attention') },
    { title: 'Active and idle', agents: visibleAgents.filter((agent) => groupForState(agent.state) === 'active') },
    { title: 'Completed and cancelled', agents: visibleAgents.filter((agent) => groupForState(agent.state) === 'terminal') },
    { title: 'Unknown state', agents: visibleAgents.filter((agent) => groupForState(agent.state) === 'unknown') },
    { title: 'Unmanaged detections', agents: visibleAgents.filter((agent) => groupForState(agent.state) === 'unmanaged') },
  ]

  function applyDeferredScan(next: ScanResult) {
    const current = scanRef.current
    if (current && scanContentFingerprint(next) !== scanContentFingerprint(current)) setPendingScan(next)
    else {
      orderedIds.current = next.agents.map((agent) => agent.id)
      scanRef.current = next
      setPendingScan(null)
      setScan(next)
    }
    setError(null)
  }

  function closeContainment() {
    if (mandatoryActiveRef.current) return
    containmentOpenRef.current = false
    mandatoryGeneration.current += 1
    const resumeDependencyScan = deferredDependencyScanRef.current
    deferredDependencyScanRef.current = false
    const deferred = deferredExternalScanRef.current
    deferredExternalScanRef.current = null
    setContainment(null)
    if (deferred) applyDeferredScan(deferred)
    if (resumeDependencyScan) void refresh().catch(() => undefined)
  }

  function beginContainment(agent: AgentDetail, kind: ActionKind) {
    // A scan already in progress may otherwise win after the reviewed dialog
    // opens. Invalidate it synchronously and defer its reconciliation until
    // the verified containment flow has completed.
    requestGeneration.current += 1
    containmentOpenRef.current = true
    setSelected(null); setReturnAgent(null); setContainment({ agent, kind })
  }
  function openInspector(agent: AgentSummary, trigger: HTMLButtonElement) { inspectTriggerRef.current = trigger; setSelected(agent) }

  function requireCurrentReconciliation(generation: number) {
    if (!mountedRef.current || generation !== mandatoryGeneration.current || !containmentOpenRef.current) {
      throw new Error('Containment reconciliation was superseded by a newer swarm request. Retry reconciliation.')
    }
  }

  async function mandatoryReconcileContainment() {
    if (!containment) throw new Error('Containment context is unavailable. Retry from the latest swarm state.')
    if (mandatoryActiveRef.current) {
      if (mandatoryPromiseRef.current) return mandatoryPromiseRef.current
      throw new Error('Containment reconciliation is already in progress. Retry when it finishes.')
    }
    mandatoryActiveRef.current = true
    const generation = ++mandatoryGeneration.current
    const targetId = containment.agent.id
    setReturnAgent(null)
    const request = (async () => {
      const nextScan = await transport.scan({ includeUnmanagedCandidates })
      requireCurrentReconciliation(generation)
      const summary = nextScan.agents.find((agent) => agent.id === targetId)
      if (summary) {
        const detail = await transport.getAgentDetail(targetId, {
          id: summary.id,
          revision: summary.revision,
          pid: summary.pid,
          processInstanceId: summary.processInstanceId,
        })
        requireCurrentReconciliation(generation)
        if (stableStringify(verifiedAgentSummary(detail)) !== stableStringify(verifiedAgentSummary(summary))) {
          throw new Error('The agent changed while reconciliation was loading. Retry to inspect the latest state.')
        }
      }
      orderedIds.current = nextScan.agents.map((agent) => agent.id)
      scanRef.current = nextScan; setPendingScan(null); setScan(nextScan)
      setReturnAgent(summary ?? null)
    })()
    mandatoryPromiseRef.current = request
    try { await request }
    finally {
      mandatoryActiveRef.current = false
      mandatoryPromiseRef.current = null
    }
  }

  async function receiptComplete(receipt: ContainmentReceipt) {
    void receipt
    await mandatoryReconcileContainment()
  }
  function returnToInspector() {
    if (!returnAgent) inspectTriggerRef.current = document.querySelector<HTMLElement>('#page-title')
    closeContainment()
    setSelected(returnAgent)
  }

  return (
    <div className="swarm-page">
      <header className="swarm-header"><div><p className="eyebrow">Containment Console</p><h1 id="page-title" data-route-heading="true" tabIndex={-1}>Swarm</h1><p>Local agent health, evidence, and reviewable containment.</p></div><span className="demo-pill">{transport.mode === 'native' ? transport.capabilities.processActions ? 'Local engine · native actions' : 'Local engine · process actions unavailable' : 'Demo lab · no OS changes'}</span></header>
      {transport.mode === 'native' && <p className="local-warning"><strong>Native capabilities.</strong> {transport.capabilities.processActions ? 'Process scanning and reviewed stop actions use the local engine.' : 'Process scanning uses the local engine. Process actions are unavailable on this host.'} Additional recovery workflows appear in Memory Vault, Activity, and Settings when supported by this engine and the selected resource.</p>}
      {!scan && !error && <div className="swarm-skeleton" aria-label="Loading swarm radar"><span /><span /><span /><p>Loading coverage and agent evidence…</p></div>}
      {error && <div className="error-banner" role="alert"><strong>Scan incomplete</strong><p>{error}</p><button type="button" className="secondary-button" onClick={() => void refresh().catch(() => undefined)}>Retry scan</button></div>}
      {scan && <>
        <section className="coverage-banner" aria-label="Coverage status"><div><strong>{scan.coverage.blindSpotCount} coverage blind spots</strong><span>{scan.coverage.completeness === 'complete' ? 'Complete' : 'Partial'} {scan.mode === 'native' ? 'local-engine' : 'Demo lab'} coverage · {scan.coverage.observedProcessCount} processes observed</span></div><ul>{scan.coverage.blindSpots.map((spot) => <li key={spot}>{spot}</li>)}</ul></section>
        <ul className="summary-strip" aria-label="Swarm summary"><li><span>Needs attention</span><strong>{scan.metrics.needsAttention}</strong></li><li><span>Active</span><strong>{scan.metrics.active}</strong></li><li><span>Unmanaged</span><strong>{scan.metrics.unmanaged}</strong></li><li><span>Reclaimable</span><strong>{scan.metrics.reclaimableMb === null ? 'Not available' : `${scan.metrics.reclaimableMb} MB`}</strong></li><li><span>API cost</span><strong>{scan.usage.costUsd === null ? 'Not available' : `$${scan.usage.costUsd.toFixed(2)}`}</strong></li></ul>
        <div className="swarm-toolbar"><label>Search agents<input type="search" aria-label="Search agents" value={query} onChange={(event) => setQuery(event.target.value)} /></label><button type="button" className="secondary-button" onClick={() => setPaused((value) => !value)}>{paused ? 'Resume auto-refresh' : 'Pause auto-refresh'}</button><button type="button" className="secondary-button" onClick={() => void refresh().catch(() => undefined)}>Refresh swarm</button>{inFlight > 0 && <span className="updating" role="status">Updating…</span>}</div>
        {pendingScan && <button className="changed-banner" type="button" onClick={() => { orderedIds.current = pendingScan.agents.map((a) => a.id); scanRef.current = pendingScan; setScan(pendingScan); setPendingScan(null) }}>{updateLabel(scan, pendingScan)}</button>}
        {visibleAgents.length === 0 ? <div className="all-quiet"><h2>All quiet in the swarm</h2><p>No agents match the current view.</p></div> : groups.map((group) => <section className="agent-group" key={group.title} aria-labelledby={`group-${group.title.replaceAll(' ', '-').toLowerCase()}`}><div className="agent-group__heading"><h2 id={`group-${group.title.replaceAll(' ', '-').toLowerCase()}`}>{group.title}</h2><span>{group.agents.length}</span></div>{group.agents.length ? <ul className="agent-list">{group.agents.map((agent) => <AgentRow key={agent.id} agent={agent} capturedAt={scan.capturedAt} native={scan.mode === 'native'} onInspect={openInspector} />)}</ul> : <p className="group-empty">No detections in this group.</p>}</section>)}
      </>}
      {selected && <AgentDetails key={`${selected.id}:${selected.revision}`} agent={selected} transport={transport} onClose={() => setSelected(null)} onReview={beginContainment} />}
      {containment && <ContainmentDialog agent={containment.agent} transport={transport} initialKind={containment.kind} onClose={closeContainment} onComplete={receiptComplete} onUncertain={mandatoryReconcileContainment} onReturn={returnToInspector} restoreFocusRef={inspectTriggerRef} />}
    </div>
  )
}
