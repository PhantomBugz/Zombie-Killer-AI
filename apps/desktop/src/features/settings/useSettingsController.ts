import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react'

import { TransportError } from '../../transport'
import type { AppSettings, EngineTransport } from '../../transport'

export type SettingsSaveStatus = 'idle' | 'saving' | 'saved'
type SettingsIntent =
  | { kind: 'update'; changes: Partial<Omit<AppSettings, 'revision'>> }
  | { kind: 'reset' }

export interface SettingsController {
  discardPending: boolean
  error: string
  loading: boolean
  retryPending: boolean
  reload: () => Promise<AppSettings>
  reset: () => void
  saveStatus: SettingsSaveStatus
  settings: AppSettings | undefined
  update: (changes: Partial<Omit<AppSettings, 'revision'>>) => void
}

function messageFrom(reason: unknown, fallback: string) {
  return reason instanceof Error ? reason.message : fallback
}

function intentAlreadyApplied(intent: SettingsIntent, value: AppSettings) {
  if (intent.kind !== 'update') return false
  const durable = value as unknown as Record<string, unknown>
  return Object.entries(intent.changes).every(([key, expected]) => Object.is(durable[key], expected))
}

function projectPendingUpdates(value: AppSettings, pendingIntents: readonly SettingsIntent[]) {
  let projected = { ...value }
  for (const intent of pendingIntents) {
    if (intent.kind === 'reset') break
    projected = { ...projected, ...intent.changes }
  }
  return projected
}

export function useSettingsController(transport: EngineTransport): SettingsController {
  const [settings, setSettings] = useState<AppSettings>()
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [saveStatus, setSaveStatus] = useState<SettingsSaveStatus>('idle')
  const [retryPending, setRetryPending] = useState(false)
  const [discardPending, setDiscardPending] = useState(false)
  const mounted = useRef(true)
  const persisted = useRef<AppSettings | undefined>(undefined)
  const optimistic = useRef<AppSettings | undefined>(undefined)
  const pending = useRef(0)
  const loadPromise = useRef<Promise<AppSettings> | null>(null)
  const intents = useRef<SettingsIntent[]>([])
  const draining = useRef(false)
  const queueBlocked = useRef(false)
  const retryableBlock = useRef(false)
  const discardableBlock = useRef(false)
  const drainRef = useRef<(() => Promise<void>) | null>(null)

  const commit = useCallback((value: AppSettings) => {
    persisted.current = value
    optimistic.current = value
    if (mounted.current) setSettings(value)
  }, [])

  const reload = useCallback(() => {
    if (loadPromise.current) return loadPromise.current
    if (mounted.current) setLoading(true)
    const request = transport.getSettings().then((value) => {
      commit(value)
      if (retryableBlock.current) {
        queueBlocked.current = false
        retryableBlock.current = false
        if (mounted.current) { setRetryPending(false); setDiscardPending(false); setSaveStatus('saving') }
        queueMicrotask(() => { void drainRef.current?.() })
      } else if (discardableBlock.current) {
        intents.current = []
        pending.current = 0
        queueBlocked.current = false
        discardableBlock.current = false
        if (mounted.current) { setDiscardPending(false); setSaveStatus('idle') }
      }
      if (mounted.current) setError('')
      return value
    }).catch((reason: unknown) => {
      if (mounted.current) setError(messageFrom(reason, 'Settings are unavailable.'))
      throw reason
    }).finally(() => {
      loadPromise.current = null
      if (mounted.current) setLoading(false)
    })
    loadPromise.current = request
    return request
  }, [commit, transport])

  useEffect(() => {
    mounted.current = true
    void reload().catch(() => undefined)
    return () => { mounted.current = false }
  }, [reload])

  useLayoutEffect(() => {
    if (!settings) return
    if (settings.theme === 'system') document.documentElement.removeAttribute('data-theme')
    else document.documentElement.dataset.theme = settings.theme
    document.documentElement.dataset.motion = settings.motion
    document.documentElement.dataset.dense = settings.denseMode ? 'true' : 'false'
  }, [settings])

  const drain = useCallback(async () => {
    if (draining.current || queueBlocked.current) return
    draining.current = true
    try {
      while (intents.current.length > 0 && !queueBlocked.current) {
        const intent = intents.current[0]
        const apply = async () => {
          const base = persisted.current
          if (!base) throw new Error('Settings are not loaded.')
          return intent.kind === 'update'
            ? transport.updateSettings({ expectedRevision: base.revision, changes: intent.changes })
            : transport.resetSettings(base.revision)
        }
        let next: AppSettings
        try {
          const base = persisted.current
          next = base && intentAlreadyApplied(intent, base) ? base : await apply()
        } catch (firstReason) {
          if (!(firstReason instanceof TransportError) || firstReason.code !== 'conflict') {
            // A timeout, validation failure, or uncertain result is not a
            // compare-and-swap conflict. Never replay those writes blindly.
            queueBlocked.current = true
            retryableBlock.current = false
            discardableBlock.current = true
            if (persisted.current) {
              optimistic.current = persisted.current
              if (mounted.current) setSettings(persisted.current)
            }
            if (mounted.current) {
              setRetryPending(false)
              setDiscardPending(true)
              setError(messageFrom(firstReason, 'Settings update failed.'))
              setSaveStatus('idle')
            }
            break
          }
          // Reconcile once, then retry the exact same intent before touching
          // any later queued intent. A failed retry leaves the whole queue
          // intact and blocks writes until an explicit reload succeeds.
          let fresh: AppSettings
          try {
            fresh = await transport.getSettings()
          } catch (reloadReason) {
            queueBlocked.current = true
            retryableBlock.current = true
            discardableBlock.current = false
            if (persisted.current) {
              optimistic.current = persisted.current
              if (mounted.current) setSettings(persisted.current)
            }
            if (mounted.current) {
              setRetryPending(true)
              setDiscardPending(false)
              setError(messageFrom(reloadReason, 'Settings reconciliation failed.'))
              setSaveStatus('idle')
            }
            break
          }
          commit(fresh)
          try {
            next = intentAlreadyApplied(intent, fresh) ? fresh : await apply()
          } catch (retryReason) {
            // The reconciliation fetch above already committed the latest
            // durable state. Keep the exact failed intent (and every queued
            // successor) pending, and stop until an explicit reload succeeds.
            queueBlocked.current = true
            retryableBlock.current = retryReason instanceof TransportError && retryReason.code === 'conflict'
            discardableBlock.current = !retryableBlock.current
            if (persisted.current) {
              optimistic.current = persisted.current
              if (mounted.current) setSettings(persisted.current)
            }
            if (mounted.current) {
              setRetryPending(retryableBlock.current)
              setDiscardPending(discardableBlock.current)
              setError(messageFrom(retryReason ?? firstReason, 'Settings update failed.'))
              setSaveStatus('idle')
            }
            break
          }
        }
        intents.current.shift()
        pending.current = Math.max(0, pending.current - 1)
        persisted.current = next
        optimistic.current = pending.current === 0 ? next : projectPendingUpdates(next, intents.current)
        if (mounted.current) setSettings(optimistic.current)
      }
      if (mounted.current && !queueBlocked.current && pending.current === 0) {
        retryableBlock.current = false
        discardableBlock.current = false
        setRetryPending(false)
        setDiscardPending(false)
        setError('')
        setSaveStatus('saved')
      }
    } finally {
      draining.current = false
    }
  }, [commit, transport])
  useEffect(() => { drainRef.current = drain }, [drain])

  const update = useCallback((changes: Partial<Omit<AppSettings, 'revision'>>) => {
    if (!transport.capabilities.settingsUpdate) {
      setError('Settings updates are unavailable from this transport.')
      return
    }
    const current = optimistic.current
    if (!current) return
    if (queueBlocked.current) return
    optimistic.current = { ...current, ...changes }
    setSettings(optimistic.current)
    pending.current += 1
    setSaveStatus('saving')
    intents.current.push({ kind: 'update', changes })
    void drain()
  }, [drain, transport])

  const reset = useCallback(() => {
    if (!transport.capabilities.settingsUpdate) {
      setError('Settings updates are unavailable from this transport.')
      return
    }
    if (!persisted.current) return
    if (queueBlocked.current) return
    pending.current += 1
    setSaveStatus('saving')
    intents.current.push({ kind: 'reset' })
    void drain()
  }, [drain, transport])

  return { discardPending, error, loading, retryPending, reload, reset, saveStatus, settings, update }
}
