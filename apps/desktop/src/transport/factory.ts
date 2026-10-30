import { isTauri } from '@tauri-apps/api/core'

import { DemoTransport } from './demo'
import { TauriTransport, type NativeInvoke } from './tauri'
import type { EngineTransport } from './types'

export function isTauriRuntime(detect: () => boolean = isTauri): boolean {
  try { return detect() }
  catch { return false }
}

interface FactoryOptions {
  nativeRuntime?: boolean
  dev?: boolean
  demoOverride?: boolean
  invoke?: NativeInvoke
}

function queryRequestsDemo() {
  return typeof window !== 'undefined' && new URLSearchParams(window.location.search).get('demo') === '1'
}

export function createTransport(options: FactoryOptions = {}): EngineTransport {
  const nativeRuntime = options.nativeRuntime ?? isTauriRuntime()
  const dev = options.dev ?? import.meta.env.DEV
  const demoOverride = options.demoOverride ?? queryRequestsDemo()
  if (!nativeRuntime || (dev && demoOverride)) return new DemoTransport()
  return new TauriTransport(options.invoke)
}
