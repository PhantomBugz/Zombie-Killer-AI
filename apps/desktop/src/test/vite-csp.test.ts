import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

import { createServer, loadConfigFromFile } from 'vite'
import { describe, expect, it } from 'vitest'

import {
  DEV_CSP_NONCE,
  transformCspMetaForCommand,
} from '../../vite.config'

const desktopRoot = process.cwd()
const configPath = resolve(desktopRoot, 'vite.config.ts')
const indexHtml = readFileSync(resolve(desktopRoot, 'index.html'), 'utf8')
const tauriConfig = JSON.parse(
  readFileSync(resolve(desktopRoot, 'src-tauri/tauri.conf.json'), 'utf8'),
) as { app: { security: { csp: string; devCsp: string } } }

function policyFrom(html: string) {
  const document = new DOMParser().parseFromString(html, 'text/html')
  const meta = document.querySelector<HTMLMetaElement>('meta[http-equiv="Content-Security-Policy"]')
  if (!meta) throw new Error('CSP meta not found')
  return meta.content
}

function sources(policy: string, directive: string) {
  const entry = policy
    .split(';')
    .map((value) => value.trim())
    .find((value) => value.startsWith(`${directive} `))
  if (!entry) throw new Error(`${directive} not found`)
  return entry.split(/\s+/).slice(1)
}

describe('Vite development CSP', () => {
  it('uses one nonce in the actual serve config, transformed HTML, and Tauri dev policy', async () => {
    const loaded = await loadConfigFromFile(
      { command: 'serve', mode: 'development' },
      configPath,
      desktopRoot,
    )
    expect(loaded?.config.html?.cspNonce).toBe(DEV_CSP_NONCE)

    const devHtml = transformCspMetaForCommand(indexHtml, 'serve')
    const nonceSource = `'nonce-${DEV_CSP_NONCE}'`
    expect(sources(policyFrom(devHtml), 'style-src')).toEqual(["'self'", nonceSource])
    expect(sources(policyFrom(devHtml), 'script-src')).toEqual(["'self'", nonceSource])
    expect(sources(tauriConfig.app.security.devCsp, 'style-src')).toEqual(["'self'", nonceSource])
    expect(sources(tauriConfig.app.security.devCsp, 'script-src')).toEqual(["'self'", nonceSource])
    expect(`${policyFrom(devHtml)};${tauriConfig.app.security.devCsp}`).not.toMatch(
      /'unsafe-inline'|'unsafe-eval'|(?:^|\s)\*(?:\s|;|$)/,
    )
  })

  it('lets Vite nonce its injected client and publish the nonce for runtime styles', async () => {
    const server = await createServer({
      root: desktopRoot,
      configFile: configPath,
      appType: 'custom',
      server: { middlewareMode: true },
    })

    try {
      const transformed = await server.transformIndexHtml('/index.html', indexHtml)
      const document = new DOMParser().parseFromString(transformed, 'text/html')
      const nonceMeta = document.querySelector<HTMLMetaElement>('meta[property="csp-nonce"]')
      expect(nonceMeta?.nonce || nonceMeta?.getAttribute('nonce')).toBe(DEV_CSP_NONCE)
      const scripts = [...document.querySelectorAll<HTMLScriptElement>('script')]
      expect(scripts.length).toBeGreaterThan(1)
      expect(scripts.every((script) => script.nonce === DEV_CSP_NONCE)).toBe(true)
      expect(sources(policyFrom(transformed), 'style-src')).toContain(`'nonce-${DEV_CSP_NONCE}'`)
    } finally {
      await server.close()
    }
  })

  it('leaves production HTML and release CSP strict and nonce-free', async () => {
    const loaded = await loadConfigFromFile(
      { command: 'build', mode: 'production' },
      configPath,
      desktopRoot,
    )
    expect(loaded?.config.html?.cspNonce).toBeUndefined()
    expect(transformCspMetaForCommand(indexHtml, 'build')).toBe(indexHtml)
    expect(sources(policyFrom(indexHtml), 'style-src')).toEqual(["'self'"])
    expect(sources(policyFrom(indexHtml), 'script-src')).toEqual(["'self'"])
    expect(tauriConfig.app.security.csp).not.toContain('nonce-')
    expect(`${indexHtml};${tauriConfig.app.security.csp}`).not.toMatch(/'unsafe-inline'|'unsafe-eval'/)
  })
})
