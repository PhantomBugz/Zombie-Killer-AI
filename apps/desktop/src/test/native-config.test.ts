import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

import { describe, expect, it } from 'vitest'

const tauriConfig = JSON.parse(readFileSync(resolve(process.cwd(), 'src-tauri/tauri.conf.json'), 'utf8')) as Record<string, any>
const capability = JSON.parse(readFileSync(resolve(process.cwd(), 'src-tauri/capabilities/main.json'), 'utf8')) as Record<string, any>
const permission = readFileSync(resolve(process.cwd(), 'src-tauri/permissions/engine.toml'), 'utf8')
const sidecarBuild = readFileSync(resolve(process.cwd(), '../../scripts/build-engine-sidecar.py'), 'utf8')
const desktopPackage = JSON.parse(readFileSync(resolve(process.cwd(), 'package.json'), 'utf8')) as Record<string, any>
const rustBuild = readFileSync(resolve(process.cwd(), 'src-tauri/build.rs'), 'utf8')
const indexHtml = readFileSync(resolve(process.cwd(), 'index.html'), 'utf8')

function parseCsp(policy: string) {
  const directives = new Map<string, string[]>()
  for (const directive of policy.split(';').map((value) => value.trim()).filter(Boolean)) {
    const [name, ...sources] = directive.split(/\s+/)
    const normalizedName = name.toLowerCase()
    if (directives.has(normalizedName)) throw new Error(`Duplicate CSP directive: ${normalizedName}`)
    directives.set(normalizedName, sources)
  }
  return directives
}

function htmlMetaCsp(html: string) {
  const document = new DOMParser().parseFromString(html, 'text/html')
  const metas = [...document.querySelectorAll<HTMLMetaElement>('meta[http-equiv]')]
    .filter((meta) => meta.httpEquiv.toLowerCase() === 'content-security-policy')
  if (metas.length !== 1 || metas[0].parentElement !== document.head) {
    throw new Error('Exactly one Content-Security-Policy meta must be a direct child of head.')
  }
  const meta = metas[0]
  const headElements = [...document.head.querySelectorAll('*')]
  const activeContentPrecedesMeta = headElements
    .slice(0, headElements.indexOf(meta))
    .some((element) => element.matches('script, style, link[rel~="stylesheet"]'))
  if (activeContentPrecedesMeta) throw new Error('Content-Security-Policy meta must precede active content.')
  const content = meta.content
  if (!content) throw new Error('Content-Security-Policy meta content is missing.')
  return content
}

describe('native shell policy', () => {
  it('rejects duplicate CSP directives and an ineffective late policy meta', () => {
    expect(() => parseCsp("script-src https:; script-src 'self'")).toThrow(/duplicate CSP directive/i)
    expect(() => htmlMetaCsp(`
      <html>
        <head>
          <script src="./unsafe.js"></script>
          <meta http-equiv="Content-Security-Policy" content="script-src 'self'" />
        </head>
      </html>
    `)).toThrow(/must precede active content/i)
  })

  it('has one local main window, a frozen prototype, and a strict IPC-only CSP', () => {
    expect(tauriConfig.identifier).toBe('com.phantombugz.zombiekiller')
    expect(tauriConfig.app.windows).toHaveLength(1)
    expect(tauriConfig.app.windows[0]).toMatchObject({ label: 'main', url: 'index.html' })
    expect(tauriConfig.app.security.freezePrototype).toBe(true)
    const csp = JSON.stringify(tauriConfig.app.security.csp)
    expect(csp).toContain("default-src 'self'")
    expect(csp).toContain('connect-src ipc: http://ipc.localhost')
    expect(csp).not.toMatch(/https:|wss:|\*/)
  })

  it('keeps required Tauri IPC origins and strict script/style sources in every renderer policy', () => {
    const policies = [
      ['HTML meta', htmlMetaCsp(indexHtml)],
      ['Tauri production', String(tauriConfig.app.security.csp)],
      ['Tauri development', String(tauriConfig.app.security.devCsp)],
    ] as const

    for (const [name, policy] of policies) {
      const directives = parseCsp(policy)
      expect(directives.get('connect-src'), `${name} connect-src`).toEqual(expect.arrayContaining(['ipc:', 'http://ipc.localhost']))
      const expectedSources = name === 'Tauri development'
        ? ["'self'", expect.stringMatching(/^'nonce-[A-Za-z0-9+/_-]+'$/)]
        : ["'self'"]
      expect(directives.get('script-src'), `${name} script-src`).toEqual(expectedSources)
      expect(directives.get('style-src'), `${name} style-src`).toEqual(expectedSources)
      expect(policy, `${name} unsafe source`).not.toMatch(/'unsafe-inline'|'unsafe-eval'/)
      for (const override of ['script-src-elem', 'script-src-attr', 'style-src-elem', 'style-src-attr']) {
        expect(directives.has(override), `${name} must not define ${override}`).toBe(false)
      }
    }
  })

  it('grants only the engine request command to the main window', () => {
    expect(capability.windows).toEqual(['main'])
    expect(capability.permissions).toEqual(['allow-engine-request'])
    expect(JSON.stringify(capability)).not.toMatch(/shell|http|fs:|dialog|updater/i)
    expect(permission).toContain('commands.allow = ["engine_request"]')
    expect(permission).not.toMatch(/shell|http|fs:|dialog|updater/i)
    expect(tauriConfig.plugins).toBeUndefined()
  })

  it('packages a fixed PyInstaller onedir resource instead of a onefile extractor', () => {
    expect(tauriConfig.bundle.resources).toEqual({ 'resources/engine/': 'engine/' })
    expect(tauriConfig.build.beforeBuildCommand).toBe('pnpm native:prepare')
    expect(desktopPackage.scripts['native:prepare']).toContain('build-engine-sidecar.py')
    expect(sidecarBuild).toContain('"--onedir"')
    expect(sidecarBuild).not.toContain('"--onefile"')
    expect(sidecarBuild).toContain('PYINSTALLER_VERSION = "6.18.0"')
    expect(sidecarBuild).toContain('sidecar symbolic link escaped the staging tree')
    expect(sidecarBuild).toContain('candidate.rename(destination)')
    expect(rustBuild).toContain('release engine resource is missing')
    expect(rustBuild).toContain('resource_manifest::verify_bundle')
  })
})
