import react from '@vitejs/plugin-react'
import type { Plugin } from 'vite'
import { defineConfig } from 'vitest/config'

export const DEV_CSP_NONCE = 'WktEZXZOb25jZVYxMjAyNjA4MTM'

type ViteCommand = 'build' | 'serve'

const cspMetaPattern = /<meta\b(?=[^>]*\bhttp-equiv\s*=\s*(["'])Content-Security-Policy\1)[^>]*>/i
const contentAttributePattern = /\bcontent\s*=\s*(["'])([\s\S]*?)\1/i

function addNonceSource(policy: string, directiveName: 'script-src' | 'style-src') {
  const nonceSource = `'nonce-${DEV_CSP_NONCE}'`
  let matches = 0
  const directives = policy.split(';').map((directive) => {
    const trimmed = directive.trim()
    const [name, ...values] = trimmed.split(/\s+/)
    if (name.toLowerCase() !== directiveName) return directive
    matches += 1
    if (values.includes(nonceSource)) return directive
    return `${directiveName} ${[...values, nonceSource].join(' ')}`
  })
  if (matches !== 1) {
    throw new Error(`Expected exactly one ${directiveName} directive in the renderer CSP.`)
  }
  return directives.join(';')
}

/**
 * Vite injects CSS through style elements while serving the React app. Keep the
 * checked-in production policy unchanged and grant only Vite's explicit nonce
 * during local development.
 */
export function transformCspMetaForCommand(html: string, command: ViteCommand) {
  if (command !== 'serve') return html

  let cspMetaCount = 0
  const transformed = html.replace(cspMetaPattern, (meta) => {
    cspMetaCount += 1
    let contentCount = 0
    const updated = meta.replace(contentAttributePattern, (_attribute, quote: string, policy: string) => {
      contentCount += 1
      const withScriptNonce = addNonceSource(policy, 'script-src')
      const withStyleNonce = addNonceSource(withScriptNonce, 'style-src')
      return `content=${quote}${withStyleNonce}${quote}`
    })
    if (contentCount !== 1) {
      throw new Error('Development CSP meta must contain exactly one content attribute.')
    }
    return updated
  })

  if (cspMetaCount !== 1) {
    throw new Error('Development HTML must contain exactly one Content-Security-Policy meta.')
  }
  return transformed
}

function developmentCspPlugin(): Plugin {
  return {
    name: 'zombie-killer:development-csp',
    apply: 'serve',
    enforce: 'pre',
    transformIndexHtml(html) {
      return transformCspMetaForCommand(html, 'serve')
    },
  }
}

export default defineConfig(({ command }) => ({
  plugins: [developmentCspPlugin(), react()],
  html: command === 'serve' ? { cspNonce: DEV_CSP_NONCE } : undefined,
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: './src/test/setup.ts',
  },
}))
