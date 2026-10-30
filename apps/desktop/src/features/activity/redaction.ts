const maxStringLength = 512
const maxDepth = 5
const maxCollectionItems = 50
const sensitiveKeyParts = [
  ['access', 'token'], ['api', 'key'], ['auth', 'token'], ['authorization'],
  ['aws', 'secret', 'access', 'key'], ['aws', 'session', 'token'], ['client', 'secret'],
  ['credential'], ['credentials'], ['id', 'token'], ['passphrase'], ['password'], ['passwd'],
  ['private', 'key'], ['refresh', 'token'], ['secret'], ['seed', 'phrase'],
  ['session', 'token'], ['token'], ['x', 'api', 'key'],
] as const
const sensitiveKeySeparator = '[._\\-\\p{White_Space}\\u200B\\u200C\\uFEFF\\x00-\\x1F\\x7F-\\x9F]{0,16}'
const compactSensitiveKeySeparator = '[._\\-\\u200B\\u200C\\uFEFF\\x00-\\x1F\\x7F-\\x9F]{0,16}'
const boundedWhitespaceCharacter = '[\\p{White_Space}\\uFEFF\\x00-\\x1F\\x7F-\\x9F]'
const nonWhitespaceCharacter = '[^\\p{White_Space}\\uFEFF\\x00-\\x1F\\x7F-\\x9F]'
const wordContinuationSource = '\\p{Letter}\\p{Number}\\p{Mark}\\p{Connector_Punctuation}'
const sensitiveKeySource = sensitiveKeyParts.map((parts) => parts.join(sensitiveKeySeparator)).join('|')
const bareCliSensitiveKeySource = ['client', 'secret'].join(compactSensitiveKeySeparator)
const singleSensitiveKeySource = sensitiveKeyParts.filter((parts) => parts.length === 1).map((parts) => parts[0]).join('|')
const normalizedSensitiveKeys = new Set(sensitiveKeyParts.map((parts) => parts.join('')))
const boundedSensitiveKeySource = `(?<![${wordContinuationSource}])(?:${sensitiveKeySource})(?![${wordContinuationSource}])`
const structuredSensitiveKeySource = `(?:"(?:${sensitiveKeySource})"|'(?:${sensitiveKeySource})'|${boundedSensitiveKeySource})`
const boundedWhitespaceWithValue = `${boundedWhitespaceCharacter}{1,16}(?=${nonWhitespaceCharacter})`
const namedSecretSource = [
  `${structuredSensitiveKeySource}${boundedWhitespaceCharacter}{0,16}[:=]`,
  `(?<![${wordContinuationSource}])-{1,2}(?:${sensitiveKeySource})(?![${wordContinuationSource}])${boundedWhitespaceWithValue}`,
  `(?<![${wordContinuationSource}])(?:${bareCliSensitiveKeySource})(?![${wordContinuationSource}])${boundedWhitespaceWithValue}`,
  `(?<![${wordContinuationSource}])(?:${singleSensitiveKeySource})(?![${wordContinuationSource}])(?! )${boundedWhitespaceWithValue}`,
].join('|')
const namedSecretIndicator = new RegExp(`(?:${namedSecretSource})`, 'iu')
const unresolvedSecretIndicator = new RegExp(`(?:\\bbearer\\s+(?!\\[REDACTED\\])|${namedSecretSource})`, 'iu')
const privateKeyPemBeginPattern = /-----BEGIN (?:(?:[A-Z0-9]+ )*PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----/
const tokenPatterns = [
  /\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, /\bBearer\s+[A-Za-z0-9._~+/-]+=*/gi,
  /\bsk-[A-Za-z0-9_-]{20,}\b/g, /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g,
  /\b(?:AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA|AGPA|ASCA)[A-Z0-9]{16}\b/g, /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/g,
  /\bxapp-[A-Za-z0-9-]{20,}\b/g, /\b1\/\/[A-Za-z0-9_-]{20,}\b/g,
  /\bAIza[A-Za-z0-9_-]{30,}\b/g, /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
  /\bnpm_[A-Za-z0-9]{20,}\b/g, /\bglpat-[A-Za-z0-9_-]{20,}\b/g, /\bpypi-[A-Za-z0-9_-]{20,}\b/g,
  /\bya29\.[A-Za-z0-9_-]{20,}\b/g, /\bMII[A-Za-z0-9+/=]{40,}\b/g,
]

const unicodeWhitespace = /\p{White_Space}/u
const wordContinuationCharacter = /[\p{Letter}\p{Number}\p{Mark}\p{Connector_Punctuation}]/u
const emptyPathFollowers = new Set(['"', "'", '`', '‘', '’', '“', '”', ')', ']', '}', ',', ';', '|', '?', '#', '&'])
const maxUrlInspectionItems = 128
const maxUrlInspectionCodeUnits = 16_384
const maxUrlDecodeLayers = 2
const graphemeSegmenter = new Intl.Segmenter(undefined, { granularity: 'grapheme' })

function toWellFormedText(value: string) {
  let result = ''
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index)
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1)
      if (next >= 0xdc00 && next <= 0xdfff) { result += value[index]! + value[index + 1]!; index += 1 }
      else result += '\uFFFD'
    } else if (code >= 0xdc00 && code <= 0xdfff) result += '\uFFFD'
    else result += value[index]!
  }
  return result
}

export function truncateSafeText(value: string, maxLength = maxStringLength) {
  if (!Number.isInteger(maxLength) || maxLength <= 0) return ''
  const wellFormed = toWellFormedText(value)
  if (wellFormed.length <= maxLength) return wellFormed
  let result = ''
  for (const { segment } of graphemeSegmenter.segment(wellFormed)) {
    if (result.length + segment.length > maxLength) break
    result += segment
  }
  return result
}

function isUnicodeWhitespace(character: string) {
  return character === '\uFEFF' || unicodeWhitespace.test(character)
}

function isSensitiveKey(value: string) {
  return normalizedSensitiveKeys.has(value.toLowerCase().replace(/[^a-z0-9]/g, ''))
}

function splitAtControl(value: string) {
  let offset = 0
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0
    if (code <= 0x1f || (code >= 0x7f && code <= 0x9f) || code === 0xfeff) return [value.slice(0, offset), value.slice(offset)] as const
    offset += character.length
  }
  return [value, ''] as const
}

function previousCodePoint(value: string, offset: number) {
  let start = offset - 1
  const trailing = value.charCodeAt(start)
  if (trailing >= 0xdc00 && trailing <= 0xdfff && start > 0) {
    const leading = value.charCodeAt(start - 1)
    if (leading >= 0xd800 && leading <= 0xdbff) start -= 1
  }
  const point = value.codePointAt(start)
  return point === undefined ? '' : String.fromCodePoint(point)
}

function isLocalBoundary(value: string, offset: number) {
  if (offset === 0) return true
  return !wordContinuationCharacter.test(previousCodePoint(value, offset))
}

function startsLocalPathAt(value: string, offset: number) {
  const first = value[offset]
  const second = value[offset + 1]
  const third = value[offset + 2]
  if (first !== undefined && /[A-Za-z]/u.test(first) && second === ':' && (third === '/' || third === '\\')) return true
  if (first === '\\' && second !== undefined) return true
  if (first !== '/') return false
  let cursor = offset
  while (value[cursor] === '/') cursor += 1
  if (cursor >= value.length) return false
  const point = value.codePointAt(cursor)
  if (point === undefined) return false
  const next = String.fromCodePoint(point)
  return !isUnicodeWhitespace(next) && !emptyPathFollowers.has(next)
}

function urlContentStart(value: string) {
  const scheme = value.match(/^[A-Za-z][A-Za-z0-9+.-]*:\/\//u)
  const authorityStart = scheme?.[0].length ?? (value.startsWith('//') ? 2 : 0)
  for (let offset = authorityStart; offset < value.length; offset += 1) {
    if (value[offset] !== '/' && value[offset] !== '?' && value[offset] !== '#') continue
    let contentStart = offset + 1
    while (value[contentStart] === '/') contentStart += 1
    return contentStart
  }
  return value.length
}

function isSupportedRemoteHost(hostname: string) {
  return hostname === 'localhost' || hostname.includes(':') || /^\d{1,3}(?:\.\d{1,3}){3}$/u.test(hostname) || /\.[a-z0-9-]{2,}$/iu.test(hostname)
}

function startsNestedRemoteUrl(value: string, offset: number) {
  if (!value.startsWith('//', offset)) return false
  const prefix = value.slice(0, offset)
  if (/(?:https?|ftp):$/iu.test(prefix)) return true
  try { return isSupportedRemoteHost(new URL(`https:${value.slice(offset)}`).hostname) } catch { return false }
}

function splitBeforeLocalSuffix(value: string) {
  const [remote, suffix] = splitAtControl(value)
  for (let offset = urlContentStart(remote); offset < remote.length; offset += 1) {
    if (startsNestedRemoteUrl(remote, offset)) { offset += 1; continue }
    if (isLocalBoundary(remote, offset) && startsLocalPathAt(remote, offset)) {
      return [remote.slice(0, offset), `${remote.slice(offset)}${suffix}`] as const
    }
  }
  return [remote, suffix] as const
}

function containsUnmaskedLocalPath(value: string): boolean {
  for (let offset = 0; offset < value.length; offset += 1) {
    if (isLocalBoundary(value, offset) && startsLocalPathAt(value, offset)) return true
  }
  return false
}

function decodePercentLayer(value: string) {
  if (!/%[0-9A-Fa-f]{2}/u.test(value)) return value
  try { return decodeURIComponent(value) } catch {
    return value.replace(/(?:%[0-9A-Fa-f]{2})+/gu, (sequence) => {
      try { return decodeURIComponent(sequence) } catch {
        return sequence.replace(/%([0-9A-Fa-f]{2})/gu, (escape, hex: string) => {
          const code = Number.parseInt(hex, 16)
          return code <= 0x7f ? String.fromCharCode(code) : escape
        })
      }
    })
  }
}

function hasDirectUrlUserInfo(value: string) {
  return /\b[a-z][a-z0-9+.-]*:\/\/[^\s/?#]+@/iu.test(value)
    || /(^|[^\p{Letter}\p{Number}\p{Mark}\p{Connector_Punctuation}])\/{2}(?!\/)[^\p{White_Space}\uFEFF"'<>/?#]+@/iu.test(value)
}

function remoteUrlComponents(url: URL) {
  const fragment = url.hash.startsWith('#') ? url.hash.slice(1) : url.hash
  const candidates = [...url.searchParams.keys(), ...url.searchParams.values()]
  if (fragment) {
    candidates.push(fragment)
    const fragmentParameters = new URLSearchParams(fragment.startsWith('?') ? fragment.slice(1) : fragment)
    candidates.push(...fragmentParameters.keys(), ...fragmentParameters.values())
  }
  return candidates
}

function hasUnredactedUserInfo(url: URL) {
  if (!url.username && !url.password) return false
  return !(decodedUrlComponent(url.username) === '[REDACTED]' && !url.password)
}

function decodedUrlComponent(value: string) {
  try { return decodeURIComponent(value) } catch { return value }
}

type UrlInspectionItem = { value: string, nested: boolean, decodeDepth: number }
type UrlInspectionState = {
  queue: UrlInspectionItem[]
  credential: boolean
}

function maskRemoteUrls(value: string, nested: boolean, state: UrlInspectionState): string {
  const mask = (text: string) => ' '.repeat(text.length)
  const inspectRemote = (remote: string, url: URL) => {
    if (nested && hasUnredactedUserInfo(url)) state.credential = true
    for (const component of remoteUrlComponents(url)) {
      if (component) state.queue.push({ value: component, nested: true, decodeDepth: 0 })
    }
    return mask(remote)
  }
  const schemesMasked = value.replace(/\b(?:https?|ftp):\/\/[^\p{White_Space}\uFEFF"'<>]*/giu, (candidate: string) => {
    const [remote, suffix] = splitBeforeLocalSuffix(candidate)
    try {
      const parsed = new URL(remote)
      if (!['http:', 'https:', 'ftp:'].includes(parsed.protocol) || !parsed.hostname) return candidate
      return `${inspectRemote(remote, parsed)}${suffix}`
    } catch { return candidate }
  })
  return schemesMasked.replace(/\/{2}(?!\/)[^\p{White_Space}\uFEFF"'<>]*/gu, (candidate: string, offset: number, source: string) => {
    if (!isLocalBoundary(source, offset) || (offset > 0 && (source[offset - 1] === ':' || source[offset - 1] === '/'))) return candidate
    const [remote, suffix] = splitBeforeLocalSuffix(candidate)
    try {
      const parsed = new URL(`https:${remote}`)
      const hostname = parsed.hostname
      if (!isSupportedRemoteHost(hostname)) return candidate
      return `${inspectRemote(remote, parsed)}${suffix}`
    } catch { return candidate }
  })
}

function inspectUrlSensitiveContent(value: string): 'safe' | 'path' | 'credential' | 'overflow' {
  const state: UrlInspectionState = {
    queue: [{ value, nested: false, decodeDepth: 0 }],
    credential: false,
  }
  const seen = new Set<string>()
  let inspectedCodeUnits = 0
  for (let cursor = 0; cursor < state.queue.length; cursor += 1) {
    if (cursor >= maxUrlInspectionItems) return 'overflow'
    const item = state.queue[cursor]!
    const seenKey = `${item.nested ? 1 : 0}:${item.decodeDepth}:${item.value}`
    if (seen.has(seenKey)) continue
    seen.add(seenKey)
    inspectedCodeUnits += item.value.length
    if (inspectedCodeUnits > maxUrlInspectionCodeUnits) return 'overflow'

    const masked = maskRemoteUrls(item.value, item.nested, state)
    if (state.credential) return 'credential'
    if (containsUnmaskedLocalPath(masked)) return 'path'

    const decoded = decodePercentLayer(item.value)
    if (decoded !== item.value) {
      if (item.decodeDepth >= maxUrlDecodeLayers) return 'overflow'
      state.queue.push({
        value: decoded,
        nested: item.nested || !hasDirectUrlUserInfo(item.value),
        decodeDepth: item.decodeDepth + 1,
      })
    }
    if (state.queue.length > maxUrlInspectionItems) return 'overflow'
  }
  return 'safe'
}

export function redactSensitiveText(value: string) {
  if (namedSecretIndicator.test(value)) return '[REDACTED]'
  if (privateKeyPemBeginPattern.test(value)) return '[REDACTED]'
  const urlInspection = inspectUrlSensitiveContent(value)
  if (urlInspection === 'path') return '[REDACTED_PATH]'
  if (urlInspection === 'credential' || urlInspection === 'overflow') return '[REDACTED]'
  let redacted = value
    .replace(/\b([a-z][a-z0-9+.-]*:\/\/)[^\s/?#]+@/gi, '$1[REDACTED]@')
    .replace(/(^|[^\p{Letter}\p{Number}\p{Mark}\p{Connector_Punctuation}])\/{2}(?!\/)[^\p{White_Space}\uFEFF"'<>/?#]+@/giu, '$1//[REDACTED]@')
  for (const pattern of tokenPatterns) redacted = redacted.replace(pattern, '[REDACTED]')
  return truncateSafeText(unresolvedSecretIndicator.test(redacted) ? '[REDACTED]' : redacted)
}

function sanitize(value: unknown, depth: number, seen: WeakSet<object>): unknown {
  if (typeof value === 'string') return redactSensitiveText(value)
  if (value === null || typeof value === 'boolean' || (typeof value === 'number' && Number.isFinite(value))) return value
  if (typeof value === 'number' || typeof value === 'bigint') return String(value)
  if (typeof value !== 'object') return `[${(typeof value).toUpperCase()}]`
  if (depth >= maxDepth) return '[TRUNCATED]'
  if (seen.has(value)) return '[CIRCULAR]'
  seen.add(value)
  try {
    if (Array.isArray(value)) return value.slice(0, maxCollectionItems).map((item) => sanitize(item, depth + 1, seen))
    const entries: [string, unknown][] = []
    for (const key in value) {
      if (!Object.prototype.hasOwnProperty.call(value, key)) continue
      const index = entries.length
      if (isSensitiveKey(key)) entries.push([`[REDACTED_KEY_${index}]`, '[REDACTED]'])
      else {
        const safeKey = redactSensitiveText(key)
        const item = (value as Record<string, unknown>)[key]
        entries.push([safeKey === '[REDACTED]' ? `[REDACTED_KEY_${index}]` : safeKey, sanitize(item, depth + 1, seen)])
      }
      if (entries.length >= maxCollectionItems) break
    }
    return Object.fromEntries(entries)
  } finally {
    seen.delete(value)
  }
}

export function sanitizeForExport(value: unknown) { return sanitize(value, 0, new WeakSet()) }
export function safeDisplayValue(value: unknown, maxLength = maxStringLength) {
  const sanitized = sanitizeForExport(value)
  return truncateSafeText(typeof sanitized === 'string' ? sanitized : JSON.stringify(sanitized), maxLength)
}
