import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import path from 'node:path'

const sensitiveKeyParts = [
  ['access', 'token'], ['api', 'key'], ['auth', 'token'], ['authorization'],
  ['aws', 'secret', 'access', 'key'], ['aws', 'session', 'token'], ['client', 'secret'],
  ['credential'], ['credentials'], ['id', 'token'], ['passphrase'], ['password'], ['passwd'],
  ['private', 'key'], ['refresh', 'token'], ['secret'], ['seed', 'phrase'],
  ['session', 'token'], ['token'], ['x', 'api', 'key'],
]
const sensitiveKeySeparator = String.raw`[._\-\p{White_Space}\u200B\u200C\uFEFF\x00-\x1F\x7F-\x9F]{0,16}`
const sensitiveKeySource = sensitiveKeyParts.map((parts) => parts.join(sensitiveKeySeparator)).join('|')
const assignmentSpacing = String.raw`[\p{White_Space}\uFEFF\x00-\x1F\x7F-\x9F]{0,16}`
const cliValueSpacing = String.raw`[\p{White_Space}\uFEFF\x00-\x1F\x7F-\x9F]{1,16}`
const privateKeyLabel = String.raw`(?:(?:RSA|EC|OPENSSH|ENCRYPTED|DSA) )?PRIVATE KEY|PGP PRIVATE KEY BLOCK`
const urlUserInfoPattern = /(?:\b(?:https?|ftp):[\\/]{2,}(?!\[REDACTED\]@)[^\s\\/@?#]+@|(?<![\p{Letter}\p{Number}\p{Mark}\p{Connector_Punctuation}/])\/\/(?!\/)(?!\[REDACTED\]@)[^\s/@?#]+@)/giu
const highEntropyNamedSecretPattern = new RegExp(
  String.raw`(?:^|[^\p{Letter}\p{Number}\p{Mark}\p{Connector_Punctuation}])(?:--?)?["']?(?:${sensitiveKeySource})["']?(?:(?:${assignmentSpacing})(?:=|:)(?:${assignmentSpacing})|${cliValueSpacing})["'\x60\u2018\u2019\u201C\u201D]?([A-Za-z0-9_./+=~-]{20,})`,
  'gimu',
)
const legacyNamedSecretShapePattern = new RegExp(
  String.raw`(?:${sensitiveKeySource})${assignmentSpacing}(?:=|:)["']?[A-Za-z0-9_./+=~-]{20,}$`,
  'iu',
)
const maxEncodedUrlDecodeLayers = 3
const maxEncodedUrlInspectionLines = 128
const maxEncodedUrlInspectionCodeUnits = 65_536

const SECRET_PATTERNS = [
  { kind: 'bearer credential', pattern: /\bBearer[ \t]+[A-Za-z0-9._~+/=-]{12,}/giu },
  {
    kind: 'Basic authorization credential',
    pattern: /(?<![\p{Letter}\p{Number}\p{Mark}\p{Connector_Punctuation}-])(?:Proxy-)?Authorization[ \t]{0,16}:[ \t]{0,16}Basic[ \t]{1,16}[A-Za-z0-9+/]{8,}={0,2}(?![A-Za-z0-9+/=])/gimu,
  },
  {
    kind: 'Digest authorization credential',
    pattern: /(?<![\p{Letter}\p{Number}\p{Mark}\p{Connector_Punctuation}-])(?:Proxy-)?Authorization[ \t]{0,16}:[ \t]{0,16}Digest\b[^\r\n]{0,2048}?\bresponse[ \t]{0,16}=[ \t]{0,16}["']?[A-Fa-f0-9]{16,}["']?/gimu,
  },
  { kind: 'JWT-like credential', pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/gu },
  {
    kind: 'private key block',
    pattern: new RegExp(
      String.raw`-----BEGIN (${privateKeyLabel})-----[\s\S]{0,32768}?(?:-----END \1-----|$)|-----BEGIN (?:${privateKeyLabel})-----`,
      'gu',
    ),
  },
  { kind: 'GitHub token', pattern: /\b(?:gh[opsur]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/gu },
  { kind: 'AWS access key ID', pattern: /\b(?:A3T[A-Z0-9]|AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{16}\b/gu },
  { kind: 'OpenAI-style key', pattern: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b/gu },
  { kind: 'Slack token', pattern: /\bxox(?:a|b|p|r|s)-[A-Za-z0-9-]{20,}\b/gu },
  { kind: 'Slack app token', pattern: /\bxapp-[A-Za-z0-9-]{20,}\b/gu },
  { kind: 'Google API key', pattern: /\bAIza[0-9A-Za-z_-]{30,}\b/gu },
  { kind: 'Google OAuth token', pattern: /\bya29\.[A-Za-z0-9_-]{20,}\b/gu },
  { kind: 'OAuth refresh token', pattern: /\b1\/\/[A-Za-z0-9_-]{20,}\b/gu },
  { kind: 'GitLab token', pattern: /\bglpat-[A-Za-z0-9_-]{20,}\b/gu },
  { kind: 'npm token', pattern: /\bnpm_[A-Za-z0-9]{30,}\b/gu },
  { kind: 'PyPI token', pattern: /\bpypi-[A-Za-z0-9_-]{30,}\b/gu },
  { kind: 'Stripe key', pattern: /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b/gu },
  { kind: 'base64 key material', pattern: /\bMII[A-Za-z0-9+/=]{40,}(?![A-Za-z0-9+/=])/gu },
  {
    kind: 'URL userinfo credential',
    pattern: urlUserInfoPattern,
  },
  {
    kind: 'high-entropy named secret',
    pattern: highEntropyNamedSecretPattern,
    entropyGroup: 1,
    minimumEntropy: (match) => (legacyNamedSecretShapePattern.test(match[0]) ? 3 : 4),
  },
]

function parseTripleQuotedArray(block, field) {
  const declaration = new RegExp(`^\\s*${field}\\s*=\\s*\\[`, 'mu').exec(block)
  if (!declaration) return []
  const start = declaration.index + declaration[0].length
  let inTripleQuote = false
  let end = -1
  for (let index = start; index < block.length; index += 1) {
    if (block.startsWith("'''", index)) {
      inTripleQuote = !inTripleQuote
      index += 2
    } else if (block[index] === ']' && !inTripleQuote) {
      end = index
      break
    }
  }
  if (end < 0 || inTripleQuote) throw new Error(`Unterminated ${field} array in .secret-scan-allowlists.toml.`)
  return [...block.slice(start, end).matchAll(/'''([\s\S]*?)'''/gu)].map((match) => match[1])
}

function compile(pattern, label) {
  try {
    return new RegExp(pattern, 'u')
  } catch (error) {
    throw new Error(`Invalid ${label} regular expression in .secret-scan-allowlists.toml: ${error.message}`)
  }
}

export function parseSecretScanAllowlists(text) {
  if (/^\s*\[allowlist\]\s*$/mu.test(text)) {
    throw new Error('Legacy global [allowlist] configuration is forbidden; use match-and-path [[allowlists]].')
  }
  const blocks = text.split(/^\s*\[\[allowlists\]\]\s*$/gmu).slice(1)
  return blocks.map((block, index) => {
    const condition = block.match(/^\s*condition\s*=\s*"([^"]+)"\s*$/mu)?.[1]
    const regexTarget = block.match(/^\s*regexTarget\s*=\s*"([^"]+)"\s*$/mu)?.[1]
    const pathPatterns = parseTripleQuotedArray(block, 'paths')
    const matchPatterns = parseTripleQuotedArray(block, 'regexes')
    const commits = parseTripleQuotedArray(block, 'commits')
    if (condition !== 'AND' || regexTarget !== 'match' || pathPatterns.length === 0 || matchPatterns.length === 0) {
      throw new Error(`Allowlist ${index + 1} must combine non-empty paths and match regexes with condition AND.`)
    }
    if (pathPatterns.some((pattern) => !pattern.startsWith('^') || !pattern.endsWith('$'))) {
      throw new Error(`Allowlist ${index + 1} path expressions must be fully anchored.`)
    }
    if (matchPatterns.some((pattern) => /^(?:\^)?(?:\.\*|\.\+|\[\\s\\S\]\*)(?:\$)?$/u.test(pattern))) {
      throw new Error(`Allowlist ${index + 1} contains an overbroad match expression.`)
    }
    if (/^\s*stopwords\s*=/mu.test(block)) throw new Error(`Allowlist ${index + 1} may not suppress stopwords.`)
    if (commits.some((commit) => !/^[a-f0-9]{40}$/u.test(commit))) {
      throw new Error(`Allowlist ${index + 1} contains a non-full commit identifier.`)
    }
    return {
      paths: pathPatterns.map((pattern) => compile(pattern, 'path allowlist')),
      matches: matchPatterns.map((pattern) => compile(pattern, 'match allowlist')),
      commits: new Set(commits),
    }
  })
}

export function loadSecretScanAllowlists(root) {
  return parseSecretScanAllowlists(
    readFileSync(path.join(root, '.secret-scan-allowlists.toml'), 'utf8'),
  )
}

export function parseSecretHistoryExceptions(text) {
  let document
  try {
    document = JSON.parse(text)
  } catch (error) {
    throw new Error(`Invalid .secret-scan-history.json: ${error.message}`)
  }
  const documentKeys = document && typeof document === 'object' && !Array.isArray(document)
    ? Object.keys(document).sort()
    : []
  if (documentKeys.join('\0') !== ['exceptions', 'version'].join('\0')) {
    throw new Error('.secret-scan-history.json may contain only version and exceptions.')
  }
  if (document?.version !== 1 || !Array.isArray(document.exceptions)) {
    throw new Error('.secret-scan-history.json must declare version 1 and an exceptions array.')
  }

  const knownKinds = new Set(SECRET_PATTERNS.map(({ kind }) => kind))
  const exceptions = document.exceptions.map((exception, index) => {
    const label = `History exception ${index + 1}`
    const expectedKeys = ['commit', 'kind', 'line', 'matchSha256', 'path', 'reason']
    const keys = exception && typeof exception === 'object' && !Array.isArray(exception)
      ? Object.keys(exception).sort()
      : []
    if (keys.join('\0') !== expectedKeys.join('\0')) {
      throw new Error(`${label} must contain only the exact fingerprint fields.`)
    }
    if (typeof exception.commit !== 'string' || !/^[a-f0-9]{40}$/u.test(exception.commit)) {
      throw new Error(`${label} must contain a full lowercase commit identifier.`)
    }
    if (
      typeof exception.path !== 'string'
      || !/^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]+$/u.test(exception.path)
      || exception.path.includes('\\')
    ) {
      throw new Error(`${label} must contain a normalized repository-relative path.`)
    }
    if (typeof exception.kind !== 'string' || !knownKinds.has(exception.kind)) {
      throw new Error(`${label} must name a known secret category.`)
    }
    if (!Number.isInteger(exception.line) || exception.line < 1) {
      throw new Error(`${label} must contain a positive line number.`)
    }
    if (typeof exception.matchSha256 !== 'string' || !/^[a-f0-9]{64}$/u.test(exception.matchSha256)) {
      throw new Error(`${label} must contain a lowercase SHA-256 match digest.`)
    }
    if (typeof exception.reason !== 'string' || !/^\S(?:[^\r\n]*\S)?$/u.test(exception.reason)) {
      throw new Error(`${label} must contain a single-line reason.`)
    }
    return { ...exception }
  })

  const fingerprints = exceptions.map((exception) => (
    `${exception.commit}:${exception.path}:${exception.kind}:${exception.line}:${exception.matchSha256}`
  ))
  if (new Set(fingerprints).size !== fingerprints.length) {
    throw new Error('.secret-scan-history.json contains a duplicate exact fingerprint.')
  }
  return exceptions
}

export function loadSecretHistoryExceptions(root) {
  return parseSecretHistoryExceptions(
    readFileSync(path.join(root, '.secret-scan-history.json'), 'utf8'),
  )
}

export function decodeSecretScanBuffer(value) {
  const buffer = Buffer.isBuffer(value) ? value : Buffer.from(value ?? '', 'utf8')
  return buffer.toString('utf8')
}

function isAllowed(file, value, commit, allowlists) {
  return allowlists.some((allowlist) => (
    allowlist.paths.some((pattern) => pattern.test(file))
    && allowlist.matches.some((pattern) => pattern.test(value))
    && (allowlist.commits.size === 0 || (commit && allowlist.commits.has(commit)))
  ))
}

function isExactHistoryException(file, value, commit, kind, line, historyExceptions) {
  if (!commit) return false
  const candidates = historyExceptions.filter((exception) => (
    exception.commit === commit
    && exception.path === file
    && exception.kind === kind
    && exception.line === line
  ))
  if (candidates.length === 0) return false
  const matchSha256 = createHash('sha256').update(value, 'utf8').digest('hex')
  return candidates.some((exception) => exception.matchSha256 === matchSha256)
}

function lineNumber(text, index) {
  let line = 1
  for (let position = 0; position < index; position += 1) {
    if (text.charCodeAt(position) === 10) line += 1
  }
  return line
}

function shannonEntropy(value) {
  const counts = new Map()
  for (const character of value) counts.set(character, (counts.get(character) ?? 0) + 1)
  let entropy = 0
  for (const count of counts.values()) {
    const probability = count / value.length
    entropy -= probability * Math.log2(probability)
  }
  return entropy
}

function decodePercentLayer(value) {
  if (!/%[0-9A-Fa-f]{2}/u.test(value)) return value
  try {
    return decodeURIComponent(value)
  } catch {
    return value.replace(/(?:%[0-9A-Fa-f]{2})+/gu, (sequence) => {
      try {
        return decodeURIComponent(sequence)
      } catch {
        return sequence.replace(/%([0-9A-Fa-f]{2})/gu, (escape, hex) => {
          const code = Number.parseInt(hex, 16)
          return code <= 0x7f ? String.fromCharCode(code) : escape
        })
      }
    })
  }
}

function urlUserInfoMatches(value) {
  urlUserInfoPattern.lastIndex = 0
  return [...value.matchAll(urlUserInfoPattern)].map((match) => match[0])
}

function rememberDecodedVariants(seen, value) {
  let variant = value
  for (let layer = 0; layer <= maxEncodedUrlDecodeLayers; layer += 1) {
    seen.add(variant)
    const next = decodePercentLayer(variant)
    if (next === variant) break
    variant = next
  }
}

function encodedUrlUserInfoMatches(text) {
  const matches = []
  let inspectedCodeUnits = 0
  let inspectedLines = 0
  let line = 1
  let offset = 0
  while (offset <= text.length) {
    const end = text.indexOf('\n', offset)
    const lineEnd = end < 0 ? text.length : end
    const value = text.slice(offset, lineEnd)
    if (/%[0-9A-Fa-f]{2}/u.test(value)) {
      inspectedLines += 1
      inspectedCodeUnits += value.length
      if (inspectedLines > maxEncodedUrlInspectionLines || inspectedCodeUnits > maxEncodedUrlInspectionCodeUnits) {
        matches.push({ value: '', line, unsuppressible: true })
        break
      }
      const seen = new Set()
      for (const match of urlUserInfoMatches(value)) rememberDecodedVariants(seen, match)
      let decoded = value
      for (let layer = 0; layer < maxEncodedUrlDecodeLayers; layer += 1) {
        const next = decodePercentLayer(decoded)
        if (next === decoded) break
        decoded = next
        for (const match of urlUserInfoMatches(decoded)) {
          if (seen.has(match)) continue
          matches.push({ value: match, line })
          rememberDecodedVariants(seen, match)
        }
      }
      if (decodePercentLayer(decoded) !== decoded) matches.push({ value: '', line, unsuppressible: true })
    }
    if (end < 0) break
    offset = end + 1
    line += 1
  }
  return matches
}

export function findSecretMatches(text, file = '<memory>', options = {}) {
  const matches = []
  const allowlists = options.allowlists ?? []
  const historyExceptions = options.historyExceptions ?? []
  const allowlistPath = options.allowlistPath ?? file
  const commit = options.commit
  for (const { kind, pattern, entropyGroup, minimumEntropy } of SECRET_PATTERNS) {
    pattern.lastIndex = 0
    for (const match of text.matchAll(pattern)) {
      if (entropyGroup) {
        const entropyThreshold = typeof minimumEntropy === 'function' ? minimumEntropy(match) : minimumEntropy
        if (shannonEntropy(match[entropyGroup]) < entropyThreshold) continue
      }
      const line = lineNumber(text, match.index)
      if (isAllowed(allowlistPath, match[0], commit, allowlists)) continue
      if (isExactHistoryException(
        allowlistPath,
        match[0],
        commit,
        kind,
        line,
        historyExceptions,
      )) continue
      matches.push({ file, kind, line })
    }
  }
  for (const match of encodedUrlUserInfoMatches(text)) {
    if (!match.unsuppressible) {
      if (isAllowed(allowlistPath, match.value, commit, allowlists)) continue
      if (isExactHistoryException(
        allowlistPath,
        match.value,
        commit,
        'URL userinfo credential',
        match.line,
        historyExceptions,
      )) continue
    }
    matches.push({ file, kind: 'URL userinfo credential', line: match.line })
  }
  return matches
}

export function formatSecretScanFailure(matches) {
  const files = new Set(matches.map(({ file }) => file)).size
  const kinds = [...new Set(matches.map(({ kind }) => kind))].sort().join(', ')
  return `${matches.length} potential secrets detected in ${files} file/blob location(s); values and paths suppressed. Categories: ${kinds}.`
}
