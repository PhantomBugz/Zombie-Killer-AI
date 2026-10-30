import { existsSync, lstatSync, readFileSync, readdirSync } from 'node:fs'
import { createHash } from 'node:crypto'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import { parseDocument } from 'yaml'

import {
  findSecretMatches,
  formatSecretScanFailure,
  loadSecretScanAllowlists,
} from './secret-scan-lib.mjs'

export const PUBLIC_VERSION = '0.1.0-alpha.1'
export const PYTHON_VERSION = '0.1.0a1'

export const REQUIRED_PUBLIC_FILES = [
  'README.md',
  'LICENSE',
  'NOTICE',
  'CHANGELOG.md',
  'ROADMAP.md',
  'CONTRIBUTING.md',
  'CODE_OF_CONDUCT.md',
  'SECURITY.md',
  'SUPPORT.md',
  'PRIVACY.md',
  'RESPONSIBLE_USE.md',
  'GOVERNANCE.md',
  'MAINTAINERS.md',
  'TRADEMARKS.md',
  'DONATIONS.md',
  'DCO',
  'THIRD_PARTY_NOTICES.md',
  'CITATION.cff',
  'LICENSES/CC-BY-4.0.txt',
  'LICENSES/OFL-1.1.txt',
  'services/engine/LICENSE',
  'services/engine/NOTICE',
  'services/engine/THIRD_PARTY_NOTICES.md',
  'packages/sdk-python/LICENSE',
  'packages/sdk-python/NOTICE',
  'packages/sdk-python/THIRD_PARTY_NOTICES.md',
  'docs/architecture.md',
  'docs/detection-model.md',
  'docs/cleanup-safety.md',
  'docs/memory-vault.md',
  'docs/native-desktop.md',
  'docs/local-workflows.md',
  'docs/portable-windows.md',
  'docs/sdk.md',
  'docs/release-verification.md',
  'docs/threat-model.md',
  'scripts/verify.ps1',
  'scripts/ci_windows_owner.py',
  'scripts/package-native-artifact.py',
  'scripts/native-smoke.ps1',
  'scripts/build-portable-exe.py',
  'scripts/portable-smoke.ps1',
  'scripts/tests/test_portable_exe.py',
  'scripts/tests/native-smoke.tests.ps1',
  'scripts/tests/portable-smoke.tests.ps1',
  'tools/portable-launcher/Cargo.toml',
  'tools/portable-launcher/Cargo.lock',
  'tools/portable-launcher/build.rs',
  'tools/portable-launcher/src/main.rs',
  'tools/portable-launcher/src/lib.rs',
  'tools/portable-launcher/tests/payload.rs',
  '.github/CODEOWNERS',
  '.github/dependabot.yml',
  '.github/pull_request_template.md',
  '.github/ISSUE_TEMPLATE/bug.yml',
  '.github/ISSUE_TEMPLATE/feature.yml',
  '.github/ISSUE_TEMPLATE/detection.yml',
  '.github/ISSUE_TEMPLATE/config.yml',
  '.github/release.yml',
  '.github/workflows/ci.yml',
  '.github/workflows/codeql.yml',
  '.github/workflows/dependency-review.yml',
  '.github/workflows/secret-scan.yml',
  '.github/workflows/native-build.yml',
  '.github/workflows/release.yml',
  '.gitleaks.toml',
  '.secret-scan-allowlists.toml',
  '.secret-scan-history.json',
]

const ignoredDirectories = new Set([
  '.git',
  '.mypy_cache',
  '.pnpm-store',
  '.pytest_cache',
  '.ruff_cache',
  '.venv',
  '.venv-task7',
  'dist',
  'node_modules',
  'target',
])

const donationAllowedFiles = new Set([
  'DONATIONS.md',
  'apps/desktop/src/features/settings/SettingsPage.tsx',
  'apps/desktop/src/test/settings.test.tsx',
])

const approvedActions = new Map([
  ['actions/checkout', '11d5960a326750d5838078e36cf38b85af677262'],
  ['actions/setup-node', '49933ea5288caeca8642d1e84afbd3f7d6820020'],
  ['actions/setup-python', 'a26af69be951a213d495a4c3e4e4022e16d87065'],
  ['actions/upload-artifact', 'ea165f8d65b6e75b540449e92b4886f43607fa02'],
  ['actions/dependency-review-action', '2031cfc080254a8a887f58cffee85186f0e49e48'],
  ['actions-rust-lang/setup-rust-toolchain', '166cdcfd11aee3cb47222f9ddb555ce30ddb9659'],
  ['github/codeql-action/init', 'c4dd10e44af883a891fe31ced449bcb4a6728b9b'],
  ['github/codeql-action/analyze', 'c4dd10e44af883a891fe31ced449bcb4a6728b9b'],
])

const approvedDocumentHashes = new Map([
  ['LICENSE', 'cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30'],
  ['services/engine/LICENSE', 'cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30'],
  ['packages/sdk-python/LICENSE', 'cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30'],
  ['DCO', 'dac2b0a921aaf4bcaf484dc082fbea072398bedecf5f1d4dcce7e122bbe5d2d5'],
  ['LICENSES/CC-BY-4.0.txt', '9e5f1b3c610b9c2da5c313bf81d577a7d1acec686bdb0384edefa6df0f90cd94'],
  ['LICENSES/OFL-1.1.txt', 'd0283623ef57e722fd0eb688a8041589670c608ab780cd3612d06ba6f153d3fd'],
])

function normalize(relativePath) {
  return relativePath.replaceAll('\\', '/')
}

function sha256(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex')
}

function normalizedDocumentHash(value) {
  const normalized = `${value.replaceAll('\r\n', '\n').replace(/[\r\n]+$/u, '')}\n`
  return sha256(normalized)
}

const expectedDonationHashes = new Set([
  'c4a2ed48e1473b4f583f653883708393e8e119c6ead389d647ec1698b80d81c6',
  '43e806ab375f92682350519ddca47e447f54b5950162f89b351c7e284ac0c15e',
  '7817044eda135fc21aebd14643c1af3eed0a5367a27383b0e6d7a7c52385aa94',
])

function listRepositoryFiles(root) {
  const listed = spawnSync('git', ['ls-files', '--cached', '--others', '--exclude-standard', '-z'], {
    cwd: root,
    encoding: 'utf8',
  })
  if (listed.status === 0) return listed.stdout.split('\0').filter(Boolean).map(normalize)

  const files = []
  const walk = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (entry.isDirectory() && ignoredDirectories.has(entry.name)) continue
      const absolute = path.join(directory, entry.name)
      if (entry.isDirectory()) walk(absolute)
      else if (entry.isFile()) files.push(normalize(path.relative(root, absolute)))
    }
  }
  walk(root)
  return files
}

function readText(root, relativePath) {
  const absolute = path.join(root, relativePath)
  if (!existsSync(absolute) || !lstatSync(absolute).isFile()) return null
  if (lstatSync(absolute).size > 2 * 1024 * 1024) return null
  try {
    return readFileSync(absolute, 'utf8')
  } catch {
    return null
  }
}

function markdownLinks(text) {
  const links = []
  for (const match of text.matchAll(/(!?)\[[^\]]*\]\(([^)\s]+)(?:\s+['"][^'"]*['"])?\)/gu)) {
    links.push({ image: match[1] === '!', target: match[2].replace(/^<|>$/gu, '') })
  }
  for (const match of text.matchAll(/<(?:img|script|iframe|source)\b[^>]*\bsrc=['"]([^'"]+)['"][^>]*>/giu)) {
    links.push({ image: true, target: match[1] })
  }
  return links
}

function checkMarkdownLinks(root, file, text, issues) {
  for (const { image, target } of markdownLinks(text)) {
    if (/^(?:https?:)?\/\//iu.test(target)) {
      if (image) issues.push(`${file}: remote image or executable asset is not allowed (${target})`)
      continue
    }
    if (/^(?:mailto:|tel:|#)/iu.test(target)) continue
    const withoutFragment = target.split('#', 1)[0].split('?', 1)[0]
    if (!withoutFragment) continue
    let decoded
    try {
      decoded = decodeURIComponent(withoutFragment)
    } catch {
      issues.push(`${file}: invalid encoded link (${target})`)
      continue
    }
    const resolved = path.resolve(path.dirname(path.join(root, file)), decoded)
    const rootPrefix = `${path.resolve(root)}${path.sep}`
    if (resolved !== path.resolve(root) && !resolved.startsWith(rootPrefix)) {
      issues.push(`${file}: relative link escapes repository (${target})`)
    } else if (!existsSync(resolved)) {
      issues.push(`${file}: broken relative link (${target})`)
    }
  }
}

function extractDonationCandidates(text, file) {
  const values = new Set()
  for (const match of text.matchAll(/\b0x[a-fA-F0-9]{40}\b/gu)) values.add(match[0])
  for (const match of text.matchAll(/\bbc1q[a-z0-9]{30,70}\b/gu)) values.add(match[0])

  // A base58 token is not inherently a Solana address, so scan every known
  // address everywhere, then scan value-agnostic candidates only where the
  // repository declares or discusses donation addresses. This catches a
  // substituted address without treating arbitrary 43/44-character tokens as
  // wallets.
  for (const match of text.matchAll(/\b[1-9A-HJ-NP-Za-km-z]{43,44}\b/gu)) {
    if (expectedDonationHashes.has(sha256(match[0]))) values.add(match[0])
  }

  const solanaScopes = []
  if (file === 'DONATIONS.md') solanaScopes.push(text)
  if (file === 'apps/desktop/src/features/settings/SettingsPage.tsx') {
    const declaration = text.match(/\bconst\s+donations\s*=\s*\[[\s\S]*?\]\s*as\s+const\b/u)
    if (declaration) solanaScopes.push(declaration[0])
  }
  solanaScopes.push(
    ...text.split(/\r?\n/u).filter((line) => /(?:\bsolana\b|\bSOL\b|donat|wallet|address)/iu.test(line)),
  )
  for (const scope of solanaScopes) {
    for (const match of scope.matchAll(/\b[1-9A-HJ-NP-Za-km-z]{43,44}\b/gu)) values.add(match[0])
  }
  return [...values]
}

function checkWorkflowPolicy(file, text, issues) {
  if (/\bpull_request_target\s*:/u.test(text)) issues.push(`${file}: pull_request_target is forbidden`)
  if (/\$\{\{\s*secrets\./u.test(text)) issues.push(`${file}: workflows must not consume repository secrets`)
  if (!/^permissions:\s*\n\s+contents:\s+read\s*$/mu.test(text)) {
    issues.push(`${file}: default permissions must be contents: read`)
  }
  if (!/^concurrency:\s*$/mu.test(text)) issues.push(`${file}: workflow-level concurrency is required`)
  if (!/^\s+timeout-minutes:\s*\d+\s*$/mu.test(text)) issues.push(`${file}: every workflow needs a bounded job timeout`)
  for (const match of text.matchAll(/^\s*-?\s*uses:\s*([^\s#]+)(?:\s+#\s*(.+))?$/gmu)) {
    const reference = match[1]
    if (reference.startsWith('./')) continue
    if (!/@[a-f0-9]{40}$/u.test(reference)) issues.push(`${file}: action must use a full commit SHA (${reference})`)
    if (!match[2]?.trim()) issues.push(`${file}: pinned action must identify its release tag in a comment (${reference})`)
    const separator = reference.lastIndexOf('@')
    const action = reference.slice(0, separator)
    const revision = reference.slice(separator + 1)
    if (!approvedActions.has(action)) issues.push(`${file}: action is not in the reviewed allowlist (${action})`)
    else if (approvedActions.get(action) !== revision) issues.push(`${file}: action revision differs from the reviewed pin (${action})`)
  }
  if (/actions\/checkout@/u.test(text) && !/persist-credentials:\s*false/u.test(text)) {
    issues.push(`${file}: checkout must set persist-credentials: false`)
  }

  const document = parseDocument(text, { uniqueKeys: true })
  if (document.errors.length) issues.push(`${file}: YAML parser reported ${document.errors.length} error(s)`)
  const parsed = document.toJS()
  if (!parsed || typeof parsed !== 'object' || !parsed.jobs || typeof parsed.jobs !== 'object') {
    issues.push(`${file}: workflow must define jobs`)
  } else {
    for (const [jobName, job] of Object.entries(parsed.jobs)) {
      if (!job || typeof job !== 'object' || !Number.isInteger(job['timeout-minutes'])) {
        issues.push(`${file}: job ${jobName} needs integer timeout-minutes`)
      }
    }
  }
}

function expectContains(root, file, expected, issues) {
  const text = readText(root, file)
  if (text === null) return
  for (const value of expected) {
    if (!text.includes(value)) issues.push(`${file}: missing required text ${JSON.stringify(value)}`)
  }
}

const pythonDistributions = [
  {
    root: 'services/engine',
    noticeText: [
      'Zombie Killer Engine',
      'This Python distribution',
      'LICENSE',
      'THIRD_PARTY_NOTICES.md',
    ],
    thirdPartyText: [
      'declares the following direct runtime dependencies',
      'separate distributions',
      'not a complete transitive dependency or license inventory',
    ],
  },
  {
    root: 'packages/sdk-python',
    noticeText: [
      'Zombie Killer Python SDK',
      'This Python distribution',
      'LICENSE',
      'THIRD_PARTY_NOTICES.md',
    ],
    thirdPartyText: [
      'declares no third-party runtime dependencies',
      'not bundled',
      'not a dependency or license inventory for a development environment',
    ],
  },
]

function checkPythonDistributionLegalScope(root, repositoryNotice, issues) {
  const forbiddenPackageScope = /(?:\bCC BY\b|Creative Commons|\bOFL(?:-1\.1)?\b|LICENSES\/|apps\/desktop\/|docs\/assets\/|BrandMark\.tsx|src-tauri\/)/iu
  const expectedLegalFiles = ['LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.md']

  for (const distribution of pythonDistributions) {
    const noticeFile = `${distribution.root}/NOTICE`
    const thirdPartyFile = `${distribution.root}/THIRD_PARTY_NOTICES.md`
    const pyprojectFile = `${distribution.root}/pyproject.toml`
    const notice = readText(root, noticeFile)
    const thirdParty = readText(root, thirdPartyFile)
    const pyproject = readText(root, pyprojectFile)

    if (repositoryNotice !== null && notice !== null && notice === repositoryNotice) {
      issues.push(`${noticeFile}: package NOTICE must be distribution-specific, not a copy of the repository NOTICE`)
    }
    for (const [file, text] of [[noticeFile, notice], [thirdPartyFile, thirdParty]]) {
      if (text !== null && forbiddenPackageScope.test(text)) {
        issues.push(`${file}: package legal scope references desktop-only assets or licenses`)
      }
    }
    if (notice !== null) {
      for (const required of distribution.noticeText) {
        if (!notice.includes(required)) issues.push(`${noticeFile}: missing package-specific text ${JSON.stringify(required)}`)
      }
    }
    if (thirdParty !== null) {
      for (const required of distribution.thirdPartyText) {
        if (!thirdParty.includes(required)) issues.push(`${thirdPartyFile}: missing package-scope text ${JSON.stringify(required)}`)
      }
    }

    const declaration = pyproject?.match(/^license-files\s*=\s*\[([\s\S]*?)\]\s*$/mu)
    const declaredLegalFiles = declaration
      ? [...declaration[1].matchAll(/"([^"]+)"/gu)].map((match) => match[1])
      : []
    if (JSON.stringify(declaredLegalFiles) !== JSON.stringify(expectedLegalFiles)) {
      issues.push(`${pyprojectFile}: package legal files must be declared exactly as LICENSE, NOTICE, and THIRD_PARTY_NOTICES.md`)
    }
    for (const legalFile of expectedLegalFiles) {
      if (!existsSync(path.join(root, distribution.root, legalFile))) {
        issues.push(`${distribution.root}/${legalFile}: declared package legal file is missing`)
      }
    }
  }
}

export function checkPublicRepository(root, options = {}) {
  const issues = []
  const trackedFiles = (options.trackedFiles ?? listRepositoryFiles(root)).map(normalize)
  const trackedSet = new Set(trackedFiles)
  let secretAllowlists = []
  try {
    secretAllowlists = loadSecretScanAllowlists(root)
  } catch (error) {
    issues.push(`.secret-scan-allowlists.toml: ${error.message}`)
  }

  for (const file of REQUIRED_PUBLIC_FILES) {
    if (!trackedSet.has(file) && !existsSync(path.join(root, file))) issues.push(`${file}: missing required public file`)
  }

  for (const [file, approvedHash] of approvedDocumentHashes) {
    const text = readText(root, file)
    if (text !== null && normalizedDocumentHash(text) !== approvedHash) {
      issues.push(`${file}: text differs from the approved upstream document`)
    }
  }

  expectContains(
    root,
    'README.md',
    ['Made by [PhantomBugz]', 'PhantomBugz.com', 'local-first', 'POSIX', 'defunct', 'alpha', '--process-instance-id'],
    issues,
  )

  const versionExpectations = new Map([
    ['package.json', `"version": "${PUBLIC_VERSION}"`],
    ['pyproject.toml', `version = "${PYTHON_VERSION}"`],
    ['services/engine/pyproject.toml', `version = "${PYTHON_VERSION}"`],
    ['services/engine/src/zombie_killer_engine/service.py', `ENGINE_VERSION = "${PUBLIC_VERSION}"`],
    ['packages/sdk-python/pyproject.toml', `version = "${PYTHON_VERSION}"`],
    ['packages/sdk-python/src/zombie_killer/__init__.py', `__version__ = "${PYTHON_VERSION}"`],
    ['apps/desktop/package.json', `"version": "${PUBLIC_VERSION}"`],
    ['apps/desktop/src-tauri/Cargo.toml', `version = "${PUBLIC_VERSION}"`],
    ['apps/desktop/src-tauri/tauri.conf.json', `"version": "${PUBLIC_VERSION}"`],
    ['apps/desktop/src/features/settings/SettingsPage.tsx', `0.1.0-alpha.1`],
    ['CITATION.cff', `version: ${PUBLIC_VERSION}`],
    ['CHANGELOG.md', `[${PUBLIC_VERSION}]`],
  ])
  for (const [file, expected] of versionExpectations) expectContains(root, file, [expected], issues)

  const donationOccurrences = new Map()
  for (const file of trackedFiles) {
    const text = readText(root, file)
    if (text === null) continue
    if (/0\.1\.0-alpha(?!\.1)/u.test(text)) issues.push(`${file}: stale public prerelease version`)
    if (/\.(?:md|mdx)$/iu.test(file)) checkMarkdownLinks(root, file, text, issues)
    if (file.startsWith('.github/workflows/') && /\.ya?ml$/iu.test(file)) checkWorkflowPolicy(file, text, issues)
    else if (/\.ya?ml$/iu.test(file) || file === 'CITATION.cff') {
      const parsed = parseDocument(text, { uniqueKeys: true })
      if (parsed.errors.length) issues.push(`${file}: YAML parser reported ${parsed.errors.length} error(s)`)
    }
    const matches = findSecretMatches(text, file, { allowlists: secretAllowlists })
    if (matches.length) issues.push(formatSecretScanFailure(matches))
    for (const address of extractDonationCandidates(text, file)) {
      const hash = sha256(address)
      if (!expectedDonationHashes.has(hash)) issues.push(`${file}: unexpected cryptocurrency address`)
      const locations = donationOccurrences.get(hash) ?? []
      locations.push(file)
      donationOccurrences.set(hash, locations)
      if (!donationAllowedFiles.has(file)) issues.push(`${file}: donation address is outside the approved disclosure/UI files`)
    }
  }

  if (existsSync(path.join(root, 'DONATIONS.md'))) {
    for (const expectedHash of expectedDonationHashes) {
      const locations = donationOccurrences.get(expectedHash) ?? []
      if (!locations.includes('DONATIONS.md')) issues.push('DONATIONS.md: one required network address is missing')
      if (!locations.includes('apps/desktop/src/features/settings/SettingsPage.tsx')) {
        issues.push('SettingsPage.tsx: one required network address is missing')
      }
    }
  }

  expectContains(root, 'LICENSE', ['Apache License', 'Version 2.0, January 2004'], issues)
  expectContains(root, 'DCO', ['Developer Certificate of Origin', 'Version 1.1'], issues)
  expectContains(root, 'LICENSES/CC-BY-4.0.txt', ['Attribution 4.0 International'], issues)
  expectContains(root, 'LICENSES/OFL-1.1.txt', ['SIL OPEN FONT LICENSE Version 1.1'], issues)
  expectContains(root, 'CONTRIBUTING.md', ['Signed-off-by:', 'Developer Certificate of Origin'], issues)
  expectContains(root, 'apps/desktop/src/features/settings/SettingsPage.tsx', ['CC BY 4.0'], issues)
  expectContains(root, 'package.json', ['"license": "Apache-2.0"', '"name": "PhantomBugz"', 'PhantomBugz/Zombie-Killer-AI'], issues)
  expectContains(root, 'apps/desktop/package.json', ['"license": "Apache-2.0"', '"name": "PhantomBugz"', 'PhantomBugz/Zombie-Killer-AI'], issues)
  expectContains(root, 'pyproject.toml', ['license = "Apache-2.0"', 'authors = [{ name = "PhantomBugz" }]', 'PhantomBugz/Zombie-Killer-AI'], issues)
  expectContains(root, 'services/engine/pyproject.toml', ['license = "Apache-2.0"', 'authors = [{ name = "PhantomBugz" }]', 'PhantomBugz/Zombie-Killer-AI'], issues)
  expectContains(root, 'packages/sdk-python/pyproject.toml', ['license = "Apache-2.0"', 'authors = [{ name = "PhantomBugz" }]', 'PhantomBugz/Zombie-Killer-AI'], issues)
  expectContains(root, 'apps/desktop/src-tauri/tauri.conf.json', ['icons/icon.icns', '"copyright": "Copyright 2026 PhantomBugz"'], issues)
  expectContains(root, 'apps/desktop/src-tauri/Cargo.toml', ['authors = ["PhantomBugz"]', 'license = "Apache-2.0"', 'PhantomBugz/Zombie-Killer-AI'], issues)
  expectContains(root, 'SECURITY.md', ['https://github.com/PhantomBugz/Zombie-Killer-AI/security/advisories/new'], issues)
  expectContains(root, '.gitleaks.toml', ['[extend]', 'useDefault = true'], issues)
  expectContains(root, '.secret-scan-allowlists.toml', ['condition = "AND"', 'regexTarget = "match"'], issues)

  const applicationMark = readText(root, 'apps/desktop/public/zombie-killer-mark.svg')
  const documentationMark = readText(root, 'docs/assets/zombie-killer-mark.svg')
  if (applicationMark !== null && documentationMark !== null && applicationMark !== documentationMark) {
    issues.push('docs/assets/zombie-killer-mark.svg: documentation mark must be byte-identical to the attributed application mark')
  }
  checkPythonDistributionLegalScope(root, readText(root, 'NOTICE'), issues)

  return [...new Set(issues)].sort()
}
