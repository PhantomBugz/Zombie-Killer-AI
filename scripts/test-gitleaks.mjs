import { createHash } from 'node:crypto'
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const VERSION = '8.30.1'
const RELEASE_ROOT = `https://github.com/gitleaks/gitleaks/releases/download/v${VERSION}`
const ASSETS = {
  'darwin-arm64': {
    file: `gitleaks_${VERSION}_darwin_arm64.tar.gz`,
    sha256: 'b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5',
  },
  'darwin-x64': {
    file: `gitleaks_${VERSION}_darwin_x64.tar.gz`,
    sha256: 'dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709',
  },
  'linux-arm64': {
    file: `gitleaks_${VERSION}_linux_arm64.tar.gz`,
    sha256: 'e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080',
  },
  'linux-x64': {
    file: `gitleaks_${VERSION}_linux_x64.tar.gz`,
    sha256: '551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb',
  },
  'win32-x64': {
    file: `gitleaks_${VERSION}_windows_x64.zip`,
    sha256: 'd29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e',
  },
}

function invariant(condition, message) {
  if (!condition) throw new Error(message)
}

function run(file, args, cwd) {
  const result = spawnSync(file, args, {
    cwd,
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
    windowsHide: true,
  })
  invariant(result.status === 0, `Pinned Gitleaks test command failed at a redacted boundary (exit ${result.status ?? 'unknown'}).`)
  return result.stdout.trim()
}

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const gitleaksConfig = readFileSync(path.join(root, '.gitleaks.toml'), 'utf8')
invariant(
  !/^\s*\[\[allowlists\]\]\s*$/mu.test(gitleaksConfig) && !/^\s*paths\s*=/mu.test(gitleaksConfig),
  'Gitleaks configuration must not contain global path allowlists.',
)
const asset = ASSETS[`${process.platform}-${process.arch}`]
invariant(asset, `Pinned Gitleaks negative control does not support ${process.platform}-${process.arch}.`)

const temporaryRoot = mkdtempSync(path.join(tmpdir(), 'zombie-killer-gitleaks-'))
try {
  const archivePath = path.join(temporaryRoot, asset.file)
  const response = await fetch(`${RELEASE_ROOT}/${asset.file}`, {
    redirect: 'follow',
    signal: AbortSignal.timeout(60_000),
  })
  invariant(response.ok, `Pinned Gitleaks archive download failed with HTTP ${response.status}.`)
  const archive = Buffer.from(await response.arrayBuffer())
  invariant(
    createHash('sha256').update(archive).digest('hex') === asset.sha256,
    'Pinned Gitleaks archive checksum mismatch.',
  )
  writeFileSync(archivePath, archive, { mode: 0o600 })
  run('tar', ['-xf', archivePath, '-C', temporaryRoot], temporaryRoot)

  const executable = path.join(temporaryRoot, process.platform === 'win32' ? 'gitleaks.exe' : 'gitleaks')
  if (process.platform !== 'win32') chmodSync(executable, 0o700)
  invariant(run(executable, ['version'], temporaryRoot) === VERSION, 'Extracted Gitleaks version is not pinned.')

  const fixtureRoot = path.join(temporaryRoot, 'fixture')
  const formerlyAllowlistedPaths = [
    'apps/desktop/src-tauri/src/engine_tests.rs',
    'apps/desktop/src/test/activity.test.tsx',
    'apps/desktop/src/test/memory.test.tsx',
    'packages/sdk-python/tests/test_lease.py',
    'scripts/test-public-repo.mjs',
    'services/engine/tests/test_actions.py',
    'services/engine/tests/test_cli.py',
    'services/engine/tests/test_protocol.py',
    'services/engine/tests/test_redaction.py',
    'services/engine/tests/test_scanner.py',
    'services/engine/tests/test_sqlite_memory.py',
    'services/engine/tests/test_store.py',
  ]
  const unrelatedCanary = ['AKIA', 'SYNTHETICCONTROL'].join('')
  for (const relativePath of formerlyAllowlistedPaths) {
    const fixtureFile = path.join(fixtureRoot, ...relativePath.split('/'))
    mkdirSync(path.dirname(fixtureFile), { recursive: true })
    writeFileSync(fixtureFile, `aws_access_key_id = "${unrelatedCanary}"\n`, 'utf8')
  }

  const reportPath = path.join(temporaryRoot, 'report.json')
  run(executable, [
    'dir', fixtureRoot,
    '--config', path.join(root, '.gitleaks.toml'),
    '--report-format', 'json',
    '--report-path', reportPath,
    '--redact=100',
    '--no-banner',
    '--no-color',
    '--exit-code', '0',
    '--log-level', 'error',
  ], root)

  const findings = JSON.parse(readFileSync(reportPath, 'utf8'))
  invariant(
    Array.isArray(findings) && findings.length === formerlyAllowlistedPaths.length,
    'Pinned Gitleaks did not detect every formerly allowlisted path.',
  )
  const reportedPaths = new Set()
  for (const finding of findings) {
    invariant(finding.RuleID === 'aws-access-token', 'Pinned Gitleaks reported an unexpected control rule.')
    invariant(finding.Secret === 'REDACTED', 'Pinned Gitleaks report did not fully redact a control value.')
    const normalized = finding.File.replaceAll('\\', '/')
    const matchedPath = formerlyAllowlistedPaths.find((relativePath) => normalized.endsWith(relativePath))
    invariant(matchedPath, 'Pinned Gitleaks reported a control at an unexpected path.')
    reportedPaths.add(matchedPath)
  }
  invariant(reportedPaths.size === formerlyAllowlistedPaths.length, 'Pinned Gitleaks missed a formerly allowlisted path.')
} finally {
  rmSync(temporaryRoot, { recursive: true, force: true })
}

console.log(`Pinned Gitleaks ${VERSION} directory negative control passed with values suppressed.`)
