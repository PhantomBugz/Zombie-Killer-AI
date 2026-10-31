import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { parse } from 'yaml'

import {
  PUBLIC_VERSION,
  checkPublicRepository,
} from './public-repo-checks.mjs'
import {
  decodeSecretScanBuffer,
  findSecretMatches,
  formatSecretScanFailure,
  loadSecretScanAllowlists,
  loadSecretHistoryExceptions,
  parseSecretScanAllowlists,
  parseSecretHistoryExceptions,
} from './secret-scan-lib.mjs'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const supportedNativeRunnerMatrix = ['ubuntu-24.04', 'windows-2025']
const frontendRunnerMatrix = [...supportedNativeRunnerMatrix, 'macos-15']

const unixHarnessManifest = 'apps/desktop/src-tauri/build_support/unix-test-harness/Cargo.toml'
const unixHarnessCommands = [
  `cargo fmt --manifest-path ${unixHarnessManifest} --check`,
  `cargo clippy --locked --manifest-path ${unixHarnessManifest} --all-targets -- -D warnings`,
  `cargo test --locked --manifest-path ${unixHarnessManifest}`,
]

function assertNativeUnixHarnessPolicy(text) {
  const workflow = parse(text)
  assert.deepEqual(
    workflow?.jobs?.native?.strategy?.matrix?.os,
    supportedNativeRunnerMatrix,
    'native-build.yml must retain the supported Linux and Windows runner matrix',
  )
  const steps = workflow?.jobs?.native?.steps
  assert.ok(Array.isArray(steps), 'native-build.yml must define the native job steps')
  const mainRustIndex = steps.findIndex((step) => step?.name === 'Verify Rust')
  const harnessIndex = steps.findIndex((step) => step?.name === 'Verify Unix recovery harness')
  assert.ok(mainRustIndex >= 0, 'native-build.yml must retain the main Rust verification step')
  assert.ok(harnessIndex > mainRustIndex, 'Unix harness verification must run after main Rust verification')
  const harnessStep = steps[harnessIndex]
  assert.equal(harnessStep.if, "runner.os != 'Windows'", 'Unix harness verification must be excluded only on Windows')
  assert.deepEqual(
    harnessStep.run.trim().split(/\r?\n/u).map((line) => line.trim()),
    unixHarnessCommands,
    'Unix harness verification must run the exact locked fmt, clippy, and test commands',
  )
}

function assertHostedWindowsSourceGatePolicy(text) {
  // The runner chooses .ps1 from the first shell word; Python would create .py.
  const ownerShell = "pwsh -NoProfile -Command \"python -I scripts/ci_windows_owner.py -- pwsh -NoProfile -File '{0}'; exit $LASTEXITCODE\""
  const steps = parse(text)?.jobs?.native?.steps
  assert.ok(Array.isArray(steps), 'native-build.yml must define native verification steps')
  const named = (name) => steps.find((step) => step?.name === name)
  const position = (name) => steps.findIndex((step) => step?.name === name)
  assert.equal(named('Check out source')?.with?.['fetch-depth'], 0, 'Windows source gate requires complete Git history')

  const gate = named('Run full Windows source release gate')
  assert.ok(gate, 'Windows must run the full source release gate')
  assert.equal(gate.if, "runner.os == 'Windows'")
  assert.equal(gate.shell, ownerShell)
  assert.equal(gate.env?.ZK_DISPOSABLE_WINDOWS_PROFILE, '1')
  assert.match(gate.run, /\$env:RUNNER_ENVIRONMENT -ne 'github-hosted'/u)
  assert.match(gate.run, /(?:^|\n)\s*pnpm verify(?:\r?\n|$)/u, 'Windows gate must invoke verifier through pnpm')
  assert.doesNotMatch(gate.run, /pwsh -NoProfile -File scripts\/verify\.ps1/u)
  assert.match(gate.run, /if \(\$LASTEXITCODE -ne 0\) \{ exit \$LASTEXITCODE \}/u)
  assert.doesNotMatch(gate.run, /-Skip[A-Za-z]+|-AllowDirty/u)
  assert.ok(position('Install exact dependencies') < position(gate.name))

  for (const name of [
    'Verify Rust',
    'Verify portable launcher Rust',
    'Build unsigned native executable',
    'Package complete unsigned native verification archive',
  ]) {
    assert.equal(named(name)?.if, "runner.os != 'Windows'", `${name} must not duplicate the Windows source gate`)
  }
  const windowsPackage = named('Package verified Windows native artifact')
  assert.equal(windowsPackage?.if, "runner.os == 'Windows'")
  assert.match(windowsPackage.run, /scripts\/package-native-artifact\.py/u)
  assert.match(windowsPackage.run, /Get-FileHash/u)
  assert.match(windowsPackage.run, /SHA256SUMS/u)
  assert.ok(position(gate.name) < position(windowsPackage.name))
  assert.ok(position(windowsPackage.name) < position('Verify unsigned portable Windows executable'))
  for (const name of [
    'Package verified Windows native artifact',
    'Verify portable builder and smoke helpers',
    'Smoke test the extracted Windows native archive',
    'Verify unsigned portable Windows executable',
  ]) {
    const step = named(name)
    assert.equal(step?.shell, ownerShell, `${name} must run with the token user's default owner`)
    assert.match(step.run, /^\s*\$ErrorActionPreference = 'Stop'/u)
  }
  const portable = named('Verify unsigned portable Windows executable')
  assert.equal(portable?.if, "runner.os == 'Windows'")
  assert.match(portable.run, /scripts\/build-portable-exe\.py/u)
  assert.match(portable.run, /scripts\/portable-smoke\.ps1/u)
  assert.match(portable.run, /-ExpectedPayloadSha256/u)
  assert.match(portable.run, /state_removed/u)
  const upload = named('Upload native SBOM verification evidence')
  assert.ok(upload, 'native verification must retain SBOM evidence')
  assert.equal(upload.with.name, 'native-sbom-${{ runner.os }}-${{ runner.arch }}')
  assert.equal(upload.with.path, 'artifacts/sbom/**', 'native CI must upload SBOMs only')
  assert.equal(upload.with['if-no-files-found'], 'error')
  assert.deepEqual(
    steps.filter((step) => step?.uses?.startsWith('actions/upload-artifact@')),
    [upload],
    'native CI must not have another artifact upload step',
  )
  const archiveSmoke = named('Smoke test the extracted Windows native archive')
  assert.ok(archiveSmoke, 'the runner-local Windows ZIP must be smoked after extraction')
  assert.equal(archiveSmoke.if, "runner.os == 'Windows'")
  assert.equal(archiveSmoke.env?.ZK_DISPOSABLE_WINDOWS_PROFILE, '1')
  assert.match(archiveSmoke.run, /RUNNER_ENVIRONMENT -ne 'github-hosted'/u)
  assert.match(archiveSmoke.run, /Expand-Archive/u)
  assert.match(archiveSmoke.run, /Start Zombie Killer\.cmd/u)
  assert.match(archiveSmoke.run, /scripts\/native-smoke\.ps1/u)
  assert.ok(position(windowsPackage.name) < position(archiveSmoke.name))
  assert.ok(position(archiveSmoke.name) < position(portable.name))
  assert.ok(position(portable.name) < position('Generate lock and sidecar file-inventory SBOMs'))
  assert.ok(position('Generate lock and sidecar file-inventory SBOMs') < position(upload.name))
}

function assertCargoDependabotPolicy(text) {
  const configuration = parse(text)
  const cargoUpdates = configuration?.updates?.filter((update) => update?.['package-ecosystem'] === 'cargo')
  assert.ok(Array.isArray(cargoUpdates), 'dependabot.yml must define Cargo updates')
  assert.deepEqual(
    cargoUpdates.map((update) => update.directory).sort(),
    [
      '/apps/desktop/src-tauri',
      '/apps/desktop/src-tauri/build_support/unix-test-harness',
    ],
    'Dependabot must cover exactly the main and standalone Unix-harness Cargo workspaces',
  )
  for (const update of cargoUpdates) {
    assert.equal(update.schedule?.interval, 'weekly')
    assert.equal(update['open-pull-requests-limit'], 5)
    assert.deepEqual(update.groups, { rust: { patterns: ['*'] } })
  }
}

assert.equal(PUBLIC_VERSION, '0.1.0-alpha.1')
const packageManifest = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8'))
assert.equal(
  packageManifest.scripts?.verify,
  'pwsh -NoProfile -File scripts/verify.ps1',
  'pnpm verify must delegate to the exact unskipped source gate',
)

const ciWorkflow = readFileSync(path.join(root, '.github/workflows/ci.yml'), 'utf8')
const ciJobs = parse(ciWorkflow)?.jobs
assert.deepEqual(
  ciJobs?.python?.strategy?.matrix?.os,
  supportedNativeRunnerMatrix,
  'full Python qualification must run on supported Linux and Windows platforms',
)
assert.deepEqual(
  ciJobs?.frontend?.strategy?.matrix?.os,
  frontendRunnerMatrix,
  'frontend checks may also run on experimental macOS',
)
const macosScanJob = ciJobs?.['macos-scan']
assert.equal(macosScanJob?.['runs-on'], 'macos-15', 'macOS scanner scope must run on a hosted macOS runner')
assert.equal(macosScanJob?.['continue-on-error'], undefined, 'macOS scanner failures must fail CI')
const macosScanSteps = macosScanJob?.steps
assert.ok(Array.isArray(macosScanSteps), 'macOS scanner scope must define steps')
assert.ok(macosScanSteps.some((step) => step?.run === 'uv sync --frozen'), 'macOS scanner scope must sync the exact Python lock')
assert.ok(
  macosScanSteps.some((step) => step?.run === 'uv run pytest services/engine/tests/test_scanner.py -q'),
  'macOS scanner scope must run the real scanner test module without exclusions',
)
const windowsPythonTests = ciJobs?.python?.steps?.find(
  (step) => step?.name === 'Test engine, SDK, and release helpers on Windows',
)
assert.equal(windowsPythonTests?.if, "runner.os == 'Windows'")
assert.equal(
  windowsPythonTests?.shell,
  "pwsh -NoProfile -Command \"python -I scripts/ci_windows_owner.py -- pwsh -NoProfile -File '{0}'; exit $LASTEXITCODE\"",
)
assert.match(windowsPythonTests.run, /^\s*\$ErrorActionPreference = 'Stop'/u)
assert.match(ciWorkflow, /pytest services\/engine\/tests packages\/sdk-python\/tests packages\/protocol\/tests scripts\/tests -q/u)
assert.match(ciWorkflow, /ruff check services\/engine packages\/sdk-python packages\/protocol\/tests scripts/u)
const pythonSteps = parse(ciWorkflow)?.jobs?.python?.steps ?? []
const linuxStaticStep = pythonSteps.find((step) => step.name === 'Static Python checks')
assert.equal(linuxStaticStep?.if, "matrix.os == 'ubuntu-24.04' && matrix.python == '3.12'")
assert.match(
  linuxStaticStep?.run ?? '',
  /mypy scripts\/package-native-artifact\.py scripts\/collect-sidecar-legal\.py scripts\/python_package_artifacts\.py/u,
)
const windowsMypyStep = pythonSteps.find((step) => step.name === 'Type-check Windows source and release tooling')
assert.equal(windowsMypyStep?.if, "matrix.os == 'windows-2025' && matrix.python == '3.12'")
assert.match(
  windowsMypyStep?.run ?? '',
  /mypy services\/engine\/src packages\/sdk-python\/src scripts\/package-native-artifact\.py scripts\/collect-sidecar-legal\.py scripts\/python_package_artifacts\.py scripts\/tests/u,
)
assert.match(ciWorkflow, /python scripts\/python_package_artifacts\.py --dist dist/u)

const nativeWorkflow = readFileSync(path.join(root, '.github/workflows/native-build.yml'), 'utf8')
assertNativeUnixHarnessPolicy(nativeWorkflow)
assertHostedWindowsSourceGatePolicy(nativeWorkflow)
assert.throws(
  () => assertHostedWindowsSourceGatePolicy(nativeWorkflow.replace('fetch-depth: 0', 'fetch-depth: 1')),
  /complete Git history/u,
)
assert.throws(
  () => assertNativeUnixHarnessPolicy(nativeWorkflow.replace(unixHarnessCommands[1], '')),
  /exact locked fmt, clippy, and test commands/u,
)
assert.throws(
  () => assertNativeUnixHarnessPolicy(nativeWorkflow.replace(
    "      - name: Verify Unix recovery harness\n        if: runner.os != 'Windows'",
    "      - name: Verify Unix recovery harness\n        if: runner.os == 'Linux'",
  )),
  /excluded only on Windows/u,
)
assert.throws(
  () => assertNativeUnixHarnessPolicy(nativeWorkflow.replace('          - ubuntu-24.04\n', '')),
  /supported Linux and Windows runner matrix/u,
)

const codeqlJob = parse(readFileSync(path.join(root, '.github/workflows/codeql.yml'), 'utf8'))?.jobs?.analyze
assert.equal(
  codeqlJob?.if,
  'github.event.repository.private == false',
  'CodeQL must wait for public repository visibility when private code scanning is unavailable',
)
assert.equal(codeqlJob?.permissions?.actions, 'read', 'CodeQL must read workflow-run metadata')
assert.equal(codeqlJob?.permissions?.['security-events'], 'write', 'CodeQL must upload public code scanning results')

const dependencyReviewJob = parse(readFileSync(path.join(root, '.github/workflows/dependency-review.yml'), 'utf8'))?.jobs?.review
assert.equal(
  dependencyReviewJob?.if,
  'github.event.repository.private == false',
  'Dependency review must wait for public repository visibility when private dependency review is unavailable',
)

const dependabot = readFileSync(path.join(root, '.github/dependabot.yml'), 'utf8')
assertCargoDependabotPolicy(dependabot)
const dependabotWithoutHarness = dependabot.replace(
  /\n  - package-ecosystem: cargo\n    directory: \/apps\/desktop\/src-tauri\/build_support\/unix-test-harness[\s\S]*?(?=\n  - package-ecosystem:|\s*$)/u,
  '',
)
assert.throws(
  () => assertCargoDependabotPolicy(dependabotWithoutHarness),
  /exactly the main and standalone Unix-harness Cargo workspaces/u,
)

const secretFixture = [
  'safe line',
  'Authorization: ' + ['Bear', 'er '].join('') + 'abcdefghijklmnopqrstuvwxyz0123456789',
  'to' + 'ken=' + ['eyJhbGciOiJIUzI1NiJ9', 'eyJzdWIiOiJmaXh0dXJlIn0', 'signaturefixture123456'].join('.'),
  'aws=' + ['AKIA', 'ABCDEFGHIJKLMNOP'].join(''),
  'openai=' + ['sk-proj-', 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJK'].join(''),
  'slack=' + ['xoxb-', '123456789012-', 'abcdefghijklmnopqrstuvwxyz'].join(''),
  'google=' + ['AIzaSy', 'abcdefghijklmnopqrstuvwxyz1234567'].join(''),
  'gitlab=' + ['glpat-', 'abcdefghijklmnopqrst'].join(''),
  'npm=' + ['npm_', 'abcdefghijklmnopqrstuvwxyz0123456789'].join(''),
  'url=https://' + ['fixture-user', 'fixture-password'].join(':') + '@example.invalid/path',
  'client_secret=' + ['fixture-', 'named-secret-value-123456789'].join(''),
  ['-----BEGIN ', 'PRIVATE KEY-----'].join(''),
].join('\n')
const secretMatches = findSecretMatches(secretFixture, 'fixture.txt')
assert.equal(secretMatches.length, 12)
const safeFailure = formatSecretScanFailure(secretMatches)
assert.match(safeFailure, /12 potential secrets/)
assert.doesNotMatch(safeFailure, /abcdefghijklmnopqrstuvwxyz/)
assert.doesNotMatch(safeFailure, /eyJhbGci/)
assert.doesNotMatch(safeFailure, /fixture-password/)

const urlFixtureUser = ['fixture', 'user'].join('-')
const urlFixturePassword = ['fixture', 'password'].join('-')
const urlUserInfoFixtures = [
  ['http:', '', `${urlFixtureUser}@example.invalid`, 'safe'].join('/'),
  ['https:', '', `${urlFixtureUser}@example.invalid`, 'safe'].join('/'),
  ['ftp:', '', `${urlFixtureUser}@files.example.invalid`, 'pub'].join('/'),
  ['', '', `${urlFixtureUser}@example.invalid`, 'safe'].join('/'),
  ['https:', '', `${urlFixtureUser}:${urlFixturePassword}@example.invalid`, 'safe'].join('/'),
  ['', '', `${urlFixtureUser}:${urlFixturePassword}@example.invalid`, 'safe'].join('/'),
]
assert.deepEqual(
  urlUserInfoFixtures.map((value) => findSecretMatches(value, 'url-userinfo-fixture.txt').map(({ kind }) => kind)),
  urlUserInfoFixtures.map(() => ['URL userinfo credential']),
)
const safeUrlAndEmailFixtures = [
  `${urlFixtureUser}@example.invalid`,
  `Contact ${urlFixtureUser}@example.invalid for support`,
  ['http:', '', 'example.invalid', 'safe'].join('/'),
  ['https:', '', 'example.invalid', 'safe'].join('/'),
  ['ftp:', '', 'files.example.invalid', 'pub'].join('/'),
  ['', '', 'example.invalid', 'safe'].join('/'),
  ['https:', '', '[REDACTED]@example.invalid', 'safe'].join('/'),
  ['', '', '[REDACTED]@example.invalid', 'safe'].join('/'),
  ['https:', '', `example.invalid?contact=${urlFixtureUser}@mail.example.invalid`].join('/'),
  ['', '', `example.invalid#contact=${urlFixtureUser}@mail.example.invalid`].join('/'),
  ['', '', ` ${urlFixtureUser}@example.invalid is a comment owner`].join('/'),
  ['', '', `TODO: contact ${urlFixtureUser}@example.invalid`].join('/'),
  'const ratio = 1 // 2',
  'source//owner@example.test/branch',
  'ratio//owner@example.test/value',
  ['https:', '', 'example.test', 'a', '', 'release@example.test', 'b'].join('/'),
]
for (const value of safeUrlAndEmailFixtures) assert.equal(findSecretMatches(value, 'safe-url-fixture.txt').length, 0)
const userInfoFailure = formatSecretScanFailure(findSecretMatches(urlUserInfoFixtures.join('\n'), 'url-userinfo-fixture.txt'))
assert.match(userInfoFailure, /values and paths suppressed/u)
assert.doesNotMatch(userInfoFailure, new RegExp(urlFixtureUser, 'u'))
assert.doesNotMatch(userInfoFailure, new RegExp(urlFixturePassword, 'u'))

const longUrlUserInfoFixtures = [386, 512, 4096].map((length) => (
  ['https:', '', `${'u'.repeat(length)}:${urlFixturePassword}@example.invalid`, 'safe'].join('/')
))
for (const value of longUrlUserInfoFixtures) {
  assert.deepEqual(findSecretMatches(value, 'long-url-userinfo-fixture.txt').map(({ kind }) => kind), ['URL userinfo credential'])
}
const encodeLayers = (value, layers) => {
  let encoded = value
  for (let layer = 0; layer < layers; layer += 1) encoded = encodeURIComponent(encoded)
  return encoded
}
const nestedCredentialUrls = [
  ['https:', '', `${urlFixtureUser}:${urlFixturePassword}@inner.example.invalid`, 'safe'].join('/'),
  ['', '', `${urlFixtureUser}:${urlFixturePassword}@inner.example.invalid`, 'safe'].join('/'),
  ['https:', '', `${urlFixtureUser}@realm:${urlFixturePassword}@inner.example.invalid`, 'safe'].join('/'),
  ['', '', `:${urlFixturePassword}@inner.example.invalid`, 'safe'].join('/'),
]
for (const inner of nestedCredentialUrls) {
  for (const layers of [0, 1, 2, 3]) {
    const value = `${['https:', '', 'outer.example.invalid', 'safe'].join('/')}?next=${encodeLayers(inner, layers)}`
    assert.deepEqual(findSecretMatches(value, 'encoded-url-userinfo-fixture.txt').map(({ kind }) => kind), ['URL userinfo credential'])
  }
}
const safeEncodedUrlFixtures = [
  ['https:', '', 'inner.example.invalid', 'safe'].join('/'),
  ['', '', 'cdn.example.invalid', 'asset.js'].join('/'),
  `${urlFixtureUser}@example.invalid`,
]
for (const inner of safeEncodedUrlFixtures) {
  for (const layers of [0, 1, 2, 3]) {
    const value = `${['https:', '', 'outer.example.invalid', 'safe'].join('/')}?next=${encodeLayers(inner, layers)}`
    assert.equal(findSecretMatches(value, 'safe-encoded-url-fixture.txt').length, 0)
  }
}
const collisionAllowlists = loadSecretScanAllowlists(root)
const allowedRawUserInfo = ['https:', '', `${urlFixtureUser}:${urlFixturePassword}@example.invalid`, 'safe'].join('/')
const opaqueUser = ['opaque', 'user'].join('-')
const opaquePassword = ['opaque', 'password'].join('-')
const unallowedRawUserInfo = ['https:', '', `${opaqueUser}:${opaquePassword}@outside.invalid`, 'safe'].join('/')
const encodedAllowedUserInfo = encodeURIComponent(allowedRawUserInfo)
const encodedUnallowedUserInfo = encodeURIComponent(unallowedRawUserInfo)
const collisionPath = 'scripts/test-public-repo.mjs'
for (const value of [
  `${allowedRawUserInfo} ${encodedUnallowedUserInfo}`,
  `${encodedAllowedUserInfo} ${encodedUnallowedUserInfo}`,
  `${encodedUnallowedUserInfo} ${encodedAllowedUserInfo}`,
]) {
  assert.deepEqual(
    findSecretMatches(value, collisionPath, { allowlists: collisionAllowlists }).map(({ kind }) => kind),
    ['URL userinfo credential'],
  )
}
const overflowFixtures = [
  `fixture ${encodeLayers(unallowedRawUserInfo, 4)}`,
  `fixture ${'%41'.repeat(22_000)} ${encodedUnallowedUserInfo}`,
  `${Array.from({ length: 129 }, (_, index) => `fixture-${index}-%41`).join('\n')}\n${encodedUnallowedUserInfo}`,
]
for (const value of overflowFixtures) {
  const matches = findSecretMatches(value, collisionPath, { allowlists: collisionAllowlists })
  assert.ok(matches.some(({ kind }) => kind === 'URL userinfo credential'))
  const failure = formatSecretScanFailure(matches)
  assert.match(failure, /values and paths suppressed/u)
  assert.doesNotMatch(failure, new RegExp(opaquePassword, 'u'))
}
const schemeFreeTripleSlash = ['', '', '', `${urlFixtureUser}@example.invalid`, 'safe'].join('/')
assert.equal(findSecretMatches(schemeFreeTripleSlash, 'triple-slash-fixture.txt').length, 0)
const noncanonicalUserInfo = `${opaqueUser}:${opaquePassword}@outside.invalid/safe`
const noncanonicalSchemeUserInfo = [
  ['https:', '///', noncanonicalUserInfo].join(''),
  ['http:', '////', noncanonicalUserInfo].join(''),
  ['https:', '\\\\', noncanonicalUserInfo].join(''),
  ['https:', '/\\', noncanonicalUserInfo].join(''),
  ['https:', '\\/', noncanonicalUserInfo].join(''),
]
for (const value of noncanonicalSchemeUserInfo) {
  assert.deepEqual(findSecretMatches(value, 'noncanonical-url-userinfo-fixture.txt').map(({ kind }) => kind), ['URL userinfo credential'])
}
for (const value of ['C:\\Users\\fixture-user\\safe.txt', 'D:/Fixture/safe.txt', '\\\\fixture-host\\share\\safe.txt']) {
  assert.equal(findSecretMatches(value, 'windows-path-fixture.txt').length, 0)
}

const privateArmorLabels = ['PRIVATE KEY', 'RSA PRIVATE KEY', 'EC PRIVATE KEY', 'OPENSSH PRIVATE KEY', 'ENCRYPTED PRIVATE KEY', 'DSA PRIVATE KEY', 'PGP PRIVATE KEY BLOCK']
for (const label of privateArmorLabels) {
  const begin = ['-----BEGIN ', `${label}-----`].join('')
  const end = ['-----END ', `${label}-----`].join('')
  for (const value of [[begin, 'synthetic private material'].join('\n'), [begin, 'synthetic private material', end].join('\n')]) {
    assert.deepEqual(findSecretMatches(value, 'private-armor-fixture.txt').map(({ kind }) => kind), ['private key block'])
  }
}
for (const label of ['CERTIFICATE', 'PUBLIC KEY']) {
  const value = [
    ['-----BEGIN ', `${label}-----`].join(''),
    'synthetic public material',
    ['-----END ', `${label}-----`].join(''),
  ].join('\n')
  assert.equal(findSecretMatches(value, 'public-armor-fixture.txt').length, 0)
}
assert.equal(findSecretMatches('Documentation may mention BEGIN PRIVATE KEY without armor.', 'private-key-prose.txt').length, 0)

const namedSecretAliases = [
  ['api', 'key'], ['x', 'api', 'key'], ['auth', 'token'], ['id', 'token'], ['session', 'token'],
  ['aws', 'session', 'token'], ['passphrase'], ['authorization'], ['credential'], ['credentials'], ['seed', 'phrase'],
]
const namedSecretSeparators = ['\t', '\u00a0', '\u2003', '\u200b', '\u200c', '.', '-', '_', ' '.repeat(4), ' '.repeat(16)]
const highEntropyValue = ['Q7vN2mL9xR4pT8wK3cH6sF1zB5dJ0gY', 'Aa9_'].join('')
for (const parts of namedSecretAliases) {
  const separators = parts.length === 1 ? [''] : namedSecretSeparators
  for (const separator of separators) {
    const key = parts.join(separator)
    assert.deepEqual(findSecretMatches(`${key}=${highEntropyValue}`, 'named-secret-fixture.txt').map(({ kind }) => kind), ['high-entropy named secret'])
  }
}
for (const value of [
  `api${' '.repeat(17)}key=${highEntropyValue}`,
  'The API key concept is documented without an assigned value.',
  'tokenizer=enabled passwordless=true credentialed=false',
  `api_key=${'a'.repeat(24)}`,
]) assert.equal(findSecretMatches(value, 'safe-named-secret-fixture.txt').length, 0)

const scannerGrammarFixtures = [
  `"api_key" : "${highEntropyValue}"`,
  `'client_secret'\t=\t'${highEntropyValue}'`,
  `password : \`${highEntropyValue}\``,
  `token = “${highEntropyValue}”`,
  `--api-key ${highEntropyValue}`,
  `client_secret\t${highEntropyValue}`,
]
for (const value of scannerGrammarFixtures) {
  assert.deepEqual(findSecretMatches(value, 'scanner-grammar-fixture.txt').map(({ kind }) => kind), ['high-entropy named secret'])
}
for (const value of [
  '"api_key" is a documented field name',
  '--api-key',
  `api_key${' '.repeat(17)}=${highEntropyValue}`,
  `token${' '.repeat(17)}${highEntropyValue}`,
]) assert.equal(findSecretMatches(value, 'safe-scanner-grammar-fixture.txt').length, 0)

const frontendParityScannerTokens = [
  ['xapp-', '1-demo-', 'Ab3dEf5hIj7kLm9nPq2sTu4w'].join(''),
  ['ya29.', 'Ab3dEf5hIj7kLm9nPq2sTu4w'].join(''),
  ['1', '', 'Ab3dEf5hIj7kLm9nPq2sTu4w'].join('/'),
  ['pk_test_', 'Ab3dEf5hIj7kLm9nPq2s'].join(''),
  ['ghr_', 'Ab3dEf5hIj7kLm9nPq2sTu4wXy6zA8'].join(''),
  ['MII', 'Ab3dEf5hIj7kLm9nPq2sTu4wXy6zA8Bc0dEf2hIj4k'].join(''),
]
for (const value of frontendParityScannerTokens) assert.equal(findSecretMatches(value, 'token-parity-fixture.txt').length, 1)

const basicValue = Buffer.from(`${opaqueUser}:${opaquePassword}`, 'utf8').toString('base64')
const digestResponse = 'a1'.repeat(16)
const authorizationFixtures = [
  `Authorization: Basic ${basicValue}`,
  `Proxy-Authorization:\tBasic ${basicValue}`,
  `Authorization: Digest username="${opaqueUser}", realm="outside", response="${digestResponse}"`,
  `Proxy-Authorization: Digest username="${opaqueUser}", response='${digestResponse}'`,
]
for (const value of authorizationFixtures) assert.equal(findSecretMatches(value, 'authorization-fixture.txt').length, 1)
for (const value of [
  'Authorization schemes include Basic and Digest.',
  'Basic authentication is documented without a credential.',
  `response="${digestResponse}" without a Digest authorization header`,
]) assert.equal(findSecretMatches(value, 'safe-authorization-fixture.txt').length, 0)

const binaryFixture = Buffer.concat([
  Buffer.from([0, 1, 2, 0]),
  Buffer.from('Authorization: ' + ['Bear', 'er '].join('') + 'binaryfixturevalue1234567890', 'utf8'),
])
assert.match(decodeSecretScanBuffer(binaryFixture), /binaryfixturevalue/u)
const oversizedFixture = Buffer.from(
  `${'x'.repeat(2 * 1024 * 1024 + 1)}\nclient_secret=abcdefghijklmnopqrstuvwxyz0123456789ABCD`,
  'utf8',
)
assert.equal(findSecretMatches(decodeSecretScanBuffer(oversizedFixture), 'large.bin').length, 1)

const parsedAllowlists = parseSecretScanAllowlists(`
[[allowlists]]
description = "one exact synthetic match in one exact fixture"
condition = "AND"
regexTarget = "match"
paths = ['''^tests/fixture\\.txt$''']
regexes = ['''^token=synthetic-value-123456789$''']
`)
assert.equal(parsedAllowlists.length, 1)
assert.equal(
  findSecretMatches('token=synthetic-value-123456789', 'tests/fixture.txt', { allowlists: parsedAllowlists }).length,
  0,
)
assert.equal(
  findSecretMatches('token=synthetic-value-123456789', 'src/production.txt', { allowlists: parsedAllowlists }).length,
  1,
)

const repositoryAllowlists = loadSecretScanAllowlists(root)
assert.equal(repositoryAllowlists.length, 1)
assert.equal(repositoryAllowlists[0].commits.size, 0)
const gitleaksConfig = readFileSync(path.join(root, '.gitleaks.toml'), 'utf8')
assert.equal(
  /^\s*\[\[allowlists\]\]\s*$/mu.test(gitleaksConfig),
  false,
  'Gitleaks must not contain global allowlists that can prefilter entire paths.',
)
assert.equal(/^\s*paths\s*=/mu.test(gitleaksConfig), false)
const randomCliSecret = ['to', 'ken='].join('') + 'Q7vN2mL9xR4pT8wK3cH6sF1zB5dJ0gY'
assert.equal(
  findSecretMatches(randomCliSecret, 'services/engine/tests/test_cli.py', {
    allowlists: repositoryAllowlists,
  }).length,
  1,
)

const actionHistoryJwt = [
  'eyJhbGciOiJIUzI1NiJ9',
  'eyJzdWIiOiJzeW50aGV0aWMtdGVzdCJ9',
  'syntheticSignatureSegment789',
].join('.')
const actionHistoryCommit = '1'.repeat(40)
const actionHistoryExceptions = parseSecretHistoryExceptions(JSON.stringify({
  version: 1,
  exceptions: [{
    commit: actionHistoryCommit,
    path: 'services/engine/tests/test_actions.py',
    kind: 'JWT-like credential',
    line: 2,
    matchSha256: createHash('sha256').update(actionHistoryJwt, 'utf8').digest('hex'),
    reason: 'Synthetic unit-test fixture.',
  }],
}))
assert.throws(
  () => parseSecretHistoryExceptions(JSON.stringify({ version: 1, exceptions: [], unexpected: true })),
  /only version and exceptions/u,
)
const lineTwoActionHistoryJwt = `safe line\n${actionHistoryJwt}`
assert.equal(findSecretMatches(lineTwoActionHistoryJwt, 'old:test_actions.py', {
  historyExceptions: actionHistoryExceptions,
  allowlistPath: 'services/engine/tests/test_actions.py',
  commit: actionHistoryCommit,
}).length, 0)
assert.equal(findSecretMatches(lineTwoActionHistoryJwt, 'old:test_actions.py', {
  historyExceptions: actionHistoryExceptions,
  allowlistPath: 'services/engine/tests/test_actions.py',
  commit: 'ffffffffffffffffffffffffffffffffffffffff',
}).length, 1)
assert.equal(findSecretMatches(lineTwoActionHistoryJwt, 'old:src/actions.py', {
  historyExceptions: actionHistoryExceptions,
  allowlistPath: 'services/engine/src/zombie_killer_engine/actions.py',
  commit: actionHistoryCommit,
}).length, 1)
const differentActionHistorySecret = ['Bea', 'rer ', 'Q7vN2mL9xR4pT8wK3cH6sF1zB5dJ0gY'].join('')
assert.equal(findSecretMatches(`safe line\n${differentActionHistorySecret}`, 'old:test_actions.py', {
  historyExceptions: actionHistoryExceptions,
  allowlistPath: 'services/engine/tests/test_actions.py',
  commit: actionHistoryCommit,
}).length, 1)
const differentActionHistoryJwt = [
  'eyJhbGciOiJIUzI1NiJ9',
  'eyJzdWIiOiJhbm90aGVyLXN5bnRoZXRpYy10ZXN0In0',
  'differentSyntheticSignature456',
].join('.')
assert.equal(findSecretMatches(`safe line\n${differentActionHistoryJwt}`, 'old:test_actions.py', {
  historyExceptions: actionHistoryExceptions,
  allowlistPath: 'services/engine/tests/test_actions.py',
  commit: actionHistoryCommit,
}).length, 1)
assert.equal(findSecretMatches(actionHistoryJwt, 'old:test_actions.py', {
  historyExceptions: actionHistoryExceptions,
  allowlistPath: 'services/engine/tests/test_actions.py',
  commit: actionHistoryCommit,
}).length, 1)

const repositoryHistoryExceptions = loadSecretHistoryExceptions(root)
assert.equal(repositoryHistoryExceptions.length, 0)

const roadmap = readFileSync(path.join(root, 'ROADMAP.md'), 'utf8')
assert.match(
  roadmap,
  /Keep the verified identity-bound CLI containment path covered by PID-reuse, target-changed, and clean-machine release regression tests\./u,
)
assert.match(
  roadmap,
  /Concurrency and recovery hardening with explicit cooperating-writer limits for JSON and transactional in-place SQLite restore\./u,
)
const changelog = readFileSync(path.join(root, 'CHANGELOG.md'), 'utf8')
assert.match(
  changelog,
  /Short-lived, immutable, process-instance-bound stop plans, including explicit scan-derived PID\/process-instance CLI planning and execution\./u,
)
assert.match(
  changelog,
  /Reviewed SDK-declared resource quarantine and exact Graveyard restore through the default service, desktop, and finite CLI, with legacy restore-only recovery\./u,
)
assert.match(
  changelog,
  /Explicit local source registration, backup-first JSON\/JSONL and constrained SQLite scalar repair, snapshot history, and planned restore across separate engine invocations\./u,
)
assert.match(
  changelog,
  /This alpha source tree does not certify a signed installer, package-registry publication, or clean-machine\/platform release approval; those are separate release decisions\./u,
)
const readme = readFileSync(path.join(root, 'README.md'), 'utf8')
const contributing = readFileSync(path.join(root, 'CONTRIBUTING.md'), 'utf8')
for (const [name, document] of [['README.md', readme], ['CONTRIBUTING.md', contributing]]) {
  assert.match(document, /PowerShell 7 or newer \(`pwsh`\)/u, `${name} must document the pwsh prerequisite`)
}

const trackedLockfiles = [
  'pnpm-lock.yaml',
  'uv.lock',
  'apps/desktop/src-tauri/Cargo.lock',
  'apps/desktop/src-tauri/build_support/unix-test-harness/Cargo.lock',
  'tools/portable-launcher/Cargo.lock',
]
for (const file of ['THIRD_PARTY_NOTICES.md', 'docs/release-verification.md']) {
  const document = readFileSync(path.join(root, file), 'utf8')
  for (const lockfile of trackedLockfiles) {
    assert.ok(document.includes(`\`${lockfile}\``), `${file} must name tracked lockfile ${lockfile}`)
  }
}

const historicalAllowlist = parseSecretScanAllowlists(`
[[allowlists]]
description = "one historical fixture match"
condition = "AND"
regexTarget = "match"
commits = ['''0123456789abcdef0123456789abcdef01234567''']
paths = ['''^tests/history\\.txt$''']
regexes = ['''^token=synthetic-history-value-123456789$''']
`)
assert.equal(
  findSecretMatches('token=synthetic-history-value-123456789', 'old:tests/history.txt', {
    allowlists: historicalAllowlist,
    allowlistPath: 'tests/history.txt',
    commit: '0123456789abcdef0123456789abcdef01234567',
  }).length,
  0,
)
assert.equal(
  findSecretMatches('token=synthetic-history-value-123456789', 'old:tests/history.txt', {
    allowlists: historicalAllowlist,
    allowlistPath: 'tests/history.txt',
    commit: 'ffffffffffffffffffffffffffffffffffffffff',
  }).length,
  1,
)
assert.throws(() => parseSecretScanAllowlists(`
[[allowlists]]
condition = "AND"
regexTarget = "match"
paths = ['''^tests/fixture\\.txt$''']
regexes = ['''.*''']
`), /overbroad/u)

const brokenRoot = mkdtempSync(path.join(tmpdir(), 'zombie-killer-public-check-'))
try {
  mkdirSync(path.join(brokenRoot, 'docs'), { recursive: true })
  mkdirSync(path.join(brokenRoot, 'services/engine'), { recursive: true })
  mkdirSync(path.join(brokenRoot, 'packages/sdk-python'), { recursive: true })
  writeFileSync(path.join(brokenRoot, 'LICENSE'), 'Apache License\nVersion 2.0, January 2004\n', 'utf8')
  const copiedDesktopNotice = [
    'Zombie Killer',
    'apps/desktop/public/zombie-killer-mark.svg is licensed under CC BY 4.0.',
    'Third-party notices are provided in THIRD_PARTY_NOTICES.md and LICENSES/.',
  ].join('\n')
  writeFileSync(path.join(brokenRoot, 'NOTICE'), copiedDesktopNotice, 'utf8')
  for (const packageRoot of ['services/engine', 'packages/sdk-python']) {
    writeFileSync(path.join(brokenRoot, packageRoot, 'NOTICE'), copiedDesktopNotice, 'utf8')
    writeFileSync(
      path.join(brokenRoot, packageRoot, 'THIRD_PARTY_NOTICES.md'),
      '# Package notices\n\nSee LICENSES/OFL-1.1.txt for bundled desktop fonts.\n',
      'utf8',
    )
    writeFileSync(
      path.join(brokenRoot, packageRoot, 'pyproject.toml'),
      '[project]\nlicense-files = ["LICENSE"]\n',
      'utf8',
    )
  }
  writeFileSync(
    path.join(brokenRoot, 'README.md'),
    '# Fixture\n\n[missing](docs/missing.md)\n\n![remote](https://invalid.example/image.png)\n',
    'utf8',
  )
  writeFileSync(
    path.join(brokenRoot, 'DONATIONS.md'),
    `# Donations\n\n- Solana address: \`${'4'.repeat(44)}\`\n`,
    'utf8',
  )
  const fixtureSettings = 'apps/desktop/src/features/settings/SettingsPage.tsx'
  mkdirSync(path.join(brokenRoot, path.dirname(fixtureSettings)), { recursive: true })
  writeFileSync(
    path.join(brokenRoot, fixtureSettings),
    `const donations = [['replacement', '${'3'.repeat(44)}']] as const\n`,
    'utf8',
  )
  const broken = checkPublicRepository(brokenRoot, {
    trackedFiles: ['README.md', 'DONATIONS.md', fixtureSettings],
  })
  assert.ok(broken.some((issue) => issue.includes('required public file')))
  for (const portableFile of [
    'docs/portable-windows.md',
    'scripts/build-portable-exe.py',
    'scripts/portable-smoke.ps1',
    'tools/portable-launcher/Cargo.toml',
    'tools/portable-launcher/Cargo.lock',
    'tools/portable-launcher/build.rs',
    'tools/portable-launcher/src/main.rs',
    'tools/portable-launcher/src/lib.rs',
  ]) {
    assert.ok(broken.includes(`${portableFile}: missing required public file`))
  }
  assert.ok(broken.some((issue) => issue.includes('broken relative link')))
  assert.ok(broken.some((issue) => issue.includes('remote image')))
  assert.ok(broken.some((issue) => issue.includes('LICENSE: text differs from the approved upstream document')))
  assert.ok(broken.some((issue) => issue.includes('DONATIONS.md: unexpected cryptocurrency address')))
  assert.ok(broken.some((issue) => issue.includes(`${fixtureSettings}: unexpected cryptocurrency address`)))
  assert.ok(broken.some((issue) => issue.includes('services/engine/NOTICE: package NOTICE must be distribution-specific')))
  assert.ok(broken.some((issue) => issue.includes('packages/sdk-python/NOTICE: package NOTICE must be distribution-specific')))
  assert.ok(broken.some((issue) => issue.includes('services/engine/NOTICE: package legal scope references desktop-only assets or licenses')))
  assert.ok(broken.some((issue) => issue.includes('packages/sdk-python/THIRD_PARTY_NOTICES.md: package legal scope references desktop-only assets or licenses')))
  assert.ok(broken.some((issue) => issue.includes('services/engine/pyproject.toml: package legal files must be declared exactly')))
  assert.ok(broken.some((issue) => issue.includes('packages/sdk-python/pyproject.toml: package legal files must be declared exactly')))
} finally {
  rmSync(brokenRoot, { recursive: true, force: true })
}

const repositoryIssues = checkPublicRepository(root)
assert.deepEqual(repositoryIssues, [], repositoryIssues.join('\n'))

console.log('Public repository policy tests passed.')
