import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  buildSbomDocuments,
  collectLockInventory,
  serializeSbomDocuments,
  validateSbomDocuments,
} from './generate-sbom.mjs'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const first = buildSbomDocuments(root)
const second = buildSbomDocuments(root)
assert.deepEqual(serializeSbomDocuments(first), serializeSbomDocuments(second), 'SBOM output must be deterministic')

const validationIssues = validateSbomDocuments(first)
assert.deepEqual(validationIssues, [], validationIssues.join('\n'))

const expected = collectLockInventory(root)
assert.ok(expected.length > 0)
const expectedPurls = new Set(expected.map((component) => component.purl))
assert.deepEqual(new Set(first.cyclone.components.filter((item) => item.type === 'library').map((item) => item.purl)), expectedPurls)
assert.deepEqual(
  new Set(first.spdx.packages.slice(1).map((item) => item.externalRefs[0].referenceLocator)),
  expectedPurls,
)
const expectedLockfiles = [
  'pnpm-lock.yaml',
  'uv.lock',
  'apps/desktop/src-tauri/Cargo.lock',
  'apps/desktop/src-tauri/build_support/unix-test-harness/Cargo.lock',
  'tools/portable-launcher/Cargo.lock',
]
assert.equal(first.scope.lockfiles.length, 5)
assert.deepEqual(first.scope.lockfiles.map((lockfile) => lockfile.path), expectedLockfiles)
assert.equal(first.scope.binaryInventoryIncluded, false)

const generated = mkdtempSync(path.join(tmpdir(), 'zombie-killer-sbom-test-'))
try {
  const output = serializeSbomDocuments(first)
  assert.doesNotThrow(() => JSON.parse(output.spdx))
  assert.doesNotThrow(() => JSON.parse(output.cyclone))
  assert.equal(Buffer.compare(Buffer.from(output.spdx), Buffer.from(serializeSbomDocuments(second).spdx)), 0)
  assert.equal(readFileSync(path.join(root, 'LICENSE'), 'utf8').includes('Apache License'), true)

  const sidecarManifest = path.join(generated, 'BUILD-MANIFEST.json')
  writeFileSync(sidecarManifest, `${JSON.stringify({
    format: 'pyinstaller-onedir',
    platform: 'test-platform',
    architecture: 'test-arch',
    python: '3.12.10',
    pyinstaller: '6.18.0',
    entries: [
      { path: 'engine', type: 'file', size: 3, sha256: 'a'.repeat(64) },
      { path: 'relative-link', type: 'symlink', target: 'engine' },
    ],
  }, null, 2)}\n`, 'utf8')
  const binaryDocuments = buildSbomDocuments(root, { sidecarManifestPath: sidecarManifest })
  assert.equal(binaryDocuments.scope.binaryInventoryIncluded, true)
  assert.equal(binaryDocuments.scope.sidecarEntryCount, 2)
  assert.equal(binaryDocuments.spdx.files.length, 2)
  assert.equal(binaryDocuments.cyclone.components.filter((item) => item.type === 'file').length, 2)
  assert.deepEqual(validateSbomDocuments(binaryDocuments), [])

  const incomplete = structuredClone(first)
  incomplete.cyclone.components = incomplete.cyclone.components.slice(1)
  assert.ok(validateSbomDocuments(incomplete).some((issue) => issue.includes('lock inventory')))

  const missingLockfile = structuredClone(first)
  missingLockfile.scope.lockfiles = missingLockfile.scope.lockfiles.slice(0, -1)
  assert.ok(validateSbomDocuments(missingLockfile).some((issue) => issue.includes('five-lockfile inventory contract')))

  const duplicateLockfiles = structuredClone(first)
  duplicateLockfiles.scope.lockfiles = duplicateLockfiles.scope.lockfiles.map(() => duplicateLockfiles.scope.lockfiles[0])
  assert.ok(validateSbomDocuments(duplicateLockfiles).some((issue) => issue.includes('five-lockfile inventory contract')))

  const wrongSchema = structuredClone(first)
  wrongSchema.cyclone.specVersion = '1.5'
  assert.ok(validateSbomDocuments(wrongSchema).some((issue) => issue.includes('CycloneDX 1.6')))
} finally {
  rmSync(generated, { recursive: true, force: true })
}

console.log(`SBOM policy tests passed for ${expected.length} locked components.`)
