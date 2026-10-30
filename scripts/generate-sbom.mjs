import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

import { parse } from 'yaml'

const modulePath = fileURLToPath(import.meta.url)
const defaultRoot = path.resolve(path.dirname(modulePath), '..')
const LOCKFILES = [
  { path: 'pnpm-lock.yaml', ecosystem: 'npm' },
  { path: 'uv.lock', ecosystem: 'pypi' },
  { path: 'apps/desktop/src-tauri/Cargo.lock', ecosystem: 'cargo' },
  { path: 'apps/desktop/src-tauri/build_support/unix-test-harness/Cargo.lock', ecosystem: 'cargo' },
  { path: 'tools/portable-launcher/Cargo.lock', ecosystem: 'cargo' },
]

function read(root, relativePath) {
  return readFileSync(path.join(root, relativePath), 'utf8')
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function purlName(ecosystem, name) {
  const encoded = encodeURIComponent(name)
  return ecosystem === 'npm' ? encoded.replaceAll('%2F', '/') : encoded
}

function component(ecosystem, name, version, lockfile) {
  return {
    ecosystem,
    name,
    version,
    lockfile,
    purl: `pkg:${ecosystem}/${purlName(ecosystem, name)}@${encodeURIComponent(version)}`,
  }
}

function packagesFromToml(text, ecosystem, lockfile) {
  const packages = []
  for (const block of text.split(/^\[\[package\]\]\s*$/gmu).slice(1)) {
    const name = block.match(/^name\s*=\s*"([^"]+)"/mu)?.[1]
    const version = block.match(/^version\s*=\s*"([^"]+)"/mu)?.[1]
    if (name && version) packages.push(component(ecosystem, name, version, lockfile))
  }
  return packages
}

function packagesFromPnpm(text, lockfile) {
  const lock = parse(text)
  const packages = []
  for (const key of Object.keys(lock.packages ?? {})) {
    const clean = key.replace(/^\//u, '').split('(')[0]
    const separator = clean.lastIndexOf('@')
    if (separator <= 0) continue
    packages.push(component('npm', clean.slice(0, separator), clean.slice(separator + 1), lockfile))
  }
  return packages
}

export function collectLockInventory(root = defaultRoot) {
  const items = []
  for (const lockfile of LOCKFILES) {
    const text = read(root, lockfile.path)
    items.push(...(lockfile.ecosystem === 'npm'
      ? packagesFromPnpm(text, lockfile.path)
      : packagesFromToml(text, lockfile.ecosystem, lockfile.path)))
  }
  return [...new Map(items.map((item) => [item.purl, item])).values()]
    .sort((left, right) => left.purl.localeCompare(right.purl))
}

function lockfileScope(root) {
  return LOCKFILES.map((lockfile) => {
    const text = read(root, lockfile.path)
    const parsedEntries = lockfile.ecosystem === 'npm'
      ? packagesFromPnpm(text, lockfile.path).length
      : packagesFromToml(text, lockfile.ecosystem, lockfile.path).length
    return { path: lockfile.path, sha256: sha256(text), parsedEntries }
  })
}

function sourceTimestamp(root) {
  const result = spawnSync('git', ['show', '-s', '--format=%cI', 'HEAD'], { cwd: root, encoding: 'utf8' })
  return result.status === 0 && result.stdout.trim()
    ? new Date(result.stdout.trim()).toISOString()
    : new Date(0).toISOString()
}

function readSidecarManifest(manifestPath) {
  if (!manifestPath) return null
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'))
  if (!manifest || typeof manifest !== 'object' || !Array.isArray(manifest.entries)) {
    throw new Error('Sidecar manifest must contain an entries array.')
  }
  const entries = manifest.entries.map((entry, index) => {
    if (!entry || typeof entry !== 'object' || typeof entry.path !== 'string' || !['file', 'symlink'].includes(entry.type)) {
      throw new Error(`Sidecar manifest entry ${index + 1} is invalid.`)
    }
    if (entry.type === 'file' && (!Number.isSafeInteger(entry.size) || entry.size < 0 || !/^[a-f0-9]{64}$/u.test(entry.sha256))) {
      throw new Error(`Sidecar file entry ${index + 1} lacks a valid size or SHA-256.`)
    }
    if (entry.type === 'symlink' && typeof entry.target !== 'string') {
      throw new Error(`Sidecar symlink entry ${index + 1} lacks a target.`)
    }
    return { ...entry }
  }).sort((left, right) => left.path.localeCompare(right.path))
  return { ...manifest, entries }
}

function sidecarFileRef(entry, index) {
  return `SPDXRef-SidecarFile-${index + 1}`
}

function cycloneFileRef(entry, index) {
  return `urn:zombie-killer:sidecar-file:${index + 1}:${sha256(entry.path)}`
}

function sidecarEntryDigest(entry) {
  return entry.type === 'file' ? entry.sha256 : sha256(`symlink-target:${entry.target}`)
}

export function buildSbomDocuments(root = defaultRoot, options = {}) {
  const rootPackage = JSON.parse(read(root, 'package.json'))
  const inventory = collectLockInventory(root)
  const lockfiles = lockfileScope(root)
  const lockDigest = sha256(lockfiles.map((item) => `${item.path}\0${item.sha256}\n`).join(''))
  const timestamp = sourceTimestamp(root)
  const sidecar = readSidecarManifest(options.sidecarManifestPath)
  const scope = {
    lockfiles,
    lockedComponentCount: inventory.length,
    binaryInventoryIncluded: sidecar !== null,
    sidecarEntryCount: sidecar?.entries.length ?? 0,
    sidecarManifest: options.sidecarManifestPath ? path.basename(options.sidecarManifestPath) : null,
    licensesComplete: false,
    statement: sidecar
      ? 'Lockfile components plus a hash-bound sidecar file inventory; transitive license conclusions remain NOASSERTION pending release review.'
      : 'Lockfile component inventory only; no native executable or sidecar file inventory is included.',
  }

  const spdxPackages = inventory.map((item, index) => ({
    SPDXID: `SPDXRef-LockedPackage-${index + 1}`,
    name: item.name,
    versionInfo: item.version,
    downloadLocation: 'NOASSERTION',
    filesAnalyzed: false,
    licenseConcluded: 'NOASSERTION',
    licenseDeclared: 'NOASSERTION',
    comment: `Resolved from ${item.lockfile}; license must be verified from the distributed package metadata.`,
    externalRefs: [{
      referenceCategory: 'PACKAGE-MANAGER',
      referenceType: 'purl',
      referenceLocator: item.purl,
    }],
  }))
  const spdxFiles = (sidecar?.entries ?? []).map((entry, index) => ({
    SPDXID: sidecarFileRef(entry, index),
    fileName: `./sidecar/${entry.path}`,
    checksums: [{ algorithm: 'SHA256', checksumValue: sidecarEntryDigest(entry) }],
    licenseConcluded: 'NOASSERTION',
    licenseInfoInFiles: ['NOASSERTION'],
    copyrightText: 'NOASSERTION',
    comment: entry.type === 'file'
      ? `Manifest-bound regular file; ${entry.size} bytes.`
      : `Manifest-bound symbolic link to ${entry.target}; checksum covers the declared link target, not target file content.`,
  }))
  const spdx = {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: `Zombie-Killer-${rootPackage.version}`,
    documentNamespace: `https://github.com/PhantomBugz/Zombie-Killer-AI/sbom/${rootPackage.version}/${lockDigest}${sidecar ? `-${sha256(JSON.stringify(sidecar))}` : ''}`,
    documentDescribes: ['SPDXRef-RootPackage'],
    creationInfo: { created: timestamp, creators: ['Tool: Zombie-Killer-SBOM-Generator-2'] },
    comment: scope.statement,
    packages: [{
      SPDXID: 'SPDXRef-RootPackage',
      name: 'Zombie Killer',
      versionInfo: rootPackage.version,
      downloadLocation: 'NOASSERTION',
      filesAnalyzed: false,
      licenseConcluded: 'Apache-2.0',
      licenseDeclared: 'Apache-2.0',
      copyrightText: 'Copyright 2026 PhantomBugz',
    }, ...spdxPackages],
    files: spdxFiles,
    relationships: [
      ...spdxPackages.map((item) => ({
        spdxElementId: 'SPDXRef-RootPackage',
        relationshipType: 'DEPENDS_ON',
        relatedSpdxElement: item.SPDXID,
      })),
      ...spdxFiles.map((item) => ({
        spdxElementId: 'SPDXRef-RootPackage',
        relationshipType: 'CONTAINS',
        relatedSpdxElement: item.SPDXID,
      })),
    ],
  }

  const cycloneLibraries = inventory.map((item) => ({
    type: 'library',
    'bom-ref': item.purl,
    name: item.name,
    version: item.version,
    purl: item.purl,
    properties: [{ name: 'zombie-killer:source-lockfile', value: item.lockfile }],
  }))
  const cycloneFiles = (sidecar?.entries ?? []).map((entry, index) => ({
    type: 'file',
    'bom-ref': cycloneFileRef(entry, index),
    name: entry.path,
    hashes: [{ alg: 'SHA-256', content: sidecarEntryDigest(entry) }],
    properties: [
      { name: 'zombie-killer:sidecar-entry-type', value: entry.type },
      ...(entry.type === 'file'
        ? [{ name: 'zombie-killer:size', value: String(entry.size) }]
        : [
            { name: 'zombie-killer:symlink-target', value: entry.target },
            { name: 'zombie-killer:hash-meaning', value: 'SHA-256 of declared symlink target descriptor' },
          ]),
    ],
  })).map((item) => Object.fromEntries(Object.entries(item).filter(([, value]) => value !== undefined)))
  const rootRef = 'pkg:generic/zombie-killer'
  const cyclone = {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: `urn:uuid:${lockDigest.slice(0, 8)}-${lockDigest.slice(8, 12)}-4${lockDigest.slice(13, 16)}-a${lockDigest.slice(17, 20)}-${lockDigest.slice(20, 32)}`,
    version: 1,
    metadata: {
      timestamp,
      tools: { components: [{ type: 'application', name: 'Zombie Killer SBOM Generator', version: '2' }] },
      component: {
        type: 'application',
        'bom-ref': rootRef,
        name: 'Zombie Killer',
        version: rootPackage.version,
        licenses: [{ license: { id: 'Apache-2.0' } }],
        copyright: 'Copyright 2026 PhantomBugz',
      },
      properties: [
        { name: 'zombie-killer:scope', value: scope.statement },
        { name: 'zombie-killer:binary-inventory-included', value: String(scope.binaryInventoryIncluded) },
        { name: 'zombie-killer:licenses-complete', value: 'false' },
      ],
    },
    components: [...cycloneLibraries, ...cycloneFiles],
    dependencies: [{ ref: rootRef, dependsOn: [...inventory.map((item) => item.purl), ...cycloneFiles.map((item) => item['bom-ref'])] }],
  }

  return { spdx, cyclone, inventory, scope }
}

export function validateSbomDocuments(documents) {
  const issues = []
  const { spdx, cyclone, inventory, scope } = documents
  const scopedLockfiles = Array.isArray(scope?.lockfiles) ? scope.lockfiles : []
  const scopedLockfilePaths = scopedLockfiles.map((item) => item?.path)
  if (spdx?.spdxVersion !== 'SPDX-2.3' || spdx?.dataLicense !== 'CC0-1.0' || spdx?.SPDXID !== 'SPDXRef-DOCUMENT') {
    issues.push('SPDX document does not satisfy the required SPDX 2.3 root schema contract.')
  }
  if (!Array.isArray(spdx?.packages) || !Array.isArray(spdx?.files) || !Array.isArray(spdx?.relationships)) {
    issues.push('SPDX document is missing required package, file, or relationship arrays.')
  }
  if (cyclone?.bomFormat !== 'CycloneDX' || cyclone?.specVersion !== '1.6' || cyclone?.version !== 1) {
    issues.push('CycloneDX document does not satisfy the required CycloneDX 1.6 root schema contract.')
  }
  if (!Array.isArray(cyclone?.components) || !Array.isArray(cyclone?.dependencies)) {
    issues.push('CycloneDX document is missing required component or dependency arrays.')
  }
  if (!Array.isArray(inventory)
    || !scope
    || !Array.isArray(scope.lockfiles)
    || scopedLockfilePaths.length !== LOCKFILES.length
    || new Set(scopedLockfilePaths).size !== LOCKFILES.length
    || LOCKFILES.some((expected) => !scopedLockfilePaths.includes(expected.path))) {
    issues.push('SBOM generator scope is missing the five-lockfile inventory contract.')
    return issues
  }
  if (scope.lockfiles.some((item) => !LOCKFILES.some((expected) => expected.path === item.path)
    || !/^[a-f0-9]{64}$/u.test(item.sha256) || !Number.isInteger(item.parsedEntries) || item.parsedEntries < 1)) {
    issues.push('Lockfile scope metadata is incomplete or malformed.')
  }

  const expectedPurls = new Set(inventory.map((item) => item.purl))
  if (expectedPurls.size !== inventory.length) issues.push('Lock inventory contains duplicate package URLs.')
  const spdxPurls = new Set((spdx.packages ?? []).slice(1).map((item) => item.externalRefs?.[0]?.referenceLocator))
  const cyclonePurls = new Set((cyclone.components ?? []).filter((item) => item.type === 'library').map((item) => item.purl))
  if (spdxPurls.size !== expectedPurls.size || [...expectedPurls].some((purl) => !spdxPurls.has(purl))) {
    issues.push('SPDX package set does not match the complete lock inventory.')
  }
  if (cyclonePurls.size !== expectedPurls.size || [...expectedPurls].some((purl) => !cyclonePurls.has(purl))) {
    issues.push('CycloneDX library set does not match the complete lock inventory.')
  }
  const spdxIds = [...(spdx.packages ?? []), ...(spdx.files ?? [])].map((item) => item.SPDXID)
  if (spdxIds.some((item) => typeof item !== 'string') || new Set(spdxIds).size !== spdxIds.length) {
    issues.push('SPDX element identifiers must be present and unique.')
  }
  const cycloneRefs = (cyclone.components ?? []).map((item) => item['bom-ref'])
  if (cycloneRefs.some((item) => typeof item !== 'string') || new Set(cycloneRefs).size !== cycloneRefs.length) {
    issues.push('CycloneDX component references must be present and unique.')
  }
  if ((spdx.files ?? []).some((item) => item.checksums?.length !== 1 || !/^[a-f0-9]{64}$/u.test(item.checksums[0]?.checksumValue))) {
    issues.push('SPDX sidecar entries require exactly one valid SHA-256 descriptor checksum.')
  }
  if ((cyclone.components ?? []).filter((item) => item.type === 'file')
    .some((item) => item.hashes?.length !== 1 || !/^[a-f0-9]{64}$/u.test(item.hashes[0]?.content))) {
    issues.push('CycloneDX sidecar entries require exactly one valid SHA-256 descriptor hash.')
  }
  const dependency = (cyclone.dependencies ?? []).find((item) => item.ref === 'pkg:generic/zombie-killer')
  if (!dependency || expectedPurls.size !== new Set((dependency.dependsOn ?? []).filter((item) => expectedPurls.has(item))).size) {
    issues.push('CycloneDX root dependency graph does not cover the complete lock inventory.')
  }
  if ((spdx.files ?? []).length !== scope.sidecarEntryCount) issues.push('SPDX sidecar file count differs from declared scope.')
  if ((cyclone.components ?? []).filter((item) => item.type === 'file').length !== scope.sidecarEntryCount) {
    issues.push('CycloneDX sidecar file count differs from declared scope.')
  }
  if (scope.binaryInventoryIncluded !== (scope.sidecarEntryCount > 0)) issues.push('Binary inventory scope flag is inconsistent.')
  if (scope.licensesComplete !== false) issues.push('Generated SBOM must not claim complete transitive license conclusions.')
  return issues
}

export function serializeSbomDocuments(documents) {
  return {
    spdx: `${JSON.stringify(documents.spdx, null, 2)}\n`,
    cyclone: `${JSON.stringify(documents.cyclone, null, 2)}\n`,
  }
}

function argumentValue(name) {
  const index = process.argv.indexOf(name)
  if (index < 0) return undefined
  if (!process.argv[index + 1]) throw new Error(`${name} requires a value.`)
  return process.argv[index + 1]
}

function main() {
  const outputRoot = path.resolve(defaultRoot, argumentValue('--output') ?? 'output/sbom')
  const sidecarArgument = argumentValue('--sidecar-manifest')
  const sidecarManifestPath = sidecarArgument ? path.resolve(defaultRoot, sidecarArgument) : undefined
  if (sidecarManifestPath && !existsSync(sidecarManifestPath)) throw new Error('Requested sidecar manifest does not exist.')
  const documents = buildSbomDocuments(defaultRoot, { sidecarManifestPath })
  const issues = validateSbomDocuments(documents)
  if (issues.length) throw new Error(`SBOM validation failed: ${issues.join(' ')}`)
  const serialized = serializeSbomDocuments(documents)
  mkdirSync(outputRoot, { recursive: true })
  writeFileSync(path.join(outputRoot, 'zombie-killer.spdx.json'), serialized.spdx, 'utf8')
  writeFileSync(path.join(outputRoot, 'zombie-killer.cdx.json'), serialized.cyclone, 'utf8')
  const scope = documents.scope.binaryInventoryIncluded ? ` plus ${documents.scope.sidecarEntryCount} sidecar entries` : ''
  console.log(`Generated validated SPDX 2.3 and CycloneDX 1.6 SBOMs for ${documents.inventory.length} locked components${scope}.`)
}

if (process.argv[1] && path.resolve(process.argv[1]) === modulePath) main()
