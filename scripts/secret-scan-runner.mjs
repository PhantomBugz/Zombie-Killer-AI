import { readFileSync } from 'node:fs'
import path from 'node:path'
import { spawnSync } from 'node:child_process'

import {
  decodeSecretScanBuffer,
  findSecretMatches,
  formatSecretScanFailure,
  loadSecretScanAllowlists,
  loadSecretHistoryExceptions,
} from './secret-scan-lib.mjs'

const REDACTED_FAILURE = 'Secret scan failed at a redacted boundary; values and paths suppressed.'

export function parseSecretScanArguments(args) {
  const allowed = new Set(['--tracked', '--history'])
  if (!Array.isArray(args) || args.some((argument) => !allowed.has(argument))) {
    throw new Error('Unknown secret scan argument; values and paths suppressed.')
  }
  const argumentsSet = new Set(args)
  const useDefaults = argumentsSet.size === 0
  const modes = {
    scanTracked: useDefaults || argumentsSet.has('--tracked'),
    scanHistory: useDefaults || argumentsSet.has('--history'),
  }
  if (!modes.scanTracked && !modes.scanHistory) {
    throw new Error('Secret scan requires at least one mode; values and paths suppressed.')
  }
  return modes
}

function createGitCommand(root) {
  return (args, options = {}) => spawnSync('git', args, {
    cwd: root,
    encoding: options.encoding === 'buffer' ? null : 'utf8',
    maxBuffer: 512 * 1024 * 1024,
    windowsHide: true,
  })
}

function requireGitResult(git, args, options, operation) {
  let result
  try {
    result = git(args, options)
  } catch {
    throw new Error(`${operation} failed; refusing an incomplete secret scan.`)
  }
  if (!result || result.error || result.status !== 0) {
    throw new Error(`${operation} failed; refusing an incomplete secret scan.`)
  }
  return result
}

function requireGitText(git, args, operation) {
  const result = requireGitResult(git, args, {}, operation)
  if (typeof result.stdout !== 'string') {
    throw new Error(`${operation} returned invalid output; refusing an incomplete secret scan.`)
  }
  return result.stdout
}

function normalize(file) {
  return file.replaceAll('\\', '/')
}

function scan(content, location, allowlistPath, matches, allowlists, historyExceptions, commit) {
  const text = decodeSecretScanBuffer(content)
  for (const match of findSecretMatches(text, location, {
    allowlists,
    historyExceptions,
    allowlistPath,
    commit,
  })) matches.push(match)
}

export function runSecretScan({
  root,
  scanTracked,
  scanHistory,
  allowlists,
  historyExceptions,
  git,
  readFile = readFileSync,
}) {
  if (!scanTracked && !scanHistory) {
    throw new Error('Secret scan requires at least one mode; values and paths suppressed.')
  }
  const effectiveAllowlists = allowlists ?? loadSecretScanAllowlists(root)
  const effectiveHistoryExceptions = historyExceptions ?? loadSecretHistoryExceptions(root)
  const runGit = git ?? createGitCommand(root)
  const matches = []
  let trackedCount = 0
  let historyPairCount = 0

  if (scanTracked) {
    const files = requireGitText(
      runGit,
      ['ls-files', '--cached', '--others', '--exclude-standard', '-z'],
      'Git tracked-file enumeration',
    ).split('\0').filter(Boolean).map(normalize)
    for (const file of files) {
      trackedCount += 1
      scan(
        readFile(path.join(root, file)),
        file,
        file,
        matches,
        effectiveAllowlists,
        effectiveHistoryExceptions,
      )
    }
  }

  if (scanHistory) {
    const commits = requireGitText(
      runGit,
      ['rev-list', '--all'],
      'Git history enumeration',
    ).split(/\r?\n/u).filter(Boolean)
    if (commits.some((commit) => !/^[a-f0-9]{40,64}$/u.test(commit))) {
      throw new Error('Git history enumeration returned invalid output; refusing an incomplete secret scan.')
    }
    for (const commit of commits) {
      const names = requireGitText(
        runGit,
        ['diff-tree', '--root', '--no-commit-id', '--name-only', '--diff-filter=ACMRTUXB', '-r', '-z', commit],
        'Git history path enumeration',
      ).split('\0').filter(Boolean).map(normalize)
      for (const file of names) {
        const object = requireGitText(
          runGit,
          ['rev-parse', '--verify', '--end-of-options', `${commit}:${file}`],
          'Git history object lookup',
        ).trim()
        if (!/^[a-f0-9]{40,64}$/u.test(object)) {
          throw new Error('Git history object lookup returned invalid output; refusing an incomplete secret scan.')
        }
        const type = requireGitText(
          runGit,
          ['cat-file', '-t', object],
          'Git history object type lookup',
        ).trim()
        if (type !== 'blob') {
          throw new Error('Git history object is not a blob; refusing an incomplete secret scan.')
        }
        const content = requireGitResult(
          runGit,
          ['cat-file', 'blob', object],
          { encoding: 'buffer' },
          'Git history blob read',
        ).stdout
        if (!Buffer.isBuffer(content)) {
          throw new Error('Git history blob read returned invalid output; refusing an incomplete secret scan.')
        }
        historyPairCount += 1
        scan(
          content,
          `${commit}:${file}`,
          file,
          matches,
          effectiveAllowlists,
          effectiveHistoryExceptions,
          commit,
        )
      }
    }
  }

  const unique = [...new Map(matches.map((match) => [`${match.file}:${match.line}:${match.kind}`, match])).values()]
  return { matches: unique, trackedCount, historyPairCount }
}

export function runSecretScanCli({
  root,
  args,
  runScan = runSecretScan,
  writeOutput = console.log,
  writeError = console.error,
}) {
  try {
    const modes = parseSecretScanArguments(args)
    const result = runScan({ root, ...modes })
    if (result.matches.length > 0) {
      writeError(formatSecretScanFailure(result.matches))
      return 1
    }
    writeOutput(
      `Secret scan passed with values suppressed (${result.trackedCount} tracked files; ${result.historyPairCount} historical commit/file pairs).`,
    )
    return 0
  } catch {
    writeError(REDACTED_FAILURE)
    return 1
  }
}
