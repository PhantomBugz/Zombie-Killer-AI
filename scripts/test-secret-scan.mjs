import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

import {
  parseSecretScanArguments,
  runSecretScan,
  runSecretScanCli,
} from './secret-scan-runner.mjs'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

assert.deepEqual(parseSecretScanArguments([]), { scanTracked: true, scanHistory: true })
assert.deepEqual(parseSecretScanArguments(['--tracked']), { scanTracked: true, scanHistory: false })
assert.deepEqual(parseSecretScanArguments(['--history']), { scanTracked: false, scanHistory: true })
assert.deepEqual(parseSecretScanArguments(['--tracked', '--history']), { scanTracked: true, scanHistory: true })
assert.throws(() => parseSecretScanArguments(['--unexpected']), /Unknown secret scan argument/u)

assert.throws(
  () => runSecretScan({ root, scanTracked: false, scanHistory: false }),
  /at least one mode/u,
)

const exceptedCommit = '1'.repeat(40)
const unexceptedCommit = '2'.repeat(40)
const blob = 'a'.repeat(40)
const historyPath = 'tests/history-fixture.txt'
const historyValue = [
  'eyJhbGciOiJIUzI1NiJ9',
  'eyJzdWIiOiJzeW50aGV0aWMtaGlzdG9yeSJ9',
  'syntheticSignatureSegment789',
].join('.')
const historyExceptions = [{
  commit: exceptedCommit,
  path: historyPath,
  kind: 'JWT-like credential',
  line: 1,
  matchSha256: createHash('sha256').update(historyValue, 'utf8').digest('hex'),
  reason: 'Synthetic test-only history fixture.',
}]

function result(stdout, status = 0) {
  return { status, stdout, stderr: '', error: undefined }
}

function historyGit({ failure, objectType = 'blob' } = {}) {
  return (args) => {
    if (args[0] === 'rev-list') return result(`${exceptedCommit}\n${unexceptedCommit}\n`)
    if (args[0] === 'diff-tree') return result(`${historyPath}\0`)
    if (args[0] === 'rev-parse') {
      return failure === 'object' ? result('', 1) : result(`${blob}\n`)
    }
    if (args[0] === 'cat-file' && args[1] === '-t') {
      return failure === 'type' ? result('', 1) : result(`${objectType}\n`)
    }
    if (args[0] === 'cat-file' && args[1] === 'blob') {
      return failure === 'read' ? result(Buffer.alloc(0), 1) : result(Buffer.from(historyValue, 'utf8'))
    }
    throw new Error('Unexpected synthetic Git operation.')
  }
}

const perCommit = runSecretScan({
  root,
  scanTracked: false,
  scanHistory: true,
  allowlists: [],
  historyExceptions,
  git: historyGit(),
})
assert.equal(perCommit.historyPairCount, 2)
assert.equal(perCommit.matches.length, 1)
assert.match(perCommit.matches[0].file, new RegExp(`^${unexceptedCommit}:`, 'u'))

for (const failure of ['object', 'type', 'read']) {
  assert.throws(
    () => runSecretScan({
      root,
      scanTracked: false,
      scanHistory: true,
      allowlists: [],
      historyExceptions: [],
      git: historyGit({ failure }),
    }),
    /refusing an incomplete secret scan/u,
  )
}
assert.throws(
  () => runSecretScan({
    root,
    scanTracked: false,
    scanHistory: true,
    allowlists: [],
    historyExceptions: [],
    git: historyGit({ objectType: 'tree' }),
  }),
  /refusing an incomplete secret scan/u,
)

const privateFailureDetail = ['sensitive', '-fixture-detail'].join('')
let errorOutput = ''
const failureExitCode = runSecretScanCli({
  root,
  args: ['--history'],
  runScan: () => {
    throw new Error(privateFailureDetail)
  },
  writeError: (message) => {
    errorOutput += message
  },
})
assert.equal(failureExitCode, 1)
assert.match(errorOutput, /values and paths suppressed/u)
assert.doesNotMatch(errorOutput, new RegExp(privateFailureDetail, 'u'))

const unknownArgument = ['--unknown-', 'sensitive-fixture-detail'].join('')
const cli = spawnSync(process.execPath, [path.join(root, 'scripts', 'secret-scan.mjs'), unknownArgument], {
  cwd: root,
  encoding: 'utf8',
})
assert.equal(cli.status, 1)
assert.match(cli.stderr, /values and paths suppressed/u)
assert.doesNotMatch(cli.stderr, new RegExp(unknownArgument, 'u'))
assert.equal(cli.stdout, '')

console.log('Secret scan runner tests passed with values suppressed.')
