import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { runSecretScanCli } from './secret-scan-runner.mjs'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
process.exitCode = runSecretScanCli({ root, args: process.argv.slice(2) })
