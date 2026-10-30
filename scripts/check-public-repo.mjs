import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { checkPublicRepository } from './public-repo-checks.mjs'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const issues = checkPublicRepository(root)

if (issues.length) {
  console.error(`Public repository check failed with ${issues.length} issue(s):`)
  for (const issue of issues) console.error(`- ${issue}`)
  process.exitCode = 1
} else {
  console.log('Public repository check passed: files, links, versions, licenses, YAML, workflows, and donation placement.')
}
