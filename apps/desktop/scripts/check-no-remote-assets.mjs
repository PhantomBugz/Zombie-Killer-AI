import { readdir, readFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const remoteUrlPattern = /(?:https?:\/\/|\/\/[a-z0-9.-]+\.[a-z]{2,})/i
const exactTauriIpcToken = /http:\/\/ipc\.localhost(?=[\s'";),]|$)/g
const allowedNonAssetLiterals = [
  'http://www.w3.org/1998/Math/MathML',
  'http://www.w3.org/1999/xlink',
  'http://www.w3.org/2000/svg',
  'http://www.w3.org/XML/1998/namespace',
  'https://react.dev/errors/',
]
const literalQuotes = ['"', "'", '`']

function removeAllowedNonAssetLiterals(source) {
  const withoutExactIpc = source.replace(exactTauriIpcToken, '')
  return allowedNonAssetLiterals.reduce(
    (content, url) =>
      literalQuotes.reduce(
        (quotedContent, quote) =>
          quotedContent.replaceAll(`${quote}${url}${quote}`, `${quote}${quote}`),
        content,
      ),
    withoutExactIpc,
  )
}

async function collectFiles(directory, extensions) {
  const files = []
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const absolutePath = path.join(directory, entry.name)
    if (entry.isDirectory()) {
      files.push(...(await collectFiles(absolutePath, extensions)))
    } else if (extensions.has(path.extname(entry.name))) {
      files.push(absolutePath)
    }
  }
  return files
}

const authoredFiles = [
  path.join(packageRoot, 'index.html'),
  ...(await collectFiles(path.join(packageRoot, 'src'), new Set(['.css', '.ts', '.tsx']))),
  ...(await collectFiles(
    path.join(packageRoot, 'public'),
    new Set(['.css', '.html', '.js', '.json', '.svg', '.webmanifest']),
  )),
]
const builtFiles = await collectFiles(
  path.join(packageRoot, 'dist'),
  new Set(['.css', '.html', '.js', '.mjs', '.svg']),
)

for (const file of [...authoredFiles, ...builtFiles]) {
  const source = removeAllowedNonAssetLiterals(await readFile(file, 'utf8'))
  if (remoteUrlPattern.test(source)) {
    throw new Error(`Remote asset URL found in ${path.relative(packageRoot, file)}`)
  }
}

console.log(`PASS: ${authoredFiles.length + builtFiles.length} authored and built asset files are local-only`)
