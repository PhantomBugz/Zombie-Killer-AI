import type { MemoryRecord } from '../../transport'

export type EditableMemoryFields = Pick<MemoryRecord, 'title' | 'content' | 'tags' | 'collection'>

const editableKeys = ['title', 'content', 'tags', 'collection'] as const
const maxDraftBytes = 16_384

function findDuplicateKey(raw: string) {
  const scopes: Array<Set<string> | null> = []
  for (let index = 0; index < raw.length; index += 1) {
    const character = raw[index]
    if (character === '{') { scopes.push(new Set()); continue }
    if (character === '[') { scopes.push(null); continue }
    if (character === '}' || character === ']') { scopes.pop(); continue }
    if (character !== '"') continue
    const start = index
    index += 1
    while (index < raw.length) {
      if (raw[index] === '\\') { index += 2; continue }
      if (raw[index] === '"') break
      index += 1
    }
    let after = index + 1
    while (/\s/.test(raw[after] ?? '')) after += 1
    if (raw[after] !== ':') continue
    try {
      const decoded = JSON.parse(raw.slice(start, index + 1)) as string
      const scope = scopes.at(-1)
      if (scope?.has(decoded)) return decoded
      scope?.add(decoded)
    } catch { return undefined }
  }
  return undefined
}

export function serializeMemoryDraft(record: EditableMemoryFields) {
  return JSON.stringify({ title: record.title, content: record.content, tags: record.tags, collection: record.collection }, null, 2)
}

export function parseMemoryDraft(raw: string): { value?: EditableMemoryFields; error?: string } {
  if (new TextEncoder().encode(raw).byteLength > maxDraftBytes) return { error: `Raw JSON draft exceeds the ${maxDraftBytes}-byte limit.` }
  const duplicate = findDuplicateKey(raw)
  if (duplicate) return { error: `Duplicate key "${duplicate}" is not allowed.` }
  let parsed: unknown
  try { parsed = JSON.parse(raw) } catch { return { error: 'Raw JSON is not valid JSON.' } }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return { error: 'Raw JSON must be one object.' }
  const object = parsed as Record<string, unknown>
  const actualKeys = Object.keys(object)
  if (actualKeys.length !== editableKeys.length || actualKeys.some((key) => !editableKeys.includes(key as typeof editableKeys[number]))) return { error: 'Raw JSON schema allows exactly title, content, tags, and collection.' }
  if (typeof object.title !== 'string' || object.title.trim().length === 0 || object.title.length > 200) return { error: 'title must be a non-empty string of at most 200 characters.' }
  if (typeof object.content !== 'string' || object.content.length > 8192) return { error: 'content must be a string of at most 8192 characters.' }
  if (typeof object.collection !== 'string' || object.collection.trim().length === 0 || object.collection.length > 128) return { error: 'collection must be a non-empty string of at most 128 characters.' }
  if (!Array.isArray(object.tags) || object.tags.length > 20 || object.tags.some((tag) => typeof tag !== 'string' || tag.length === 0 || tag.length > 64)) return { error: 'tags must be an array of at most 20 non-empty strings, each at most 64 characters.' }
  return { value: { title: object.title, content: object.content, tags: object.tags as string[], collection: object.collection } }
}
