import type { ActivityEvent } from '../../transport'
import { sanitizeForExport } from './redaction'

const safeFields = ['timestamp', 'actor', 'project', 'target', 'action', 'result', 'correlationId'] as const
const unicodeWhitespace = /\p{White_Space}/u

function isFormulaWhitespace(character: string) {
  return character === '\uFEFF' || unicodeWhitespace.test(character)
}

function needsFormulaNeutralization(text: string) {
  let index = 0
  while (index < text.length) {
    const point = text.codePointAt(index)
    if (point === undefined) break
    const character = String.fromCodePoint(point)
    if (!isFormulaWhitespace(character)) break
    index += character.length
  }
  if (index >= text.length) return false
  return '=+-@'.includes(text[index] ?? '')
}

function cleanCsvControls(text: string) {
  let clean = ''
  for (const character of text) {
    const code = character.charCodeAt(0)
    if ((code <= 31 && code !== 10 && code !== 13) || (code >= 127 && code <= 159) || code === 0xfeff) clean += ' '
    else clean += character
  }
  return clean
}

export function buildSanitizedExport(events: ActivityEvent[], format: 'jsonl' | 'csv') {
  const rows = events.map((event) => Object.fromEntries(safeFields.map((field) => [field, sanitizeForExport(event[field])])))
  if (format === 'jsonl') return rows.map((row) => JSON.stringify(row)).join('\n')
  const cell = (value: unknown) => {
    const rawText = typeof value === 'string' ? value : JSON.stringify(value ?? '')
    const text = cleanCsvControls(rawText)
    const neutralized = needsFormulaNeutralization(text) ? `'${text}` : text
    return `"${neutralized.replaceAll('"', '""')}"`
  }
  return [safeFields.map(cell).join(','), ...rows.map((row) => safeFields.map((field) => cell(row[field])).join(','))].join('\r\n')
}

export async function copyText(text: string) {
  if (!navigator.clipboard?.writeText) return false
  try { await navigator.clipboard.writeText(text); return true } catch { return false }
}
