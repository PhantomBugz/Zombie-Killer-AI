import { useLayoutEffect, useRef, useState } from 'react'

import { Dialog } from '../../components/Dialog'
import { LocalWorkflowReview } from '../../components/LocalWorkflowReview'
import type { EngineTransport, LocalWorkflowPlan, MemoryRecord, NativeScalarField, ScalarValue } from '../../transport'

interface Props {
  record: MemoryRecord
  transport: EngineTransport
  onClose: () => void
  onChanged: () => Promise<void>
  restoreFocusRef: React.RefObject<HTMLElement | null>
}

export function NativeMemoryEditor({ record, transport, onClose, onChanged, restoreFocusRef }: Props) {
  const fields = record.editableFields ?? []
  const [fieldIndex, setFieldIndex] = useState(0)
  const field = fields[fieldIndex]
  const [valueType, setValueType] = useState<NativeScalarField['valueType']>(field?.valueType ?? 'string')
  const [value, setValue] = useState(String(field?.value ?? ''))
  const [plan, setPlan] = useState<LocalWorkflowPlan>()
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const generation = useRef(0)
  const target = useRef(`${record.sourceId}:${record.id}:${record.revision}`)
  const inputRef = useRef<HTMLTextAreaElement>(null)

  useLayoutEffect(() => {
    const next = `${record.sourceId}:${record.id}:${record.revision}`
    if (target.current !== next) { generation.current += 1; target.current = next }
  }, [record.sourceId, record.id, record.revision])

  function invalidate() { generation.current += 1; setPlan(undefined); setBusy(false); setError('') }
  async function review() {
    if (!field || typeof record.revision !== 'string' || !transport.planNativeMemoryChange) return
    const current = ++generation.current
    let proposed: ScalarValue = value
    if (valueType === 'number') {
      proposed = Number(value)
      if (!value.trim() || !Number.isFinite(proposed)) { setError('Enter a finite scalar number.'); return }
    } else if (valueType === 'boolean') {
      if (value !== 'true' && value !== 'false') { setError('Enter true or false for a boolean.'); return }
      proposed = value === 'true'
    } else if (valueType === 'null') proposed = null
    setBusy(true); setError('')
    try {
      const result = await transport.planNativeMemoryChange({ sourceId: record.sourceId, recordId: record.id, expectedRevision: record.revision, field, value: proposed })
      if (generation.current === current) setPlan(result)
    } catch (reason) { if (generation.current === current) setError(reason instanceof Error ? reason.message : 'Memory review failed.') }
    finally { if (generation.current === current) setBusy(false) }
  }

  if (plan && transport.executeNativeMemoryChange) return <LocalWorkflowReview title="Review local memory repair" subject={`${plan.sourceId} / ${plan.recordId}`} confirmLabel="Apply local repair" plan={plan} execute={transport.executeNativeMemoryChange.bind(transport)} onSettled={onChanged} onClose={onClose} restoreFocusRef={restoreFocusRef} />
  return <Dialog title="Edit local memory draft" onClose={onClose} restoreFocusRef={restoreFocusRef} initialFocusRef={inputRef} className="memory-editor">
    <p className="local-warning">Memory Repair changes the selected local scalar. The engine creates and verifies a recoverable snapshot before committing. Provider policies, accounts, billing, and rate limits are unchanged.</p>
    <p>Source revision <code>{record.revision}</code></p>
    {fields.length ? <div className="memory-editor-fields"><label className="field"><span>Editable field</span><select value={fieldIndex} onChange={(event) => { invalidate(); const index = Number(event.target.value); setFieldIndex(index); setValueType(fields[index]!.valueType); setValue(String(fields[index]!.value ?? '')) }}>{fields.map((item, index) => <option key={`${item.kind}:${item.field}`} value={index}>{item.kind === 'update_metadata' ? `metadata.${item.field}` : item.field}</option>)}</select></label><label className="field"><span>Scalar type</span><select value={valueType} onChange={(event) => { invalidate(); setValueType(event.target.value as NativeScalarField['valueType']) }}><option value="string">Text</option>{field?.kind !== 'update_content' && <><option value="number">Number</option><option value="boolean">Boolean</option><option value="null">Null</option></>}</select></label><label className="field"><span>Scalar value</span><textarea ref={inputRef} value={value} disabled={valueType === 'null'} maxLength={65_536} onChange={(event) => { invalidate(); setValue(event.target.value) }} /></label></div> : <p>This record exposes no supported scalar fields. It remains read-only.</p>}
    {error && <p className="field-error" role="alert">{error}</p>}
    <div className="dialog__actions"><button className="primary-button" type="button" disabled={!field || busy} onClick={() => void review()}>{busy ? 'Reviewing…' : 'Review local repair'}</button><button className="secondary-button" type="button" onClick={onClose}>Cancel</button></div>
  </Dialog>
}
