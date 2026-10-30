interface ElementSnapshot {
  inertAttribute: string | null
  ariaHidden: string | null
}

type IsolationAttribute = 'inert' | 'aria-hidden'

interface ExpectedAttributeWrite {
  oldValue: string | null
  newValue: string | null
}

const dialogLayers = new Set<HTMLElement>()
const dialogRestoreTargets = new Map<HTMLElement, HTMLElement | null>()
const dialogFocusFallbacks = new Map<HTMLElement, () => void>()
const elementSnapshots = new Map<HTMLElement, ElementSnapshot>()
const expectedAttributeWrites = new Map<HTMLElement, Map<IsolationAttribute, ExpectedAttributeWrite[]>>()
let bodyLockCount = 0
let bodyScrollY = 0
let bodyHadLockClass = false
let isolationObserver: MutationObserver | null = null
let isolatedTop: HTMLElement | null = null

function orderedDialogLayers() {
  return Array.from(document.querySelectorAll<HTMLElement>('.dialog-layer')).filter((layer) => dialogLayers.has(layer))
}

export function getTopmostDialogLayer() {
  return orderedDialogLayers().at(-1) ?? null
}

function blockedSiblings(layer: HTMLElement) {
  const blocked = new Set<HTMLElement>()
  let current: HTMLElement | null = layer
  while (current?.parentElement) {
    for (const sibling of current.parentElement.children) {
      if (sibling !== current && sibling instanceof HTMLElement) blocked.add(sibling)
    }
    if (current.parentElement === document.body) break
    current = current.parentElement
  }
  return blocked
}

function writeIsolationAttribute(element: HTMLElement, attribute: IsolationAttribute, value: string | null) {
  const oldValue = element.getAttribute(attribute)
  if (oldValue === value) return
  if (isolationObserver && element.isConnected) {
    let byAttribute = expectedAttributeWrites.get(element)
    if (!byAttribute) {
      byAttribute = new Map()
      expectedAttributeWrites.set(element, byAttribute)
    }
    const writes = byAttribute.get(attribute) ?? []
    writes.push({ oldValue, newValue: value })
    byAttribute.set(attribute, writes)
  }
  if (value === null) element.removeAttribute(attribute)
  else element.setAttribute(attribute, value)
}

function consumeExpectedAttributeWrite(element: HTMLElement, attribute: IsolationAttribute, oldValue: string | null, newValue: string | null) {
  const byAttribute = expectedAttributeWrites.get(element)
  const writes = byAttribute?.get(attribute)
  const expected = writes?.at(0)
  if (!expected || expected.oldValue !== oldValue || expected.newValue !== newValue) return false
  writes?.shift()
  if (writes?.length === 0) byAttribute?.delete(attribute)
  if (byAttribute?.size === 0) expectedAttributeWrites.delete(element)
  return true
}

function restoreElement(element: HTMLElement, snapshot: ElementSnapshot) {
  writeIsolationAttribute(element, 'inert', snapshot.inertAttribute)
  writeIsolationAttribute(element, 'aria-hidden', snapshot.ariaHidden)
}

function processIsolationMutations(mutations: MutationRecord[]) {
  let childListChanged = false
  let applicationAttributeChanged = false
  for (let index = 0; index < mutations.length; index += 1) {
    const mutation = mutations[index]!
    if (mutation.type === 'childList') { childListChanged = true; continue }
    if (mutation.type !== 'attributes' || !(mutation.target instanceof HTMLElement) || (mutation.attributeName !== 'inert' && mutation.attributeName !== 'aria-hidden')) continue
    const element = mutation.target
    const attribute = mutation.attributeName
    const nextMutation = mutations.slice(index + 1).find((candidate) => candidate.type === 'attributes' && candidate.target === element && candidate.attributeName === attribute)
    const newValue = nextMutation ? nextMutation.oldValue : element.getAttribute(attribute)
    if (consumeExpectedAttributeWrite(element, attribute, mutation.oldValue, newValue)) continue
    const snapshot = elementSnapshots.get(element)
    if (!snapshot) continue
    if (attribute === 'inert') snapshot.inertAttribute = newValue
    else snapshot.ariaHidden = newValue
    applicationAttributeChanged = true
  }
  return { applicationAttributeChanged, childListChanged }
}

function syncDialogIsolation(focusChangedTop = false, drainObserver = true) {
  if (drainObserver && isolationObserver) {
    const pending = processIsolationMutations(isolationObserver.takeRecords())
    focusChangedTop ||= pending.childListChanged
  }
  const previousTop = isolatedTop
  const top = getTopmostDialogLayer()
  const blocked = top ? blockedSiblings(top) : new Set<HTMLElement>()
  for (const [element, snapshot] of elementSnapshots) {
    if (blocked.has(element)) continue
    restoreElement(element, snapshot)
    elementSnapshots.delete(element)
  }
  for (const element of blocked) {
    if (!elementSnapshots.has(element)) elementSnapshots.set(element, { inertAttribute: element.getAttribute('inert'), ariaHidden: element.getAttribute('aria-hidden') })
    writeIsolationAttribute(element, 'inert', '')
    writeIsolationAttribute(element, 'aria-hidden', 'true')
  }
  isolatedTop = top
  if (focusChangedTop && top && top !== previousTop && !top.contains(document.activeElement)) dialogFocusFallbacks.get(top)?.()
}

function startIsolationObserver() {
  if (isolationObserver || typeof MutationObserver === 'undefined') return
  isolationObserver = new MutationObserver((mutations) => {
    if (dialogLayers.size === 0) return
    const observed = processIsolationMutations(mutations)
    if (observed.childListChanged || observed.applicationAttributeChanged) syncDialogIsolation(observed.childListChanged, false)
  })
  isolationObserver.observe(document.body, { attributeFilter: ['inert', 'aria-hidden'], attributeOldValue: true, attributes: true, childList: true, subtree: true })
}

function stopIsolationObserver() {
  isolationObserver?.disconnect()
  isolationObserver = null
  expectedAttributeWrites.clear()
}

function canonicalRestoreTarget(candidate: HTMLElement | null) {
  if (!candidate) return null
  const owner = orderedDialogLayers().reverse().find((registered) => registered.contains(candidate))
  return owner ? dialogRestoreTargets.get(owner) ?? candidate : candidate
}

export function registerDialogLayer(layer: HTMLElement, restoreTarget: HTMLElement | null, focusFallback: () => void) {
  const canonicalTarget = canonicalRestoreTarget(restoreTarget)
  dialogLayers.add(layer)
  dialogRestoreTargets.set(layer, canonicalTarget)
  dialogFocusFallbacks.set(layer, focusFallback)
  startIsolationObserver()
  syncDialogIsolation()
  let released = false
  return {
    restoreTarget: canonicalTarget,
    release() {
      if (released) return
      released = true
      dialogLayers.delete(layer)
      dialogRestoreTargets.delete(layer)
      dialogFocusFallbacks.delete(layer)
      syncDialogIsolation()
      if (dialogLayers.size === 0) stopIsolationObserver()
    },
  }
}

export function acquireBodyScrollLock() {
  if (bodyLockCount === 0) {
    const body = document.body
    bodyScrollY = window.scrollY
    bodyHadLockClass = body.classList.contains('modal-scroll-locked')
    body.classList.add('modal-scroll-locked')
  }
  bodyLockCount += 1
  let released = false
  return () => {
    if (released) return
    released = true
    bodyLockCount = Math.max(0, bodyLockCount - 1)
    if (bodyLockCount !== 0) return
    if (!bodyHadLockClass) document.body.classList.remove('modal-scroll-locked')
    bodyHadLockClass = false
    window.scrollTo(0, bodyScrollY)
  }
}
