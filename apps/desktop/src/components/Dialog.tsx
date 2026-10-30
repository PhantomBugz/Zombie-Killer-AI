import { useEffect, useId, useLayoutEffect, useRef, type KeyboardEvent as ReactKeyboardEvent, type ReactNode } from 'react'

import { getTopmostDialogLayer, registerDialogLayer } from './modalOwnership'
import { useBodyScrollLock } from './useBodyScrollLock'

interface DialogProps {
  title: string
  children: ReactNode
  onClose: () => void
  initialFocusRef?: React.RefObject<HTMLElement | null>
  restoreFocusRef?: React.RefObject<HTMLElement | null>
  closeDisabled?: boolean
  className?: string
}

const focusableSelector = 'button:not([disabled]), input:not([disabled]), textarea:not([disabled]), select:not([disabled]), [href], [tabindex]:not([tabindex="-1"])'

function isFocusDestination(candidate: HTMLElement | null | undefined, closingLayer: HTMLElement | null, topLayer: HTMLElement | null) {
  if (!candidate?.isConnected || candidate.ownerDocument !== document || candidate === document.body || candidate === document.documentElement) return false
  if (closingLayer?.contains(candidate) || (topLayer && !topLayer.contains(candidate))) return false
  if (candidate.matches(':disabled')) return false
  let current: HTMLElement | null = candidate
  while (current) {
    if (current.hidden || current.inert || current.hasAttribute('inert') || current.getAttribute('aria-hidden')?.toLowerCase() === 'true' || current.getAttribute('aria-disabled')?.toLowerCase() === 'true') return false
    const style = window.getComputedStyle(current)
    if (style.display === 'none' || style.visibility === 'hidden' || style.visibility === 'collapse' || style.opacity === '0' || style.contentVisibility === 'hidden') return false
    current = current.parentElement
  }
  return true
}

function tryFocus(candidate: HTMLElement | null | undefined, closingLayer: HTMLElement | null, topLayer: HTMLElement | null) {
  if (!isFocusDestination(candidate, closingLayer, topLayer)) return false
  try { candidate?.focus() } catch { return false }
  return document.activeElement === candidate
}

export function Dialog({ title, children, onClose, initialFocusRef, restoreFocusRef, closeDisabled = false, className = '' }: DialogProps) {
  const dialogRef = useRef<HTMLDivElement>(null)
  const headingRef = useRef<HTMLHeadingElement>(null)
  const titleId = useId()
  useBodyScrollLock(true)

  useLayoutEffect(() => {
    const prior = document.activeElement instanceof HTMLElement ? document.activeElement : null
    const restoreAtOpen = restoreFocusRef?.current ?? prior
    const layer = dialogRef.current?.closest<HTMLElement>('.dialog-layer') ?? null
    const focusDialogFallback = () => {
      const topLayer = getTopmostDialogLayer()
      if (tryFocus(headingRef.current, null, topLayer)) return
      for (const candidate of dialogRef.current?.querySelectorAll<HTMLElement>(focusableSelector) ?? []) {
        if (tryFocus(candidate, null, topLayer)) return
      }
    }
    const ownership = layer ? registerDialogLayer(layer, restoreAtOpen, focusDialogFallback) : { restoreTarget: restoreAtOpen, release: () => undefined }
    if (dialogRef.current) dialogRef.current.scrollTop = 0
    if (!layer || getTopmostDialogLayer() === layer) {
      initialFocusRef?.current?.focus()
      if (!initialFocusRef?.current) headingRef.current?.focus()
    }
    return () => {
      ownership.release()
      const focusAfterClose = () => {
        const topLayer = getTopmostDialogLayer()
        const active = document.activeElement instanceof HTMLElement ? document.activeElement : null
        if (topLayer?.contains(active) && isFocusDestination(active, layer, topLayer)) return
        // Restore flows may deliberately retarget focus when the original opener is removed.
        // eslint-disable-next-line react-hooks/exhaustive-deps
        const currentRestore = restoreFocusRef?.current
        if ([currentRestore, restoreAtOpen, ownership.restoreTarget].some((candidate) => tryFocus(candidate, layer, topLayer))) return
        const fallback = topLayer?.querySelector<HTMLElement>('[role="dialog"] h2[tabindex="-1"]')
        if (tryFocus(fallback, layer, topLayer)) return
        for (const candidate of topLayer?.querySelectorAll<HTMLElement>(focusableSelector) ?? []) {
          if (tryFocus(candidate, layer, topLayer)) return
        }
        if (!topLayer) {
          const routeHeading = document.querySelector<HTMLElement>('#main-content [data-route-heading="true"], main [data-route-heading="true"], [data-route-heading="true"]')
          if (tryFocus(routeHeading, layer, null)) return
          tryFocus(document.querySelector<HTMLElement>('#main-content[tabindex], main[tabindex]'), layer, null)
        }
      }
      focusAfterClose()
      // React may remove the previously focused dialog control after layout cleanup.
      // Re-assert the connected destination once that DOM mutation has settled.
      queueMicrotask(focusAfterClose)
    }
  }, [initialFocusRef, restoreFocusRef])

  useEffect(() => {
    function handleDocumentEscape(event: globalThis.KeyboardEvent) {
      if (event.key !== 'Escape') return
      const layer = dialogRef.current?.closest<HTMLElement>('.dialog-layer')
      if (!layer || getTopmostDialogLayer() !== layer) return
      event.preventDefault()
      event.stopPropagation()
      event.stopImmediatePropagation()
      if (!closeDisabled) onClose()
    }
    document.addEventListener('keydown', handleDocumentEscape, true)
    return () => document.removeEventListener('keydown', handleDocumentEscape, true)
  }, [closeDisabled, onClose])

  function handleKeyDown(event: ReactKeyboardEvent<HTMLDivElement>) {
    if (event.key !== 'Tab') return
    const dialog = dialogRef.current
    const items = Array.from(dialogRef.current?.querySelectorAll<HTMLElement>(focusableSelector) ?? [])
    const first = items.at(0); const last = items.at(-1)
    const active = document.activeElement instanceof HTMLElement ? document.activeElement : null
    if (items.length === 0) {
      event.preventDefault()
      if (!dialog?.contains(active)) headingRef.current?.focus()
      return
    }
    if (active === null || !items.includes(active)) {
      event.preventDefault()
      const destination = event.shiftKey ? last : first
      destination?.focus()
      return
    }
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus() }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus() }
  }

  return (
    <div className="dialog-layer" onMouseDown={(event) => {
      if (event.target !== event.currentTarget || getTopmostDialogLayer() !== event.currentTarget) return
      if (closeDisabled) { event.preventDefault(); return }
      onClose()
    }}>
      <div ref={dialogRef} className={`dialog ${className}`} role="dialog" aria-modal="true" aria-labelledby={titleId} onKeyDown={handleKeyDown}>
        <div className="dialog__header">
          <h2 ref={headingRef} id={titleId} tabIndex={-1}>{title}</h2>
          <button type="button" className="icon-button" aria-label={`Close ${title}`} disabled={closeDisabled} onPointerDown={(event) => { if (closeDisabled) event.preventDefault() }} onMouseDown={(event) => { if (closeDisabled) event.preventDefault() }} onClick={onClose}>×</button>
        </div>
        {children}
      </div>
    </div>
  )
}
