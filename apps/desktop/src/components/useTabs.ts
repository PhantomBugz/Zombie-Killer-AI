import { useId, useRef, type KeyboardEvent } from 'react'

export function useTabs<T extends string>(items: readonly T[], selected: T, onSelect: (item: T) => void) {
  const id = useId().replaceAll(':', '')
  const refs = useRef<Array<HTMLButtonElement | null>>([])
  const selectedIndex = Math.max(0, items.indexOf(selected))
  function choose(index: number) {
    const item = items[index]
    if (!item) return
    onSelect(item)
    refs.current[index]?.focus()
  }
  function onKeyDown(event: KeyboardEvent<HTMLButtonElement>) {
    let index: number | undefined
    if (event.key === 'ArrowRight') index = (selectedIndex + 1) % items.length
    else if (event.key === 'ArrowLeft') index = (selectedIndex - 1 + items.length) % items.length
    else if (event.key === 'Home') index = 0
    else if (event.key === 'End') index = items.length - 1
    if (index === undefined) return
    event.preventDefault(); choose(index)
  }
  const slug = (item: T) => item.toLowerCase().replaceAll(/[^a-z0-9]+/g, '-')
  return {
    focus: (item: T) => refs.current[items.indexOf(item)]?.focus(),
    tabProps: (item: T, index: number) => ({
      id: `${id}-tab-${slug(item)}`, 'aria-controls': `${id}-panel-${slug(item)}`,
      'aria-selected': selected === item, tabIndex: selected === item ? 0 : -1,
      ref: (element: HTMLButtonElement | null) => { refs.current[index] = element },
      onClick: () => onSelect(item), onKeyDown,
    }),
    panelProps: { id: `${id}-panel-${slug(selected)}`, 'aria-labelledby': `${id}-tab-${slug(selected)}` },
  }
}
