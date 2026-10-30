import { useEffect } from 'react'

import { acquireBodyScrollLock } from './modalOwnership'

export function useBodyScrollLock(active: boolean) {
  useEffect(() => {
    if (!active) {
      return
    }

    return acquireBodyScrollLock()
  }, [active])
}
