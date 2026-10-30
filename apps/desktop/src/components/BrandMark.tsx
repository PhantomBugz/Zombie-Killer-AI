import { useId } from 'react'

export function BrandMark() {
  const maskId = useId().replaceAll(':', '')

  return (
    <div className="brand-mark">
      <svg
        className="brand-mark__symbol"
        viewBox="0 0 48 48"
        aria-hidden="true"
        focusable="false"
      >
        <defs>
          <mask id={maskId}>
            <rect width="48" height="48" fill="black" />
            <rect x="14" y="14" width="20" height="20" rx="2" fill="white" />
            <path
              data-mark-part="negative-space-pulse"
              d="M16 18h16l-9 6h5l-7 7h12"
              fill="none"
              stroke="black"
              strokeLinecap="square"
              strokeLinejoin="miter"
              strokeWidth="3.2"
            />
          </mask>
        </defs>

        <rect
          data-mark-part="signal-field"
          x="14"
          y="14"
          width="20"
          height="20"
          rx="2"
          fill="currentColor"
          mask={`url(#${maskId})`}
        />
        <rect
          data-mark-part="chip-outline"
          x="10"
          y="9"
          width="28"
          height="30"
          rx="5"
          fill="none"
          stroke="currentColor"
          strokeWidth="2.5"
        />
        <path
          data-mark-part="exterior-traces"
          d="M17 3v4m7-4v4m7-4v4M17 41v4m7-4v4m7-4v4M4 17h4m-4 7h4m-4 7h4m36-14h4m-4 7h4m-4 7h4"
          fill="none"
          stroke="currentColor"
          strokeLinecap="square"
          strokeWidth="2"
        />
      </svg>
      <span className="brand-mark__word">Zombie Killer</span>
    </div>
  )
}
