export type IconName =
  | 'activity'
  | 'command'
  | 'host'
  | 'memory'
  | 'menu'
  | 'scan'
  | 'settings'
  | 'swarm'

interface IconProps {
  name: IconName
  size?: number
}

export function Icon({ name, size = 20 }: IconProps) {
  return (
    <svg
      className="icon"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {name === 'swarm' && (
        <>
          <circle cx="12" cy="12" r="2.4" />
          <circle cx="5" cy="6" r="1.7" />
          <circle cx="19" cy="6" r="1.7" />
          <circle cx="5" cy="18" r="1.7" />
          <circle cx="19" cy="18" r="1.7" />
          <path d="m6.5 7.3 3.6 3m7.4-3-3.6 3m-7.4 6.4 3.6-3m7.4 3-3.6-3" />
        </>
      )}
      {name === 'memory' && (
        <>
          <path d="M5 4.5h11.5A2.5 2.5 0 0 1 19 7v12.5H7.5A2.5 2.5 0 0 1 5 17z" />
          <path d="M5 17a2.5 2.5 0 0 1 2.5-2.5H19M9 8h6" />
        </>
      )}
      {name === 'activity' && (
        <>
          <path d="M4 12h3l2-5 3.5 10 2.5-7 2 2h3" />
          <circle cx="12" cy="12" r="9" />
        </>
      )}
      {name === 'settings' && (
        <>
          <circle cx="12" cy="12" r="3" />
          <path d="M12 3v2m0 14v2m9-9h-2M5 12H3m15.4-6.4L17 7m-10 10-1.4 1.4m12.8 0L17 17M7 7 5.6 5.6" />
        </>
      )}
      {name === 'host' && (
        <>
          <rect x="4" y="4" width="16" height="12" rx="2" />
          <path d="M8 20h8m-4-4v4M7.5 8h.01M10.5 8h3" />
        </>
      )}
      {name === 'scan' && (
        <>
          <path d="M8 4H5a1 1 0 0 0-1 1v3m12-4h3a1 1 0 0 1 1 1v3M8 20H5a1 1 0 0 1-1-1v-3m12 4h3a1 1 0 0 0 1-1v-3" />
          <circle cx="12" cy="12" r="3" />
        </>
      )}
      {name === 'command' && (
        <>
          <rect x="4" y="5" width="16" height="14" rx="3" />
          <path d="m8 10 2 2-2 2m4 0h4" />
        </>
      )}
      {name === 'menu' && <path d="M4 7h16M4 12h16M4 17h16" />}
    </svg>
  )
}
