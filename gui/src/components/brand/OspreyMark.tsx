import { clsx } from "clsx";

/**
 * Osprey mark — a low-poly osprey in flight (raised "gull-wing" raptor
 * silhouette, head down and forward, white crown, single amber eye), faceted
 * in the brand's slate/navy palette. Adapted from the Osprey brand lockup.
 * Two modes:
 *   - full  (default): the faceted, full-colour brand mark
 *   - mono           : a single-fill silhouette in `currentColor` for small
 *                      placements, the favicon, and inline text runs
 *
 * viewBox is 132×112; callers pass a single `size` (the rendered width) and the
 * height follows the mark's aspect ratio.
 */
const RATIO = 112 / 132;

export function OspreyMark({
  size = 28,
  mono = false,
  className,
  title = "Osprey",
}: {
  size?: number;
  mono?: boolean;
  className?: string;
  title?: string;
}) {
  const common = {
    width: size,
    height: Math.round(size * RATIO),
    viewBox: "0 0 132 112",
    fill: "none",
    role: "img" as const,
    "aria-label": title,
  };

  if (mono) {
    // Flat silhouette: every facet filled with currentColor so the shape reads
    // as one solid mark at favicon / inline sizes.
    return (
      <svg {...common} className={className}>
        <g fill="currentColor">
          <path d="M74 53 L40 33 L8 15 L22 31 L46 45 Z" />
          <path d="M74 53 L46 45 L22 31 L30 40 L52 52 Z" />
          <path d="M74 53 L52 52 L30 40 L40 49 L70 60 Z" />
          <path d="M80 51 L108 34 L130 22 L118 35 L92 50 Z" />
          <path d="M80 51 L92 50 L118 35 L112 44 L86 56 Z" />
          <path d="M63 82 L49 110 L58 104 Z" />
          <path d="M66 82 L58 104 L67 106 L70 84 Z" />
          <path d="M69 82 L70 84 L67 106 L76 100 Z" />
          <path d="M70 60 L80 51 L86 56 L82 78 L68 86 L63 82 Z" />
          <path d="M82 78 L86 56 L90 66 L84 80 Z" />
          <path d="M86 56 L96 47 L106 57 L104 62 L90 66 Z" />
          <path d="M104 61 L117 66 L103 67 Z" />
        </g>
      </svg>
    );
  }

  return (
    <svg
      {...common}
      className={clsx("drop-shadow-[0_2px_6px_rgba(0,0,0,0.45)]", className)}
    >
      <defs>
        <linearGradient id="osp-wt" x1="0" y1="0" x2="0.3" y2="1">
          <stop offset="0" stopColor="#8d9cbb" />
          <stop offset="1" stopColor="#5a6c8c" />
        </linearGradient>
        <linearGradient id="osp-wb" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#2a3a56" />
          <stop offset="1" stopColor="#16213a" />
        </linearGradient>
        <linearGradient id="osp-wl" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#f1f4fa" />
          <stop offset="1" stopColor="#c7d1e1" />
        </linearGradient>
      </defs>

      {/* Left wing (far) — raised up-left, navy underside → slate → white leading */}
      <path d="M74 53 L40 33 L8 15 L22 31 L46 45 Z" fill="url(#osp-wb)" />
      <path d="M74 53 L46 45 L22 31 L30 40 L52 52 Z" fill="url(#osp-wt)" />
      <path d="M74 53 L52 52 L30 40 L40 49 L70 60 Z" fill="url(#osp-wl)" />

      {/* Right wing (near) — raised up-right */}
      <path d="M80 51 L108 34 L130 22 L118 35 L92 50 Z" fill="url(#osp-wt)" />
      <path d="M80 51 L92 50 L118 35 L112 44 L86 56 Z" fill="url(#osp-wb)" />

      {/* Tail — splayed feathers */}
      <path d="M63 82 L49 110 L58 104 Z" fill="url(#osp-wb)" />
      <path d="M66 82 L58 104 L67 106 L70 84 Z" fill="url(#osp-wt)" />
      <path d="M69 82 L70 84 L67 106 L76 100 Z" fill="url(#osp-wb)" />

      {/* Body / breast (white) */}
      <path d="M70 60 L80 51 L86 56 L82 78 L68 86 L63 82 Z" fill="url(#osp-wl)" />
      <path d="M82 78 L86 56 L90 66 L84 80 Z" fill="url(#osp-wt)" />

      {/* Head (white, facing right) */}
      <path d="M86 56 L96 47 L106 57 L104 62 L90 66 Z" fill="url(#osp-wl)" />
      {/* Dark eye-stripe / crown wedge */}
      <path d="M92 53 L104 60 L94 62 Z" fill="#1b2740" />
      {/* Beak */}
      <path d="M104 61 L117 66 L103 67 Z" fill="#0f1930" />
      {/* Amber eye */}
      <circle cx="99.5" cy="59.4" r="2.1" fill="#f5a623" />
      <circle cx="99.5" cy="59.4" r="0.8" fill="#1b2740" />
    </svg>
  );
}
