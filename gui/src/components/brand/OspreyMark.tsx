import { clsx } from "clsx";

/**
 * Osprey mark — a geometric osprey in flight (the characteristic bent
 * "gull-wing" raptor silhouette), faceted in navy/slate with a single amber
 * eye. Two modes:
 *   - full  (default): the faceted, full-colour brand mark
 *   - mono           : a single-fill silhouette in `currentColor` for small
 *                      placements, the favicon, and inline text runs
 */
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
  if (mono) {
    return (
      <svg
        width={size}
        height={size * (72 / 120)}
        viewBox="0 0 120 72"
        fill="none"
        className={className}
        role="img"
        aria-label={title}
      >
        <path d={WING_L + " " + WING_R + " " + BODY} fill="currentColor" />
      </svg>
    );
  }
  return (
    <svg
      width={size}
      height={size * (72 / 120)}
      viewBox="0 0 120 72"
      fill="none"
      className={clsx("drop-shadow-[0_2px_6px_rgba(0,0,0,0.45)]", className)}
      role="img"
      aria-label={title}
    >
      <defs>
        <linearGradient id="osp-wing-top" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#6c7e9e" />
          <stop offset="1" stopColor="#47597a" />
        </linearGradient>
        <linearGradient id="osp-wing-bot" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#223249" />
          <stop offset="1" stopColor="#141f36" />
        </linearGradient>
      </defs>

      {/* Left wing — lower facet (dark), then upper facet (light) on top */}
      <path d={WING_L_BOT} fill="url(#osp-wing-bot)" />
      <path d={WING_L_TOP} fill="url(#osp-wing-top)" />
      {/* Right wing */}
      <path d={WING_R_BOT} fill="url(#osp-wing-bot)" />
      <path d={WING_R_TOP} fill="url(#osp-wing-top)" />

      {/* Body + tail spindle */}
      <path d={BODY} fill="#101a30" />
      {/* Chest highlight */}
      <path d="M60 19 L63.4 30 L60 33 L56.6 30 Z" fill="#dfe6f2" opacity="0.92" />
      {/* Head cap */}
      <path d="M60 15 L64 23 L56 23 Z" fill="#0c1628" />
      {/* Amber eye */}
      <circle cx="60" cy="22.4" r="1.7" fill="#f5a623" />
    </svg>
  );
}

/* --- Geometry (viewBox 120×72, symmetric about x=60) ---------------------- */
// Left wing split into an upper (leading) feather facet and a lower facet.
const WING_L_TOP = "M54 28 L26 14.5 L3 32 L32 27 Z";
const WING_L_BOT = "M32 27 L3 32 L35 31 L54 40 Z";
// Right wing = mirror.
const WING_R_TOP = "M66 28 L94 14.5 L117 32 L88 27 Z";
const WING_R_BOT = "M88 27 L117 32 L85 31 L66 40 Z";
// Full wings (used by the mono silhouette).
const WING_L = "M54 28 L26 14.5 L3 32 L35 31 L54 40 Z";
const WING_R = "M66 28 L94 14.5 L117 32 L85 31 L66 40 Z";
// Body + tapered tail.
const BODY = "M56 30 L60 15 L64 30 L61 60 L59 60 Z";
