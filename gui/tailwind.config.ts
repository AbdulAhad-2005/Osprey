import type { Config } from "tailwindcss";

/**
 * Osprey design tokens.
 *
 * Brand: Logo 1 — a geometric osprey in flight. Deep navy base, slate mids,
 * off-white ink, a single amber "eye" accent. Dark-first; calm and spacious
 * like Claude desktop, but with the restrained, high-contrast seriousness a
 * security console wants. Colors are exposed both as Tailwind utilities and
 * as CSS variables (globals.css) so one source of truth drives both.
 */
const config: Config = {
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Structural surfaces (deep navy → raised slate)
        abyss: "#070b14",
        base: "#0a1020",
        surface: "#0e1526",
        "surface-2": "#141d31",
        "surface-3": "#1b2740",
        border: "#223049",
        "border-strong": "#2d3d59",

        // Ink
        ink: "#e8edf6",
        "ink-dim": "#94a2ba",
        "ink-faint": "#5d6b83",

        // Brand — amber osprey eye
        amber: {
          DEFAULT: "#f5a623",
          soft: "#f7b94e",
          deep: "#c47d10",
          glow: "rgba(245, 166, 35, 0.16)",
        },
        // Secondary — a cool slate-cyan for "live / in-flight" states
        signal: {
          DEFAULT: "#38bdf8",
          soft: "#7dd3fc",
          deep: "#0e7490",
        },

        // Severity ramp (reads clearly on deep navy)
        sev: {
          critical: "#ff5d6c",
          high: "#ff8a4c",
          medium: "#ffc53d",
          low: "#5eb0ef",
          info: "#8595ab",
        },
        ok: "#35c08f",
        warn: "#ffc53d",
        danger: "#ff5d6c",
      },
      fontFamily: {
        sans: ["var(--font-sans)", "ui-sans-serif", "system-ui", "sans-serif"],
        serif: ["var(--font-serif)", "ui-serif", "Georgia", "serif"],
        mono: [
          "var(--font-mono)",
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "monospace",
        ],
      },
      borderRadius: {
        xl: "0.875rem",
        "2xl": "1.125rem",
      },
      boxShadow: {
        card: "0 1px 0 0 rgba(255,255,255,0.02) inset, 0 8px 24px -12px rgba(0,0,0,0.6)",
        lift: "0 12px 40px -16px rgba(0,0,0,0.7)",
        "glow-amber": "0 0 0 1px rgba(245,166,35,0.35), 0 0 24px -6px rgba(245,166,35,0.35)",
      },
      keyframes: {
        "fade-in": {
          from: { opacity: "0", transform: "translateY(4px)" },
          to: { opacity: "1", transform: "none" },
        },
        "pulse-ring": {
          "0%": { boxShadow: "0 0 0 0 rgba(245,166,35,0.5)" },
          "70%": { boxShadow: "0 0 0 7px rgba(245,166,35,0)" },
          "100%": { boxShadow: "0 0 0 0 rgba(245,166,35,0)" },
        },
        shimmer: {
          "100%": { transform: "translateX(100%)" },
        },
        "caret-blink": {
          "0%,70%,100%": { opacity: "1" },
          "20%,50%": { opacity: "0" },
        },
      },
      animation: {
        "fade-in": "fade-in 0.22s ease-out",
        "pulse-ring": "pulse-ring 2s infinite",
        shimmer: "shimmer 1.6s infinite",
        "caret-blink": "caret-blink 1.1s steps(1) infinite",
      },
    },
  },
  plugins: [],
};

export default config;
