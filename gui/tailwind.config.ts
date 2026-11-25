import type { Config } from "tailwindcss";

/**
 * Osprey design tokens.
 *
 * A restrained, enterprise-grade system: cool neutral slate surfaces, one
 * confident blue accent, and a clear semantic ramp for severity/status. Every
 * colour resolves to a CSS variable (globals.css) holding an "R G B" triplet,
 * so a single token set drives both the light and dark themes and Tailwind's
 * opacity modifiers (`bg-accent/10`) keep working.
 */
const token = (name: string) => `rgb(var(--c-${name}) / <alpha-value>)`;

const config: Config = {
  darkMode: ["class", ".dark"],
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Structural surfaces
        abyss: token("abyss"), // recessed wells: code blocks, terminals
        base: token("base"), // page background
        surface: token("surface"), // cards, panels, sidebar
        "surface-2": token("surface-2"), // inputs, raised rows
        "surface-3": token("surface-3"), // hover / selected
        border: token("border"),
        "border-strong": token("border-strong"),

        // Ink
        ink: token("ink"),
        "ink-dim": token("ink-dim"),
        "ink-faint": token("ink-faint"),

        // Brand accent — primary actions, selection, links
        accent: {
          DEFAULT: token("accent"),
          soft: token("accent-soft"), // accent-coloured text on a tinted surface
          deep: token("accent-deep"), // pressed / hover fill
        },
        "on-accent": token("on-accent"),
        // Secondary — "live / in-flight" states
        signal: {
          DEFAULT: token("signal"),
          soft: token("signal-soft"),
          deep: token("signal-deep"),
        },

        // Severity ramp
        sev: {
          critical: token("sev-critical"),
          high: token("sev-high"),
          medium: token("sev-medium"),
          low: token("sev-low"),
          info: token("sev-info"),
        },
        ok: token("ok"),
        warn: token("warn"),
        danger: token("danger"),
      },
      fontFamily: {
        sans: ["var(--font-sans)", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: [
          "var(--font-mono)",
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "monospace",
        ],
      },
      borderRadius: {
        xl: "0.625rem",
        "2xl": "0.875rem",
      },
      boxShadow: {
        card: "0 1px 2px 0 rgb(var(--shadow) / 0.06), 0 1px 1px 0 rgb(var(--shadow) / 0.04)",
        lift: "0 8px 24px -8px rgb(var(--shadow) / 0.18), 0 2px 6px -2px rgb(var(--shadow) / 0.10)",
        focus: "0 0 0 3px rgb(var(--c-accent) / 0.22)",
      },
      keyframes: {
        "fade-in": {
          from: { opacity: "0", transform: "translateY(4px)" },
          to: { opacity: "1", transform: "none" },
        },
        "pulse-ring": {
          "0%": { boxShadow: "0 0 0 0 rgb(var(--c-ok) / 0.45)" },
          "70%": { boxShadow: "0 0 0 6px rgb(var(--c-ok) / 0)" },
          "100%": { boxShadow: "0 0 0 0 rgb(var(--c-ok) / 0)" },
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
