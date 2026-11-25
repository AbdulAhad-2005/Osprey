"use client";

import { useEffect, useState } from "react";
import { Moon, Sun } from "lucide-react";

/** Light/dark switch. The initial class is set pre-paint by layout.tsx; this
 *  just reflects and flips it, persisting the explicit choice. */
export function ThemeToggle({ className = "btn-ghost p-1" }: { className?: string }) {
  const [dark, setDark] = useState<boolean | null>(null);

  useEffect(() => {
    setDark(document.documentElement.classList.contains("dark"));
  }, []);

  function toggle() {
    const next = !document.documentElement.classList.contains("dark");
    document.documentElement.classList.toggle("dark", next);
    try {
      localStorage.setItem("osprey-theme", next ? "dark" : "light");
    } catch {}
    setDark(next);
  }

  const label = dark ? "Switch to light theme" : "Switch to dark theme";
  return (
    <button onClick={toggle} className={className} title={label} aria-label={label}>
      {dark ? <Sun size={19} /> : <Moon size={19} />}
    </button>
  );
}
