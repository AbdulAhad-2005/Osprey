import type { Metadata, Viewport } from "next";
import "./globals.css";
import { WorkspaceProvider } from "@/components/shell/WorkspaceProvider";
import { AppShell } from "@/components/shell/AppShell";
import { BRAND } from "@/lib/brand";

export const metadata: Metadata = {
  title: `${BRAND} — Operator Console`,
  description:
    `${BRAND} operator console: an evidence-driven penetration-testing harness with live tool execution, attack-surface intelligence, and reporting.`,
  icons: {
    icon: "/osprey-mark.svg",
  },
};

export const viewport: Viewport = {
  themeColor: "#f7f9fc",
  colorScheme: "light",
};

/* Light by default; applies a saved dark choice before first paint so it never flashes. */
const THEME_BOOT = `try{var t=localStorage.getItem("osprey-theme");if(t==="dark")document.documentElement.classList.add("dark")}catch(e){}`;

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_BOOT }} />
        {/* Runtime webfonts (not fetched at build time, so builds stay hermetic;
            falls back to system fonts if the network is unavailable). */}
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          rel="stylesheet"
          href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap"
        />
      </head>
      <body>
        <WorkspaceProvider>
          <AppShell>{children}</AppShell>
        </WorkspaceProvider>
      </body>
    </html>
  );
}
