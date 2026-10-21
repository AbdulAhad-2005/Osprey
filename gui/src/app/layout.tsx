import type { Metadata, Viewport } from "next";
import "./globals.css";
import { WorkspaceProvider } from "@/components/shell/WorkspaceProvider";
import { AppShell } from "@/components/shell/AppShell";

export const metadata: Metadata = {
  title: "Osprey — Operator Console",
  description:
    "Osprey operator console: an evidence-driven penetration-testing harness with live tool execution, attack-surface intelligence, and reporting.",
  icons: {
    icon: "/osprey-mark.svg",
  },
};

export const viewport: Viewport = {
  themeColor: "#0a1020",
  colorScheme: "dark",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        {/* Runtime webfonts (not fetched at build time, so builds stay hermetic;
            falls back to system fonts if the network is unavailable). */}
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          rel="stylesheet"
          href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Newsreader:ital,wght@0,500;0,600;1,500&family=Quicksand:wght@500;600;700&family=JetBrains+Mono:wght@400;500&display=swap"
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
