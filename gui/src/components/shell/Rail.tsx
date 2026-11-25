"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Plus, List, Settings } from "lucide-react";
import { OspreyMark } from "@/components/brand/OspreyMark";
import { cn } from "@/lib/cn";
import { useWorkspace } from "./WorkspaceProvider";
import { ThemeToggle } from "./ThemeToggle";

/** Slim, always-visible navigation rail. The engagement list opens as a
 *  flyout beside it (see Sidebar) so the content area keeps its width. */
export function Rail() {
  const { sidebarCollapsed, toggleSidebar, backendUp } = useWorkspace();
  const pathname = usePathname();

  return (
    <nav
      aria-label="Primary"
      className="flex h-full w-[68px] flex-none flex-col items-center gap-2 border-r border-border bg-surface py-4"
    >
      <Link
        href="/"
        title="Home"
        className="mb-3 grid h-10 w-10 place-items-center rounded-xl bg-[#16213a] shadow-card ring-1 ring-inset ring-white/10 transition-transform hover:scale-105"
      >
        <OspreyMark size={24} />
      </Link>

      <RailButton title="New engagement" href="/" active={pathname === "/"}>
        <Plus size={19} strokeWidth={2.25} />
      </RailButton>
      <RailButton title={sidebarCollapsed ? "Show engagements" : "Hide engagements"} onClick={toggleSidebar} active={!sidebarCollapsed}>
        <List size={19} />
      </RailButton>

      <div className="flex-1" />

      <span
        title={backendUp == null ? "Connecting…" : backendUp ? "Backend live" : "Backend offline"}
        className={cn(
          "mb-1 h-2 w-2 rounded-full",
          backendUp == null ? "bg-ink-faint" : backendUp ? "bg-ok animate-pulse-ring" : "bg-danger",
        )}
      />
      <ThemeToggle className="grid h-10 w-10 place-items-center rounded-xl text-ink-dim transition-colors hover:bg-ink/[0.06] hover:text-ink" />
      <RailButton title="Settings" href="/settings" active={pathname.startsWith("/settings")}>
        <Settings size={19} />
      </RailButton>
    </nav>
  );
}

function RailButton({
  title,
  href,
  onClick,
  active,
  children,
}: {
  title: string;
  href?: string;
  onClick?: () => void;
  active?: boolean;
  children: React.ReactNode;
}) {
  const className = cn(
    "grid h-10 w-10 place-items-center rounded-xl transition-all",
    active
      ? "bg-accent/12 text-accent shadow-[inset_0_0_0_1px_rgb(var(--c-accent)/0.35)] dark:shadow-[inset_0_0_0_1px_rgb(var(--c-accent)/0.4),0_0_22px_-4px_rgb(var(--c-accent)/0.5)]"
      : "text-ink-dim hover:bg-ink/[0.06] hover:text-ink",
  );
  return href ? (
    <Link href={href} title={title} aria-label={title} className={className}>
      {children}
    </Link>
  ) : (
    <button onClick={onClick} title={title} aria-label={title} className={className}>
      {children}
    </button>
  );
}
