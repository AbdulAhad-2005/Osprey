"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { ArrowRight, ChevronRight, Loader2, Crosshair } from "lucide-react";
import { useWorkspace } from "@/components/shell/WorkspaceProvider";
import { resolveEngagement } from "@/lib/api";
import { QUICK_INTENTS as QUICK } from "@/lib/intents";
import { cn } from "@/lib/cn";
import { BRAND } from "@/lib/brand";
import { TONE, type Tone } from "@/components/ui/primitives";

const STATUS_TONE: Record<string, Tone> = { active: "ok", running: "ok", paused: "warn", completed: "accent", failed: "danger" };

function greeting(): string {
  const h = new Date().getHours();
  if (h < 5) return "Working late";
  if (h < 12) return "Good morning";
  if (h < 18) return "Good afternoon";
  return "Good evening";
}

export default function HomePage() {
  const { engagements, refresh } = useWorkspace();
  const router = useRouter();
  const [target, setTarget] = useState("");
  const [intent, setIntent] = useState<string>("");
  const [forceNew, setForceNew] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function begin() {
    const t = target.trim();
    if (!t || busy) return;
    setBusy(true);
    setError(null);
    try {
      const eng = await resolveEngagement(t, forceNew);
      await refresh();
      const qp = intent ? `?intent=${encodeURIComponent(intent)}` : "";
      router.push(`/engagement/${encodeURIComponent(eng.id)}${qp}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not reach the backend to create the engagement.");
      setBusy(false);
    }
  }

  const recent = engagements.slice(0, 6);

  return (
    <div className="h-full overflow-y-auto">
      {/* Hero */}
      <section className="hero-bg relative overflow-hidden text-white">
        <img
          src="/osprey-mark.svg"
          alt=""
          aria-hidden
          className="pointer-events-none absolute -right-10 -top-10 w-[460px] select-none opacity-[0.12] [filter:brightness(3)_saturate(0)]"
        />
        <div className="relative mx-auto max-w-3xl px-8 pb-24 pt-12 text-center">
          <img src="/osprey-lockup-light.png" alt={BRAND} width={260} height={104} className="mx-auto h-auto w-[260px] select-none" draggable={false} />
          <p className="mt-7 text-[12px] font-semibold uppercase tracking-[0.16em] text-[#8db7ff]">{greeting()}</p>
          <h1 className="mt-2 text-[40px] font-bold leading-[1.06] tracking-[-0.035em]">
            Start an engagement.
            <br />
            <span className="text-[#8fa6d8]">Point {BRAND} at a target.</span>
          </h1>
        </div>
      </section>

      <div className="relative mx-auto -mt-14 max-w-3xl px-8 pb-14">
        {/* Composer */}
        <div className="rounded-2xl border border-border bg-surface shadow-lift transition-shadow focus-within:border-accent/60 focus-within:shadow-focus">
          <div className="px-5 pt-4">
            <label htmlFor="target" className="eyebrow">Target</label>
            <input
              id="target"
              autoFocus
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && begin()}
              placeholder="example.com   ·   10.0.0.0/24   ·   https://app.example.com"
              className="mt-1 w-full bg-transparent py-1.5 font-mono text-[17px] text-ink placeholder:text-ink-faint focus:outline-none"
            />
          </div>
          <div className="mt-3 border-t border-border px-5 py-3.5">
            <div className="eyebrow mb-2">First objective <span className="font-normal normal-case tracking-normal">(optional)</span></div>
            <div className="flex flex-wrap gap-2">
              {QUICK.map((q) => (
                <button
                  key={q.label}
                  onClick={() => setIntent(intent === q.prompt ? "" : q.prompt)}
                  aria-pressed={intent === q.prompt}
                  className={cn(
                    "flex items-center gap-2 rounded-lg border px-3 py-1.5 text-[12.5px] font-medium transition-colors",
                    intent === q.prompt
                      ? "border-accent bg-accent/10 text-accent-soft ring-1 ring-accent/30"
                      : "border-border bg-surface-2 text-ink-dim hover:border-border-strong hover:text-ink",
                  )}
                >
                  <q.icon size={14} />
                  {q.label}
                </button>
              ))}
            </div>
            {intent && <p className="mt-2 text-[12px] text-ink-faint">First instruction: <span className="text-ink-dim">{intent}</span></p>}
          </div>
          <div className="flex items-center justify-between gap-4 rounded-b-2xl border-t border-border bg-surface-2/60 px-5 py-3">
            <label className="flex items-center gap-2 text-[12.5px] text-ink-dim">
              <input type="checkbox" checked={forceNew} onChange={(event) => setForceNew(event.target.checked)} />
              Start fresh for this target
            </label>
            <button onClick={begin} disabled={!target.trim() || busy} className="btn-primary gap-2 px-5 disabled:opacity-50">
              {busy ? <Loader2 size={15} className="animate-spin" /> : null}
              Begin engagement
              {!busy && <ArrowRight size={15} />}
            </button>
          </div>
        </div>
        {error && <p className="mt-3 rounded-lg border border-danger/30 bg-danger/10 px-3 py-2 text-[12.5px] text-danger">{error}</p>}
        <p className="mt-3 text-center text-[12px] text-ink-faint">
          Authorized targets only. {BRAND} reuses prior findings for a target unless you start fresh.
        </p>

        {/* Recent */}
        {recent.length > 0 && (
          <section className="mt-12">
            <div className="mb-3 flex items-end justify-between">
              <div>
                <p className="eyebrow !text-accent">Pick up where you left off</p>
                <h2 className="mt-1 text-[20px] font-bold tracking-[-0.02em] text-ink">Recent engagements</h2>
              </div>
              <span className="text-[12.5px] text-ink-faint">{engagements.length.toLocaleString()} total</span>
            </div>
            <ul className="divide-y divide-border overflow-hidden rounded-2xl border border-border bg-surface shadow-card">
              {recent.map((e) => {
                const tone = STATUS_TONE[e.status.toLowerCase()] ?? "neutral";
                return (
                  <li key={e.id}>
                    <button
                      onClick={() => router.push(`/engagement/${encodeURIComponent(e.id)}`)}
                      className="group flex w-full items-center gap-4 px-5 py-3.5 text-left transition-colors hover:bg-accent/[0.05]"
                    >
                      <span className={cn("grid h-9 w-9 flex-none place-items-center rounded-lg", TONE[tone].chip)}>
                        <Crosshair size={17} />
                      </span>
                      <div className="min-w-0 flex-1">
                        <div className="truncate font-mono text-[14px] font-medium text-ink group-hover:text-accent-soft">{e.target || e.id}</div>
                        <div className="mt-0.5 text-[12px] text-ink-faint">
                          {e.tools_executed.toLocaleString()} tools run · {e.findings_count.toLocaleString()} records
                        </div>
                      </div>
                      <span className={cn("rounded-full border px-2.5 py-0.5 text-[11px] font-semibold capitalize", TONE[tone].soft)}>{e.status}</span>
                      <ChevronRight size={16} className="flex-none text-ink-faint transition-transform group-hover:translate-x-0.5" />
                    </button>
                  </li>
                );
              })}
            </ul>
          </section>
        )}
      </div>
    </div>
  );
}
