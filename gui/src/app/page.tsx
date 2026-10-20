"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { motion } from "framer-motion";
import { ArrowUp, Loader2, Radar, Globe, ShieldAlert, Fingerprint } from "lucide-react";
import { useWorkspace } from "@/components/shell/WorkspaceProvider";
import { OspreyMark } from "@/components/brand/OspreyMark";
import { resolveEngagement } from "@/lib/api";
import { cn } from "@/lib/cn";

function greeting(): string {
  const h = new Date().getHours();
  if (h < 5) return "Working late";
  if (h < 12) return "Good morning";
  if (h < 18) return "Good afternoon";
  return "Good evening";
}

const QUICK = [
  { icon: Radar, label: "Map the attack surface", prompt: "Map the full external attack surface — subdomains, live hosts, ports, services, and tech stack." },
  { icon: Globe, label: "Recon + OSINT", prompt: "Run recon and passive OSINT: subdomains, sister domains, emails, people, and exposed infrastructure." },
  { icon: ShieldAlert, label: "Full assessment", prompt: "Run a full assessment: recon, then vulnerability discovery against the live surface. Pause before any exploitation." },
  { icon: Fingerprint, label: "Find exposures", prompt: "Hunt for exposed credentials, secrets, and misconfigurations across the known surface." },
];

export default function HomePage() {
  const { engagements } = useWorkspace();
  const router = useRouter();
  const [target, setTarget] = useState("");
  const [intent, setIntent] = useState<string>("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function begin() {
    const t = target.trim();
    if (!t || busy) return;
    setBusy(true);
    setError(null);
    try {
      const eng = await resolveEngagement(t);
      const qp = intent ? `?intent=${encodeURIComponent(intent)}` : "";
      router.push(`/engagement/${encodeURIComponent(eng.id)}${qp}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not reach the backend to create the engagement.");
      setBusy(false);
    }
  }

  const recent = engagements.slice(0, 6);

  return (
    <div className="flex h-full flex-col items-center overflow-y-auto px-6">
      <div className="flex w-full max-w-2xl flex-1 flex-col justify-center py-16">
        {/* Soaring mark */}
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="mb-5 flex justify-center"
        >
          <motion.div
            animate={{ y: [0, -5, 0] }}
            transition={{ duration: 4.5, repeat: Infinity, ease: "easeInOut" }}
          >
            <OspreyMark size={64} />
          </motion.div>
        </motion.div>

        <motion.h1
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.05 }}
          className="text-center font-serif text-[34px] font-semibold tracking-tight text-ink"
        >
          {greeting()}, operator
        </motion.h1>
        <p className="mt-2 text-center text-[15px] text-ink-dim">
          Point Osprey at a target and start the hunt.
        </p>

        {/* Target composer */}
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.12 }}
          className="mt-8"
        >
          <div className="panel overflow-hidden shadow-lift focus-within:border-border-strong">
            <div className="flex items-center gap-3 px-4 pt-3.5">
              <span className="font-mono text-[13px] text-ink-faint">target</span>
              <input
                autoFocus
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && begin()}
                placeholder="example.com   ·   10.0.0.0/24   ·   https://app.example.com"
                className="w-full bg-transparent py-1 font-mono text-[15px] text-ink placeholder:text-ink-faint focus:outline-none"
              />
            </div>
            <div className="flex items-center justify-between px-3 pb-3 pt-3">
              <div className="flex flex-wrap gap-1.5">
                {QUICK.map((q) => (
                  <button
                    key={q.label}
                    onClick={() => setIntent(intent === q.prompt ? "" : q.prompt)}
                    className={cn(
                      "flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[12px] transition-colors",
                      intent === q.prompt
                        ? "border-amber/50 bg-amber/10 text-amber-soft"
                        : "border-border text-ink-dim hover:border-border-strong hover:text-ink",
                    )}
                  >
                    <q.icon size={12.5} />
                    {q.label}
                  </button>
                ))}
              </div>
              <button
                onClick={begin}
                disabled={!target.trim() || busy}
                className="grid h-9 w-9 flex-none place-items-center rounded-lg bg-amber text-abyss transition-colors hover:bg-amber-soft disabled:bg-surface-3 disabled:text-ink-faint"
                aria-label="Begin engagement"
              >
                {busy ? <Loader2 size={16} className="animate-spin" /> : <ArrowUp size={16} strokeWidth={2.5} />}
              </button>
            </div>
          </div>
          {intent && (
            <p className="mt-2 px-1 text-[12.5px] text-ink-faint">
              First instruction: <span className="text-ink-dim">{intent}</span>
            </p>
          )}
          {error && <p className="mt-2 px-1 text-[12.5px] text-danger">{error}</p>}
          <p className="mt-2 px-1 text-[11.5px] text-ink-faint">
            Authorized targets only. Osprey binds an engagement to this target and reuses prior
            findings unless you start fresh.
          </p>
        </motion.div>

        {/* Recent */}
        {recent.length > 0 && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.5, delay: 0.2 }}
            className="mt-10"
          >
            <div className="mb-2.5 text-[11px] font-medium uppercase tracking-wider text-ink-faint">
              Recent engagements
            </div>
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              {recent.map((e) => (
                <button
                  key={e.id}
                  onClick={() => router.push(`/engagement/${encodeURIComponent(e.id)}`)}
                  className="group flex items-center justify-between rounded-xl border border-border bg-surface/60 px-4 py-3 text-left transition-colors hover:border-border-strong hover:bg-surface-2"
                >
                  <div className="min-w-0">
                    <div className="truncate font-mono text-[13.5px] text-ink group-hover:text-amber-soft">
                      {e.target || e.id}
                    </div>
                    <div className="mt-0.5 text-[11.5px] text-ink-faint">
                      {e.findings_count} findings · {e.tools_executed} tools · {e.status}
                    </div>
                  </div>
                </button>
              ))}
            </div>
          </motion.div>
        )}
      </div>
    </div>
  );
}
