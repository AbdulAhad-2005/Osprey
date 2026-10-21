"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  ArrowLeft,
  BrainCircuit,
  Check,
  KeyRound,
  Loader2,
  RefreshCw,
  ServerCog,
  TriangleAlert,
} from "lucide-react";
import {
  getAgentStatus,
  getConfig,
  getHealth,
  listModels,
  reloadConfig,
  setLlmConfig,
  type AgentStatus,
  type LlmConfig,
  type ModelInfo,
} from "@/lib/api";
import { cn } from "@/lib/cn";

export function SettingsView() {
  const [cfg, setCfg] = useState<LlmConfig | null>(null);
  const [models, setModels] = useState<ModelInfo[]>([]);
  const [status, setStatus] = useState<AgentStatus | null>(null);
  const [backendUp, setBackendUp] = useState<boolean | null>(null);
  const [loading, setLoading] = useState(true);

  // Editable fields
  const [model, setModel] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [apiBase, setApiBase] = useState("");
  const [baseChanged, setBaseChanged] = useState(false);
  const [removeKey, setRemoveKey] = useState(false);
  const [saving, setSaving] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; message: string } | null>(null);

  async function refresh() {
    setLoading(true);
    const [c, m, s, h] = await Promise.allSettled([getConfig(), listModels(), getAgentStatus(), getHealth()]);
    if (c.status === "fulfilled") {
      setCfg(c.value);
      setModel(c.value.model);
      setApiBase("");
      setBaseChanged(false);
    } else {
      setCfg(null);
      setResult({ok:false,message:"Could not read the current settings. Retry Reload before saving to avoid replacing an unknown configuration."});
    }
    if (m.status === "fulfilled") setModels(m.value);
    if (s.status === "fulfilled") setStatus(s.value);
    setBackendUp(h.status === "fulfilled" ? !!h.value.ready : false);
    setLoading(false);
  }

  useEffect(() => {
    void refresh();
  }, []);

  async function save() {
    setSaving(true);
    setResult(null);
    try {
      const body: { model?: string; api_key?: string; api_base?: string } = {};
      body.model = model.trim();
      if (apiKey.trim() || removeKey) body.api_key = removeKey ? "" : apiKey.trim();
      if (baseChanged) body.api_base = apiBase.trim();
      const res = await setLlmConfig(body);
      setResult({
        ok: res.usable,
        message: res.usable
          ? `Saved. Active model: ${res.model}.`
          : `Saved, but not usable yet: ${res.reason || "check the model id and key."}`,
      });
      setApiKey("");
      setRemoveKey(false);
      setBaseChanged(false);
      await refresh();
    } catch (e) {
      setResult({ ok: false, message: e instanceof Error ? e.message : "Failed to save." });
    } finally {
      setSaving(false);
    }
  }

  async function doReload() {
    setSaving(true);
    try {
      await reloadConfig();
      await refresh();
      setResult({ ok: true, message: "Reloaded config and tool availability from .env." });
    } catch (e) {
      setResult({ ok: false, message: e instanceof Error ? e.message : "Reload failed." });
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto max-w-2xl px-6 py-8">
        <Link href="/" className="mb-6 inline-flex items-center gap-1.5 text-[13px] text-ink-dim hover:text-ink">
          <ArrowLeft size={14} /> Back
        </Link>
        <h1 className="font-serif text-[28px] font-semibold tracking-tight text-ink">Settings</h1>
        <p className="mt-1 text-[14px] text-ink-dim">
          Configure the model that drives Osprey and check the backend. These settings apply to this
          local instance and are stored in the project <code className="font-mono text-ink-faint">.env</code>.
        </p>

        {loading ? (
          <div className="mt-10 flex items-center gap-2 text-ink-faint">
            <Loader2 size={16} className="animate-spin" /> Loading settings…
          </div>
        ) : (
          <>
            {/* Model card */}
            <section className="panel mt-6 p-5">
              <div className="flex items-center gap-2">
                <BrainCircuit size={17} className="text-amber" />
                <h2 className="text-[15px] font-semibold text-ink">Model / LLM provider</h2>
                {cfg && (
                  <span
                    className={cn(
                      "ml-auto inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px]",
                      status?.model_active ? "bg-ok/15 text-ok" : "bg-danger/15 text-danger",
                    )}
                  >
                    {status?.model_active ? <Check size={11} /> : <TriangleAlert size={11} />}
                    {status?.model_active ? "configured" : "not configured"}
                  </span>
                )}
              </div>
              <p className="mt-1.5 text-[12.5px] text-ink-faint">
                Any LiteLLM model id — e.g. <code className="font-mono">anthropic/claude-sonnet-4</code>,{" "}
                <code className="font-mono">openrouter/meta-llama/llama-3.1-70b-instruct</code>,{" "}
                <code className="font-mono">groq/llama-3.1-8b-instant</code>, or{" "}
                <code className="font-mono">ollama/llama3.1</code> (local).
              </p>

              <label htmlFor="model-id" className="mt-4 block text-[12px] font-medium text-ink-dim">Model id</label>
              <input
                id="model-id"
                list="osprey-models"
                value={model}
                onChange={(e) => setModel(e.target.value)}
                placeholder="provider/model-name"
                className="mt-1 w-full rounded-lg border border-border bg-base/60 px-3 py-2 font-mono text-[13px] text-ink placeholder:text-ink-faint focus:border-border-strong focus:outline-none"
              />
              <datalist id="osprey-models">
                {models.map((m) => (
                  <option key={m.name} value={m.name}>
                    {m.provider} — {m.description}
                  </option>
                ))}
              </datalist>

              <label htmlFor="api-key" className="mt-4 block text-[12px] font-medium text-ink-dim">
                API key {cfg?.has_api_key && <span className="text-ink-faint">· currently set</span>}
              </label>
              <div className="mt-1 flex items-center gap-2 rounded-lg border border-border bg-base/60 px-3 focus-within:border-border-strong">
                <KeyRound size={14} className="text-ink-faint" />
                <input
                  id="api-key"
                  type="password"
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  placeholder={cfg?.has_api_key ? "•••••••• (leave blank to keep)" : "paste provider API key"}
                  className="w-full bg-transparent py-2 font-mono text-[13px] text-ink placeholder:text-ink-faint focus:outline-none"
                  autoComplete="off"
                />
              </div>
              {cfg?.has_api_key && <label className="mt-2 flex gap-2 text-xs text-ink-dim"><input type="checkbox" checked={removeKey} onChange={(e) => setRemoveKey(e.target.checked)} /> Remove saved key</label>}
              {model.split("/")[0] !== cfg?.model.split("/")[0] && <p className="mt-2 text-xs text-amber-soft">Changing providers clears the previous key and custom URL. Enter credentials for the new provider.</p>}

              <label htmlFor="api-base" className="mt-4 block text-[12px] font-medium text-ink-dim">
                API base URL <span className="text-ink-faint">· optional (proxies / local Ollama)</span>
              </label>
              <input
                id="api-base"
                value={apiBase}
                onChange={(e) => { setApiBase(e.target.value); setBaseChanged(true); }}
                placeholder={cfg?.has_custom_base ? "custom base set — blank keeps it" : "https://… (leave blank for default)"}
                className="mt-1 w-full rounded-lg border border-border bg-base/60 px-3 py-2 font-mono text-[13px] text-ink placeholder:text-ink-faint focus:border-border-strong focus:outline-none"
              />
              {cfg?.has_custom_base && <button className="btn-ghost mt-1 text-xs" onClick={() => { setApiBase(""); setBaseChanged(true); }}>Use provider default URL</button>}

              <div className="mt-4 flex items-center gap-2">
                <button onClick={save} disabled={saving || !cfg || !model.trim()} className="btn-primary">
                  {saving ? <Loader2 size={14} className="animate-spin" /> : <Check size={14} />} Save & apply
                </button>
                <button onClick={doReload} disabled={saving} className="btn-outline" title="Re-read .env and tools">
                  <RefreshCw size={13} /> Reload from .env
                </button>
              </div>

              {result && (
                <div
                  className={cn(
                    "mt-3 rounded-lg border px-3 py-2 text-[12.5px]",
                    result.ok ? "border-ok/30 bg-ok/10 text-ok" : "border-danger/30 bg-danger/10 text-danger",
                  )}
                >
                  {result.message}
                </div>
              )}

              <p className="mt-3 text-[11.5px] text-ink-faint">
                The key is written to <code className="font-mono">.env</code> on this machine and never shown
                back here. Configuration checks do not verify network access, API-key validity, or tool-calling support. Changes apply to the next message; a running assessment keeps its current model.
              </p>
            </section>

            {/* Backend & tools card */}
            <section className="panel mt-4 p-5">
              <div className="flex items-center gap-2">
                <ServerCog size={17} className="text-amber" />
                <h2 className="text-[15px] font-semibold text-ink">Backend &amp; tools</h2>
                <span
                  className={cn(
                    "ml-auto inline-flex items-center gap-1.5 text-[12px]",
                    backendUp ? "text-ok" : "text-danger",
                  )}
                >
                  <span className={cn("h-1.5 w-1.5 rounded-full", backendUp ? "bg-ok" : "bg-danger")} />
                  {backendUp == null ? "—" : backendUp ? "live" : "offline"}
                </span>
              </div>
              <dl className="mt-3 grid grid-cols-2 gap-3">
                <Stat label="Active model" value={status?.model || cfg?.model || "—"} mono />
                <Stat label="Tools available" value={status ? String(status.tools_available) : "—"} />
                <Stat label="Max agent turns" value={cfg ? String(cfg.max_agent_turns) : "—"} />
                <Stat label="Temperature" value={cfg ? String(cfg.temperature) : "—"} />
              </dl>
              <p className="mt-3 text-[11.5px] text-ink-faint">
                Tool availability is cached for the backend process; after starting/stopping the Kali tools
                container, hit <span className="text-ink-dim">Reload from .env</span> above to refresh it.
              </p>
            </section>
          </>
        )}
      </div>
    </div>
  );
}

function Stat({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="rounded-lg border border-border bg-base/40 px-3 py-2">
      <dt className="text-[11px] uppercase tracking-wider text-ink-faint">{label}</dt>
      <dd className={cn("mt-0.5 truncate text-[13px] text-ink", mono && "font-mono")} title={value}>
        {value}
      </dd>
    </div>
  );
}
