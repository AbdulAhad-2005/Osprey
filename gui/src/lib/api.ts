import type {
  AssetNode,
  ChatEvent,
  CytoGraph,
  Engagement,
  FindingSummary,
  Observation,
  ReportData,
  RecordReference,
} from "./types";
import { readEvents } from "./sse";

/**
 * API base. In dev, next.config rewrites proxy `/api/*` to the Osprey backend
 * so the browser stays same-origin (EventSource/stream friendly). Override for
 * a hosted split-origin deployment with NEXT_PUBLIC_API_BASE.
 */
export const API_BASE = process.env.NEXT_PUBLIC_API_BASE ?? "";

function url(path: string): string {
  return `${API_BASE}${path}`;
}

async function getJSON<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url(path), {
    ...init,
    headers: { "content-type": "application/json", ...(init?.headers ?? {}) },
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new ApiError(res.status, `${res.status} ${res.statusText} — ${body.slice(0, 300)}`);
  }
  return (await res.json()) as T;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

/* --- Health / engagements ------------------------------------------------ */

export async function getHealth(): Promise<{ ready: boolean; service?: string }> {
  return getJSON("/health");
}

export async function listEngagements(): Promise<Engagement[]> {
  const data = await getJSON<{ engagements?: Engagement[] } | Engagement[]>("/api/v1/engagements/");
  return Array.isArray(data) ? data : (data.engagements ?? []);
}

export async function getEngagement(id: string): Promise<Engagement> {
  return getJSON(`/api/v1/engagements/${encodeURIComponent(id)}`);
}

export async function resolveEngagement(target: string, forceNew = false): Promise<Engagement> {
  return getJSON("/api/v1/engagements/resolve", {
    method: "POST",
    body: JSON.stringify({ target, force_new: forceNew }),
  });
}

export async function createEngagement(target: string, name?: string): Promise<Engagement> {
  return getJSON("/api/v1/engagements/", {
    method: "POST",
    body: JSON.stringify({ target, name: name ?? "" }),
  });
}

export async function deleteEngagement(id: string): Promise<void> {
  const res = await fetch(url(`/api/v1/engagements/${encodeURIComponent(id)}`), { method: "DELETE" });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new ApiError(res.status, `${res.status} — ${body.slice(0, 200)}`);
  }
}

/* --- Settings: LLM config + models --------------------------------------- */

export interface LlmConfig {
  model: string;
  has_api_key: boolean;
  has_custom_base: boolean;
  max_tokens: number;
  temperature: number;
  max_agent_turns: number;
}

export interface ModelInfo {
  name: string;
  provider: string;
  description: string;
  active: boolean;
}

export interface LlmConfigResult {
  status: string;
  model: string;
  has_api_key: boolean;
  has_custom_base?: boolean;
  usable: boolean;
  reason: string;
}

export async function getConfig(): Promise<LlmConfig> {
  return getJSON("/api/v1/config/");
}

export async function setLlmConfig(body: {
  model?: string;
  api_key?: string;
  api_base?: string;
}): Promise<LlmConfigResult> {
  return getJSON("/api/v1/config/llm", { method: "POST", body: JSON.stringify(body) });
}

export async function reloadConfig(): Promise<{ status: string; model: string }> {
  return getJSON("/api/v1/config/reload", { method: "POST" });
}

export async function listModels(): Promise<ModelInfo[]> {
  const data = await getJSON<ModelInfo[] | { models?: ModelInfo[] }>("/api/v1/models/");
  return Array.isArray(data) ? data : (data.models ?? []);
}

export interface AgentStatus {
  model: string;
  model_active: boolean;
  tools_available: number;
}

export async function getAgentStatus(): Promise<AgentStatus> {
  return getJSON("/api/v1/agent/status");
}

export interface BackgroundJob {
  job_id:string; status:string; label:string; tool_name:string; command_preview:string;
  progress:string; results_log:string[]; error:string;
}

export function getBackgroundJobs(engagementId: string, signal?:AbortSignal):Promise<BackgroundJob[]> {
  return getJSON(`/api/v1/jobs?engagement_id=${encodeURIComponent(engagementId)}&limit=20`,{signal});
}

export function cancelBackgroundJob(id:string):Promise<BackgroundJob> {
  return getJSON(`/api/v1/jobs/${encodeURIComponent(id)}/cancel`,{method:"POST"});
}

export function getBackgroundJobResult(id:string, signal?:AbortSignal):Promise<Record<string,unknown>> {
  return getJSON(`/api/v1/jobs/${encodeURIComponent(id)}/result`,{signal});
}

/* --- Conversation history ------------------------------------------------ */

export interface StoredMessage {
  role: string;
  content: string;
  created_at?: string;
}

export async function getConversation(engagementId: string): Promise<StoredMessage[]> {
  const data = await getJSON<{ messages?: StoredMessage[] }>(
    `/api/v1/agent/conversation/${encodeURIComponent(engagementId)}`,
  );
  return data.messages ?? [];
}

export async function clearConversation(engagementId: string): Promise<void> {
  await getJSON(`/api/v1/agent/conversation/${encodeURIComponent(engagementId)}`, {
    method: "DELETE",
  });
}

export interface TranscriptPage {
  events: { id: number; run_id: string; event: ChatEvent["event"]; data: ChatEvent["data"] }[];
  cursor: number;
  active: boolean;
  has_more: boolean;
  legacy_messages: StoredMessage[];
  run: ChatRunState;
}

export interface ChatRunState {
  state: "idle" | "running" | "paused" | "interrupted" | "completed";
  resumable: boolean;
  reason?: string;
  run_id?: string;
  stage?: string;
  message?: string;
  elapsed_seconds?: number;
}

export async function startChat(engagementId: string, prompt: string): Promise<{accepted: boolean; run_id: string}> {
  const options = {method: "POST", body: JSON.stringify({engagement_id: engagementId, prompt, interrupt: true, request_id: crypto.randomUUID()})};
  try { return await getJSON("/api/v1/agent/chat/start", options); }
  catch (error) {
    if (error instanceof ApiError) throw error;
    // If the response was lost after admission, retry the same input identity.
    return getJSON("/api/v1/agent/chat/start", options);
  }
}

export function getTranscript(engagementId: string, after = 0, wait = 0, signal?: AbortSignal, includeLegacy = true): Promise<TranscriptPage> {
  return getJSON(`/api/v1/agent/chat-events/${encodeURIComponent(engagementId)}?after=${after}&wait_seconds=${wait}&include_legacy=${includeLegacy}`, { signal });
}

/* --- Findings (used by the chat sidebar glance + viz milestone) ---------- */

export async function listFindings(
  engagementId: string,
  signal?: AbortSignal,
): Promise<FindingSummary[]> {
  const data = await getJSON<{ findings?: FindingSummary[] } | FindingSummary[]>(
    `/api/v1/findings/?engagement_id=${encodeURIComponent(engagementId)}`,
    { signal },
  );
  return Array.isArray(data) ? data : (data.findings ?? []);
}

export async function listObservations(
  engagementId: string,
  signal?: AbortSignal,
): Promise<Observation[]> {
  const data = await getJSON<{ observations?: Observation[] }>(
    `/api/v1/observations/?engagement_id=${encodeURIComponent(engagementId)}&limit=2000`,
    { signal },
  );
  return data.observations ?? [];
}

export async function listAssets(
  engagementId: string,
  signal?: AbortSignal,
): Promise<AssetNode[]> {
  const data = await getJSON<{ assets?: AssetNode[] }>(
    `/api/v1/reasoning/assets?engagement_id=${encodeURIComponent(engagementId)}`,
    { signal },
  );
  return data.assets ?? [];
}

export async function getGraph(engagementId: string, signal?: AbortSignal): Promise<CytoGraph> {
  const data = await getJSON<{ data?: CytoGraph }>(
    `/api/v1/engagements/${encodeURIComponent(engagementId)}/visualization?format=json&max_nodes=5000&max_edges=20000&exclude_urls=false&preserve_records=true`,
    { signal },
  );
  return data.data ?? { nodes: [], edges: [] };
}

export async function getReport(engagementId: string, signal?: AbortSignal): Promise<ReportData> {
  const report = await getJSON<ReportData>(`/api/v1/report/${encodeURIComponent(engagementId)}`, { signal });
  if (report.error) throw new ApiError(404, report.error);
  return report;
}

export function getRecord(engagementId: string, record: RecordReference, signal?: AbortSignal): Promise<Record<string, unknown>> {
  const query = `engagement_id=${encodeURIComponent(engagementId)}`;
  const path = record.kind === "asset" ? `/api/v1/reasoning/asset?${query}&asset_id=${encodeURIComponent(record.id)}` :
    record.kind === "observation" ? `/api/v1/observations/${encodeURIComponent(record.id)}?${query}` :
    `/api/v1/findings/record/${encodeURIComponent(record.id)}?${query}`;
  return getJSON(path, {signal});
}

export async function browseEvidence(engagementId: string, kind: "observation" | "finding", page: number, query: string, signal?: AbortSignal): Promise<Record<string, unknown>[]> {
  const params = new URLSearchParams({engagement_id:engagementId,limit:"40",offset:String(page*40),q:query,exclude_noise:"false"});
  const result = await getJSON<{observations?: Record<string,unknown>[]; findings?:Record<string,unknown>[]}>(`/api/v1/${kind === "observation" ? "observations" : "findings"}/?${params}`,{signal});
  return (kind === "observation" ? result.observations : result.findings) || [];
}

export function reportMarkdownUrl(engagementId: string): string {
  return url(`/api/v1/report/${encodeURIComponent(engagementId)}/markdown`);
}

/* --- Interactive questions ----------------------------------------------- */

/* --- Run status / stop / live re-attach ---------------------------------- *
 * Chat runs execute in the backend as a background task (they survive a
 * refresh). A reconnecting client checks run-status and, if a run is live,
 * re-attaches to the shared event stream to show it. */

export async function getRunStatus(engagementId: string): Promise<boolean> {
  try {
    const d = await getJSON<{ active?: boolean }>(
      `/api/v1/agent/run-status/${encodeURIComponent(engagementId)}`,
    );
    return !!d.active;
  } catch {
    return false;
  }
}

export async function stopRun(engagementId: string): Promise<void> {
  await getJSON(`/api/v1/agent/stop/${encodeURIComponent(engagementId)}`, { method: "POST" });
}

/** Re-attach to an in-flight run's live events (read-only; no new prompt). */
export async function* attachChat(
  engagementId: string,
  signal?: AbortSignal,
  after = 0,
): AsyncGenerator<ChatEvent> {
  let cursor = after;
  while (!signal?.aborted) {
    const page = await getTranscript(engagementId, cursor, 20, signal);
    for (const record of page.events) {
      yield { event: record.event, data: { ...record.data, event_id: record.id, run_id: record.run_id } } as ChatEvent;
    }
    cursor = page.cursor;
    if (!page.active && !page.has_more) return;
  }
}

export async function answerQuestion(
  engagementId: string,
  questionId: string,
  answer: string,
): Promise<void> {
  const res = await getJSON<{ok: boolean; reason?: string}>(`/api/v1/agent/question/${encodeURIComponent(questionId)}/answer`, {
    method: "POST",
    body: JSON.stringify({ engagement_id: engagementId, answer }),
  });
  if (!res.ok) throw new Error(res.reason || "The answer was not accepted.");
}

/* --- Chat: POST + SSE streaming ------------------------------------------ *
 * EventSource is GET-only and cannot send a body, so the chat stream is a
 * POST whose text/event-stream response we parse by hand. Yields typed
 * ChatEvents. Honour an AbortSignal so the UI can stop a run. */

export interface ChatRequest {
  engagement_id: string;
  prompt: string;
  /** Replay mode for demos without an LLM key. */
  mock?: boolean;
}

export async function* streamChat(
  req: ChatRequest,
  signal?: AbortSignal,
): AsyncGenerator<ChatEvent> {
  // Note: this hits the Next streaming Route Handler at /stream/chat (same
  // origin). JSON and streaming handlers share lib/backendProxy.ts.
  const res = await fetch("/stream/chat", {
    method: "POST",
    headers: { "content-type": "application/json", accept: "text/event-stream" },
    body: JSON.stringify(req),
    signal,
  });
  if (!res.ok || !res.body) {
    const body = await res.text().catch(() => "");
    throw new ApiError(res.status, `chat stream failed: ${res.status} ${body.slice(0, 200)}`);
  }
  for await (const event of readEvents(res.body)) {
    yield event;
    if (event.event === "done") return;
  }
}
