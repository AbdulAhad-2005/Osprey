import type { AssetNode, ChatEvent, Engagement, FindingSummary, Observation, ReportData } from "./types";

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
  await fetch(url(`/api/v1/agent/conversation/${encodeURIComponent(engagementId)}`), {
    method: "DELETE",
  });
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

export async function getReport(engagementId: string, signal?: AbortSignal): Promise<ReportData> {
  return getJSON<ReportData>(`/api/v1/report/${encodeURIComponent(engagementId)}`, { signal });
}

export function reportMarkdownUrl(engagementId: string): string {
  return url(`/api/v1/report/${encodeURIComponent(engagementId)}/markdown`);
}

/* --- Interactive questions ----------------------------------------------- */

export async function answerQuestion(
  engagementId: string,
  questionId: string,
  answer: string,
): Promise<void> {
  await getJSON(`/api/v1/agent/question/${encodeURIComponent(questionId)}/answer`, {
    method: "POST",
    body: JSON.stringify({ engagement_id: engagementId, answer }),
  });
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
  const res = await fetch(url("/api/v1/agent/chat"), {
    method: "POST",
    headers: { "content-type": "application/json", accept: "text/event-stream" },
    body: JSON.stringify(req),
    signal,
  });
  if (!res.ok || !res.body) {
    const body = await res.text().catch(() => "");
    throw new ApiError(res.status, `chat stream failed: ${res.status} ${body.slice(0, 200)}`);
  }
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      // SSE frames are separated by a blank line.
      let sep: number;
      while ((sep = buffer.indexOf("\n\n")) !== -1) {
        const frame = buffer.slice(0, sep);
        buffer = buffer.slice(sep + 2);
        const parsed = parseFrame(frame);
        if (parsed) yield parsed;
      }
    }
  } finally {
    reader.releaseLock();
  }
}

function parseFrame(frame: string): ChatEvent | null {
  let eventName = "message";
  const dataLines: string[] = [];
  for (const line of frame.split("\n")) {
    if (line.startsWith(":")) continue; // comment / keepalive
    if (line.startsWith("event:")) eventName = line.slice(6).trim();
    else if (line.startsWith("data:")) dataLines.push(line.slice(5).replace(/^ /, ""));
  }
  if (dataLines.length === 0) return null;
  try {
    const data = JSON.parse(dataLines.join("\n"));
    return { event: eventName, data } as ChatEvent;
  } catch {
    return null;
  }
}
