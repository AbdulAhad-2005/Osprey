"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { ChatEvent, ChatTurn } from "@/lib/types";
import { answerQuestion as apiAnswer, getConversation, streamChat } from "@/lib/api";
import { applyEvent, answerQuestionBlock, uid, userTurn } from "@/lib/chatReducer";

export type ChatActivity =
  | { kind: "idle" }
  | { kind: "thinking" }
  | { kind: "waiting"; elapsed: number }
  | { kind: "working" }
  | { kind: "error"; message: string };

export interface UseChat {
  turns: ChatTurn[];
  activity: ChatActivity;
  streaming: boolean;
  send: (prompt: string) => void;
  answer: (questionId: string, value: string) => void;
  stop: () => void;
  clear: () => void;
}

export function useChat(engagementId: string, opts?: { mock?: boolean }): UseChat {
  const [turns, setTurns] = useState<ChatTurn[]>([]);
  const [activity, setActivity] = useState<ChatActivity>({ kind: "idle" });
  const [streaming, setStreaming] = useState(false);
  const abortRef = useRef<AbortController | null>(null);
  const mock = opts?.mock ?? false;

  // Load persisted conversation (text-only; live turns carry full tool detail).
  useEffect(() => {
    let cancelled = false;
    if (!engagementId || mock) {
      setTurns([]);
      return;
    }
    getConversation(engagementId)
      .then((messages) => {
        if (cancelled) return;
        setTurns(
          messages
            .filter((m) => m.role === "user" || m.role === "assistant")
            .map((m) =>
              m.role === "user"
                ? userTurn(m.content)
                : {
                    id: uid("a"),
                    role: "assistant" as const,
                    blocks: m.content.trim()
                      ? [{ kind: "text" as const, id: uid("x"), content: m.content }]
                      : [],
                  },
            ),
        );
      })
      .catch(() => {
        /* no history / backend down — start clean */
      });
    return () => {
      cancelled = true;
    };
  }, [engagementId, mock]);

  const runStream = useCallback(
    async (prompt: string) => {
      const ctrl = new AbortController();
      abortRef.current = ctrl;
      setStreaming(true);
      setActivity({ kind: "thinking" });
      try {
        const source = mock ? mockStream(prompt) : streamChat({ engagement_id: engagementId, prompt }, ctrl.signal);
        for await (const ev of source) {
          applyActivity(ev, setActivity);
          const folded = foldsIntoTurns(ev);
          if (folded) setTurns((prev) => applyEvent(prev, ev));
        }
      } catch (e) {
        if ((e as Error)?.name !== "AbortError") {
          // A transport drop (vs. an explicit backend error event) — keep it
          // calm and non-destructive: the partial turn stays, and durable
          // findings are already saved server-side.
          const raw = e instanceof Error ? e.message : "stream failed";
          const message = /fetch|network|stream|load failed|Failed to fetch/i.test(raw)
            ? "Connection to Osprey was interrupted. Any findings so far are saved — send another message to continue."
            : raw;
          setActivity({ kind: "error", message });
          setTurns((prev) => applyEvent(prev, { event: "error", data: { message } }));
        }
      } finally {
        setStreaming(false);
        setActivity((a) => (a.kind === "error" ? a : { kind: "idle" }));
        // Never leave an assistant turn stuck in the streaming state if the
        // stream ended without a terminal event (abnormal close / cancel).
        setTurns((prev) => applyEvent(prev, { event: "done", data: { content: "" } }));
        abortRef.current = null;
      }
    },
    [engagementId, mock],
  );

  const send = useCallback(
    (prompt: string) => {
      const p = prompt.trim();
      if (!p || streaming) return;
      setTurns((prev) => [...prev, userTurn(p)]);
      void runStream(p);
    },
    [runStream, streaming],
  );

  const answer = useCallback(
    (questionId: string, value: string) => {
      setTurns((prev) => answerQuestionBlock(prev, questionId, value));
      if (!mock) void apiAnswer(engagementId, questionId, value).catch(() => {});
    },
    [engagementId, mock],
  );

  const stop = useCallback(() => {
    abortRef.current?.abort();
    setStreaming(false);
    setActivity({ kind: "idle" });
  }, []);

  const clear = useCallback(() => {
    stop();
    setTurns([]);
  }, [stop]);

  return { turns, activity, streaming, send, answer, stop, clear };
}

function foldsIntoTurns(ev: ChatEvent): boolean {
  return !["llm_call_start", "llm_still_waiting", "compaction", "message_start"].includes(ev.event);
}

function applyActivity(ev: ChatEvent, set: (a: ChatActivity) => void) {
  switch (ev.event) {
    case "llm_call_start":
      set({ kind: "thinking" });
      break;
    case "llm_still_waiting":
      set({ kind: "waiting", elapsed: ev.data.elapsed_seconds });
      break;
    case "tool_start":
      set({ kind: "working" });
      break;
    case "assistant":
    case "thinking":
      set({ kind: "thinking" });
      break;
    case "done":
    case "cancelled":
      set({ kind: "idle" });
      break;
    default:
      break;
  }
}

/* --- Mock stream: a scripted run so the UI is fully demoable without an LLM
 * key or a live backend. Exercises every block type: thinking, parallel tools,
 * an interactive exploitation gate, and a final answer. ------------------- */
async function* mockStream(prompt: string): AsyncGenerator<ChatEvent> {
  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
  yield { event: "llm_call_start", data: {} };
  await sleep(500);
  yield {
    event: "thinking",
    data: { content: "Binding the engagement and widening the external surface first — subdomains from multiple sources, then resolve and probe what's live." },
  };
  await sleep(400);
  yield { event: "tool_start", data: { tool_name: "subfinder_scan", tool_call_id: "t1", arguments: JSON.stringify({ domain: "example.com" }) } };
  yield { event: "tool_start", data: { tool_name: "crt_sh_query", tool_call_id: "t2", arguments: JSON.stringify({ domain: "example.com" }) } };
  await sleep(900);
  yield {
    event: "tool_end",
    data: { tool_name: "subfinder_scan", tool_call_id: "t1", success: true, duration_seconds: 7.4, result: "success: true\nfound 23 subdomains\napi.example.com\napp.example.com\nstaging.example.com\nmail.example.com\nvpn.example.com\n…", finding_titles: ["23 subdomains"] },
  };
  await sleep(500);
  yield {
    event: "tool_end",
    data: { tool_name: "crt_sh_query", tool_call_id: "t2", success: true, duration_seconds: 2.1, result: "success: true\n9 names from certificate transparency\ninternal.example.com\ndev-api.example.com\n…", finding_titles: ["2 new names"] },
  };
  await sleep(400);
  yield { event: "assistant", data: { content: "Found **25 unique subdomains**. `dev-api.example.com` and `staging.example.com` look like non-production surface worth a closer look. Probing which are live now." } };
  await sleep(500);
  yield { event: "tool_start", data: { tool_name: "httpx_probe", tool_call_id: "t3", arguments: JSON.stringify({ hosts: "25 subdomains" }) } };
  await sleep(1100);
  yield { event: "tool_end", data: { tool_name: "httpx_probe", tool_call_id: "t3", success: true, duration_seconds: 11.2, result: "success: true\n14 live hosts\napp.example.com [200] nginx, React\napi.example.com [401] kong\ndev-api.example.com [200] Express, debug=true\n…", finding_titles: ["14 live hosts", "dev-api debug exposed"] } };
  await sleep(500);
  yield {
    event: "question",
    data: {
      id: "gate1",
      kind: "gate",
      text: "Recon surfaced a likely-exploitable exposure (`dev-api.example.com` running with `debug=true`). Do you want to proceed into the exploitation phase, or stop at findings and generate a report?",
      options: [
        { value: "exploit", label: "Proceed to exploitation", detail: "Attempt validated exploitation of confirmed issues. Non-destructive only.", intent: "danger" },
        { value: "stop", label: "Stop at findings", detail: "End recon/vuln here and produce the report.", intent: "default" },
      ],
      allow_freeform: true,
    },
  };
  // The mock pauses here; QuestionPrompt's answer resumes with a final note.
  void prompt;
}
