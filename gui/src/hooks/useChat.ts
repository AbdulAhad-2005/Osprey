"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { ChatEvent, ChatTurn } from "@/lib/types";
import { ApiError, answerQuestion as apiAnswer, attachChat, clearConversation, getTranscript, stopRun, streamChat } from "@/lib/api";
import { applyEvent, answerQuestionBlock, userTurn } from "@/lib/chatReducer";

export type ChatActivity =
  | { kind: "idle" } | { kind: "thinking" } | { kind: "working" }
  | { kind: "preparing"; message: string }
  | { kind: "waiting"; elapsed: number } | { kind: "error"; message: string };

export function useChat(engagementId: string, opts?: { mock?: boolean }) {
  const [turns, setTurns] = useState<ChatTurn[]>([]);
  const [activity, setActivity] = useState<ChatActivity>({ kind: "idle" });
  const [streaming, setStreaming] = useState(false);
  const [loading, setLoading] = useState(true);
  const abortRef = useRef<AbortController | null>(null);
  const cursor = useRef(0);
  const generation = useRef(0);
  const busy = useRef(false);
  const mock = opts?.mock ?? false;

  const consume = useCallback((event: ChatEvent) => {
    const id = Number((event.data as { event_id?: number }).event_id || 0);
    if (id && id <= cursor.current) return;
    if (id) cursor.current = id;
    if (event.event === "tool_end" || event.event === "done") {
      window.dispatchEvent(new CustomEvent("osprey:evidence-changed", {detail: engagementId}));
    }
    setTurns((prev) => applyEvent(prev, event));
    switch (event.event) {
      case "status": setActivity({ kind: "preparing", message: event.data.message }); break;
      case "llm_call_start": setActivity({ kind: "thinking" }); break;
      case "llm_still_waiting": setActivity({ kind: "waiting", elapsed: event.data.elapsed_seconds }); break;
      case "tool_start": setActivity({ kind: "working" }); break;
      case "done": setActivity({ kind: "idle" }); break;
    }
  }, [engagementId]);

  const fail = useCallback((e: unknown) => {
    setActivity({ kind: "error", message: e instanceof Error ? e.message : "Could not load the conversation." });
  }, []);

  const follow = useCallback(async (ctrl: AbortController, gen: number) => {
    for await (const event of attachChat(engagementId, ctrl.signal, cursor.current)) {
      if (gen !== generation.current) return;
      consume(event);
    }
  }, [engagementId, consume]);

  useEffect(() => {
    const gen = ++generation.current;
    const ctrl = new AbortController();
    abortRef.current = ctrl;
    cursor.current = 0;
    busy.current = true;
    setTurns([]);
    setLoading(true);
    setStreaming(false);
    setActivity({ kind: "idle" });
    (async () => {
      try {
        if (mock) return;
        const page = await getTranscript(engagementId, 0, 0, ctrl.signal);
        if (gen !== generation.current) return;
        for (const message of page.legacy_messages) {
          if (message.role === "user") setTurns((prev) => [...prev, userTurn(message.content)]);
          else {
            consume({ event: "assistant", data: { content: message.content } });
            consume({ event: "done", data: { content: "" } });
          }
        }
        for (const record of page.events) {
          consume({ event: record.event, data: { ...record.data, event_id: record.id } } as ChatEvent);
        }
        if (page.active || page.has_more) {
          setLoading(false);
          setStreaming(true);
          setActivity({ kind: "working" });
          await follow(ctrl, gen);
        }
        if (gen === generation.current) setTurns((prev) => applyEvent(prev, { event: "done", data: { content: "" } }));
      } catch (e) {
        if (!ctrl.signal.aborted && gen === generation.current) fail(e);
      } finally {
        if (gen === generation.current) {
          busy.current = false;
          setLoading(false);
          setStreaming(false);
        }
      }
    })();
    return () => { ++generation.current; ctrl.abort(); };
  }, [engagementId, mock, consume, follow, fail]);

  const send = useCallback((prompt: string) => {
    const text = prompt.trim();
    if (!text || busy.current) return;
    const gen = generation.current;
    const ctrl = new AbortController();
    abortRef.current = ctrl;
    busy.current = true;
    setStreaming(true);
    setTurns((prev) => [...prev, userTurn(text)]);
    setActivity({ kind: "thinking" });
    void (async () => {
      try {
        const source = mock ? demoStream() : streamChat({ engagement_id: engagementId, prompt: text }, ctrl.signal);
        for await (const event of source) {
          if (gen !== generation.current) return;
          consume(event);
        }
        if (!mock && !ctrl.signal.aborted) await follow(ctrl, gen);
      } catch (e) {
        if (!ctrl.signal.aborted && gen === generation.current) {
          if (e instanceof ApiError) { fail(e); return; }
          try { await follow(ctrl, gen); }
          catch (reconnectError) { if (!ctrl.signal.aborted) fail(reconnectError); }
        }
      } finally {
        if (gen === generation.current) {
          busy.current = false;
          setStreaming(false);
          setTurns((prev) => applyEvent(prev, { event: "done", data: { content: "" } }));
        }
      }
    })();
  }, [engagementId, mock, consume, follow, fail]);

  const answer = useCallback((questionId: string, value: string) => {
    void (async () => {
      try {
        if (!mock) await apiAnswer(engagementId, questionId, value);
        setTurns((prev) => answerQuestionBlock(prev, questionId, value));
      } catch (e) { fail(e); }
    })();
  }, [engagementId, mock, fail]);

  const stop = useCallback(() => {
    if (mock) abortRef.current?.abort();
    else void stopRun(engagementId).catch(fail);
  }, [engagementId, mock, fail]);

  const clear = useCallback(async () => {
    try {
      if (!mock) await clearConversation(engagementId);
      ++generation.current;
      abortRef.current?.abort();
      busy.current = false;
      cursor.current = 0;
      setStreaming(false);
      setTurns([]);
      setActivity({ kind: "idle" });
    } catch (e) { fail(e); }
  }, [engagementId, mock, fail]);

  return { turns, activity, streaming, loading, send, answer, stop, clear };
}

async function* demoStream(): AsyncGenerator<ChatEvent> {
  yield { event: "assistant", data: { content: "This is a local interface demonstration. No scans are executed." } };
  yield { event: "tool_start", data: { tool_call_id: "demo", tool_name: "httpx_probe", arguments: '{"target":"example.test"}' } };
  await new Promise((r) => setTimeout(r, 500));
  yield { event: "tool_end", data: { tool_call_id: "demo", tool_name: "httpx_probe", success: true, duration_seconds: 0.5, result: "Demonstration: example.test [200]" } };
  yield { event: "assistant", data: { content: "Expand the tool card to inspect its arguments and result." } };
  yield { event: "done", data: { content: "" } };
}
