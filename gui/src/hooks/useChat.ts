"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { ChatEvent, ChatTurn } from "@/lib/types";
import { answerQuestion as apiAnswer, clearConversation, getTranscript, startChat, stopRun, type ChatRunState } from "@/lib/api";
import { applyEvent, answerQuestionBlock, userTurn } from "@/lib/chatReducer";

export type ChatActivity =
  | { kind: "idle" } | { kind: "thinking" } | { kind: "working" }
  | { kind: "preparing"; message: string }
  | { kind: "waiting"; elapsed: number } | { kind: "error"; message: string };

const IDLE: ChatRunState = {state: "idle", resumable: false};

function delay(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    const finish = () => { clearTimeout(timer); signal.removeEventListener("abort", finish); resolve(); };
    const timer = setTimeout(finish, ms);
    signal.addEventListener("abort", finish, {once: true});
    if (signal.aborted) finish();
  });
}

/** Accept inputs separately from reading the ordered journal. Disconnects only
 * interrupt observation; every tab follows the same server-owned run. */
export function useChat(engagementId: string, opts?: { mock?: boolean }) {
  const [turns, setTurns] = useState<ChatTurn[]>([]);
  const [activity, setActivity] = useState<ChatActivity>({kind: "idle"});
  const [run, setRun] = useState<ChatRunState>(IDLE);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);
  const generation = useRef(0);
  const mutationBusy = useRef(false);
  const demoAbort = useRef<AbortController | null>(null);
  const mock = opts?.mock ?? false;

  const consume = useCallback((event: ChatEvent) => {
    setTurns((prev) => applyEvent(prev, event));
  }, [engagementId]);

  const fail = useCallback((e: unknown) => {
    setError(e instanceof Error ? e.message : "Could not connect to the conversation.");
  }, []);

  useEffect(() => {
    const gen = ++generation.current;
    const ctrl = new AbortController();
    let cursor = 0;
    let restored = false;
    mutationBusy.current = false;
    setSubmitting(false);
    setError(null);
    setTurns([]);
    setRun(IDLE);
    setLoading(!mock);
    setActivity({kind: "idle"});
    void (async () => {
      while (!mock && !ctrl.signal.aborted) {
        try {
          const page = await getTranscript(engagementId, cursor, restored ? 20 : 0, ctrl.signal, !restored);
          if (gen !== generation.current) return;
          if (!restored) {
            for (const message of page.legacy_messages) {
              if (message.role === "user") setTurns((prev) => [...prev, userTurn(message.content)]);
              else {
                consume({event: "assistant", data: {content: message.content}});
                consume({event: "done", data: {content: ""}});
              }
            }
          }
          for (const record of page.events) {
            if (record.id > cursor) {
              consume({event: record.event, data: {...record.data, event_id: record.id}} as ChatEvent);
              cursor = record.id;
            }
          }
          if (page.events.some((record) => record.event === "tool_end" || record.event === "done"))
            window.dispatchEvent(new CustomEvent("osprey:evidence-changed", {detail: engagementId}));
          restored = true;
          const state: ChatRunState = page.run || {state: page.active ? "running" : "idle", resumable: false};
          setRun(state);
          setLoading(page.has_more);
          if (!page.active && !page.has_more) {
            setTurns((prev) => applyEvent(prev, {event: "done", data: {content: ""}}));
            setActivity({kind: "idle"});
          } else if (state.stage === "llm_still_waiting") {
            setActivity({kind: "waiting", elapsed: state.elapsed_seconds || 0});
          } else if (state.stage === "llm_call_start") {
            setActivity({kind: "thinking"});
          } else if (state.message) {
            setActivity({kind: "preparing", message: state.message});
          } else setActivity({kind: "working"});
          if (!page.active && !page.has_more) await delay(2000, ctrl.signal);
        } catch (e) {
          if (ctrl.signal.aborted || gen !== generation.current) return;
          setActivity({kind: "error", message: `Connection interrupted. Reconnecting to saved activity… ${e instanceof Error ? e.message : ""}`});
          await delay(2000, ctrl.signal);
        }
      }
    })();
    return () => { ++generation.current; ctrl.abort(); demoAbort.current?.abort(); };
  }, [engagementId, mock, revision, consume, fail]);

  const send = useCallback(async (prompt: string): Promise<boolean> => {
    const text = prompt.trim();
    if (!text || mutationBusy.current) return false;
    const gen = generation.current;
    mutationBusy.current = true;
    setSubmitting(true);
    setError(null);
    try {
      if (mock) {
        demoAbort.current?.abort();
        const ctrl = new AbortController();
        demoAbort.current = ctrl;
        setTurns((prev) => [...prev, userTurn(text)]);
        setRun({state: "running", resumable: false});
        setActivity({kind: "working"});
        void (async () => {
          for await (const event of demoStream()) {
            if (ctrl.signal.aborted || gen !== generation.current) return;
            consume(event);
          }
          setRun({state: "completed", resumable: false});
          setActivity({kind: "idle"});
        })();
      } else {
        await startChat(engagementId, text);
        if (gen !== generation.current) return false;
        setRun({state: "running", resumable: false});
        setActivity({kind: "preparing", message: "Preparing engagement context…"});
      }
      return true;
    } catch (e) { if (gen === generation.current) fail(e); return false; }
    finally { if (gen === generation.current) { mutationBusy.current = false; setSubmitting(false); } }
  }, [engagementId, mock, consume, fail]);

  const answer = useCallback((questionId: string, value: string) => {
    void (async () => {
      try {
        if (!mock) await apiAnswer(engagementId, questionId, value);
        setTurns((prev) => answerQuestionBlock(prev, questionId, value));
      } catch (e) { fail(e); }
    })();
  }, [engagementId, mock, fail]);

  const stop = useCallback(() => {
    if (mutationBusy.current) return;
    mutationBusy.current = true;
    setSubmitting(true);
    void (async () => {
      try {
        if (mock) {
          demoAbort.current?.abort();
          consume({event: "cancelled", data: {}});
        } else await stopRun(engagementId);
        setRun({state: "paused", resumable: true});
        setActivity({kind: "idle"});
      } catch (e) { fail(e); }
      finally { mutationBusy.current = false; setSubmitting(false); }
    })();
  }, [engagementId, mock, consume, fail]);

  const clear = useCallback(async () => {
    try {
      if (!mock) await clearConversation(engagementId);
      setRevision((value) => value + 1);
    } catch (e) { fail(e); }
  }, [engagementId, mock, fail]);

  return {turns, activity, error, run, streaming: run.state === "running", loading, submitting, send, answer, stop, clear};
}

async function* demoStream(): AsyncGenerator<ChatEvent> {
  yield {event: "assistant", data: {content: "This is a local interface demonstration. No scans are executed."}};
  yield {event: "tool_start", data: {tool_call_id: "demo", tool_name: "httpx_probe", arguments: '{"target":"example.test"}'}};
  await new Promise((r) => setTimeout(r, 500));
  yield {event: "tool_end", data: {tool_call_id: "demo", tool_name: "httpx_probe", success: true, duration_seconds: 0.5, result: "Demonstration: example.test [200]"}};
  yield {event: "assistant", data: {content: "Expand the tool card to inspect its arguments and result."}};
  yield {event: "done", data: {content: ""}};
}
