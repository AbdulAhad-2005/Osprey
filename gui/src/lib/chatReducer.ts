import type { ChatEvent, ChatTurn, ToolCallView, TurnBlock } from "./types";

let _seq = 0;
export function uid(prefix = "b"): string {
  _seq += 1;
  return `${prefix}_${Date.now().toString(36)}_${_seq}`;
}

export function userTurn(text: string): ChatTurn {
  return { id: uid("u"), role: "user", text, blocks: [] };
}

function newAssistantTurn(): ChatTurn {
  return { id: uid("a"), role: "assistant", blocks: [], streaming: true };
}

function cloneTurns(turns: ChatTurn[]): ChatTurn[] {
  // Shallow-clone the array; mutate only the active (last) turn's blocks, which
  // we also clone. Older turns are immutable once streaming ends.
  return turns.map((turn, i) => i === turns.length - 1 ? { ...turn, blocks: turn.blocks.slice() } : turn);
}

function activeAssistant(turns: ChatTurn[]): ChatTurn {
  const last = turns[turns.length - 1];
  if (last && last.role === "assistant" && last.streaming) return last;
  const t = newAssistantTurn();
  turns.push(t);
  return t;
}

function lastBlock(turn: ChatTurn): TurnBlock | undefined {
  return turn.blocks[turn.blocks.length - 1];
}

/**
 * Fold one streaming event into the turn list, returning a new array suitable
 * for React state. Consecutive tool calls coalesce into a single `tools`
 * block (a batch); any text/thinking/question between them closes that batch,
 * so the next tool call opens a fresh one — exactly how a harness groups
 * parallel calls under one turn.
 */
export function applyEvent(prev: ChatTurn[], ev: ChatEvent): ChatTurn[] {
  const turns = cloneTurns(prev);

  switch (ev.event) {
    case "question_answer": return answerQuestionBlock(prev, ev.data.id, ev.data.answer);
    case "run_start": {
      const last = turns[turns.length - 1];
      if (last?.role !== "user" || last.text !== ev.data.prompt) turns.push(userTurn(ev.data.prompt));
      return turns;
    }
    case "thinking": {
      const t = activeAssistant(turns);
      t.blocks = t.blocks.slice();
      const lb = lastBlock(t);
      if (lb && lb.kind === "thinking") {
        t.blocks[t.blocks.length - 1] = {
          ...lb,
          content: joinText(lb.content, ev.data.content),
        };
      } else if (ev.data.content.trim()) {
        t.blocks.push({ kind: "thinking", id: uid("t"), content: ev.data.content });
      }
      return turns;
    }

    case "assistant": {
      const t = activeAssistant(turns);
      if (!ev.data.content.trim()) return turns;
      t.blocks = t.blocks.slice();
      const lb = lastBlock(t);
      if (lb && lb.kind === "text") {
        t.blocks[t.blocks.length - 1] = { ...lb, content: joinText(lb.content, ev.data.content) };
      } else {
        t.blocks.push({ kind: "text", id: uid("x"), content: ev.data.content });
      }
      return turns;
    }

    case "tool_start": {
      const t = activeAssistant(turns);
      t.blocks = t.blocks.slice();
      const call: ToolCallView = {
        id: ev.data.tool_call_id || uid("tc"),
        name: ev.data.tool_name,
        source: ev.data.source,
        args: ev.data.arguments,
        status: "running",
      };
      const lb = lastBlock(t);
      if (lb && lb.kind === "tools") {
        t.blocks[t.blocks.length - 1] = { ...lb, calls: [...lb.calls, call] };
      } else {
        t.blocks.push({ kind: "tools", id: uid("g"), calls: [call] });
      }
      return turns;
    }

    case "tool_end": {
      const t = activeAssistant(turns);
      if (!t.blocks.some((b) => b.kind === "tools" && b.calls.some((c) => c.id === ev.data.tool_call_id))) {
        t.blocks = [...t.blocks, { kind: "tools", id: uid("g"), calls: [{
          id: ev.data.tool_call_id || uid("tc"), name: ev.data.tool_name, status: ev.data.success ? "ok" : "fail",
          result: ev.data.result, durationSeconds: ev.data.duration_seconds,
        }] }];
      }
      t.blocks = t.blocks.map((b) => {
        if (b.kind !== "tools") return b;
        if (!b.calls.some((c) => c.id === ev.data.tool_call_id)) return b;
        return {
          ...b,
          calls: b.calls.map((c) =>
            c.id === ev.data.tool_call_id
              ? {
                  ...c,
                  status: ev.data.success ? "ok" : "fail",
                  result: ev.data.result,
                  durationSeconds: ev.data.duration_seconds,
                  findingTitles: ev.data.finding_titles,
                }
              : c,
          ),
        };
      });
      return turns;
    }

    case "question": {
      const t = activeAssistant(turns);
      t.blocks = [...t.blocks, { kind: "question", id: uid("q"), question: ev.data }];
      return turns;
    }

    case "error": {
      const t = activeAssistant(turns);
      t.blocks = [
        ...t.blocks,
        { kind: "text", id: uid("err"), content: `⚠️ ${ev.data.message}` },
      ];
      t.streaming = false;
      return turns;
    }

    case "done":
    case "cancelled": {
      const last = turns[turns.length - 1];
      if (last && last.role === "assistant") {
        const content = ev.event === "done" ? ev.data.content : "";
        const hasText = last.blocks.some((b) => b.kind === "text" && b.content === content);
        const blocks: TurnBlock[] = last.blocks.map((b) => b.kind === "tools" ? {
          ...b, calls: b.calls.map((c) => c.status === "running" ? { ...c, status: "stopped" as const } : c),
        } : b);
        const errorAlreadyShown = content.startsWith("(stopped:") && last.blocks.some((block) => block.kind === "text" && block.content.startsWith("⚠️ "));
        if (content && !hasText && !errorAlreadyShown) blocks.push({ kind: "text", id: uid("x"), content });
        turns[turns.length - 1] = { ...last, blocks, streaming: false };
      }
      return turns;
    }

    default:
      return prev; // llm_call_start / still_waiting / compaction handled by status, not blocks
  }
}

export function answerQuestionBlock(
  turns: ChatTurn[],
  questionId: string,
  answer: string,
): ChatTurn[] {
  return turns.map((t) => ({
    ...t,
    blocks: t.blocks.map((b) =>
      b.kind === "question" && b.question.id === questionId ? { ...b, answered: answer } : b,
    ),
  }));
}

function joinText(a: string, b: string): string {
  if (!a) return b;
  if (!b) return a;
  return `${a}\n\n${b}`;
}
