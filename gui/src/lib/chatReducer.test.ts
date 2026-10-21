import { describe, expect, it } from "vitest";
import { applyEvent, answerQuestionBlock, userTurn } from "./chatReducer";
import type { ChatEvent, ChatTurn } from "./types";

function fold(events: ChatEvent[], start: ChatTurn[] = []): ChatTurn[] {
  return events.reduce((turns, ev) => applyEvent(turns, ev), start);
}

describe("chatReducer.applyEvent", () => {
  it("shows provider failures once without repeating the stopped message", () => {
    const turns=fold([{event:"error",data:{message:"Provider rate limited"}},{event:"done",data:{content:"(stopped: Provider rate limited)"}}]);
    expect(turns[0]!.blocks).toHaveLength(1);
    expect(turns[0]!.streaming).toBe(false);
  });
  it("replays run starts without duplicating an optimistic prompt", () => {
    const turns = fold([{event:"run_start",data:{prompt:"inspect"}}], [userTurn("inspect")]);
    expect(turns).toHaveLength(1);
  });

  it("retains orphan completions and settles unfinished cards", () => {
    const turns = fold([
      {event:"tool_end",data:{tool_name:"fast",tool_call_id:"a",result:"retained",success:true,duration_seconds:1}},
      {event:"tool_start",data:{tool_name:"slow",tool_call_id:"b"}},
      {event:"done",data:{content:"Run stopped"}},
    ]);
    const block = turns[0]!.blocks[0]!;
    if (block.kind !== "tools") throw new Error("expected tools");
    expect(block.calls.map(call=>call.status)).toEqual(["ok","stopped"]);
    expect(turns[0]!.blocks.some(block=>block.kind==="text" && block.content==="Run stopped")).toBe(true);
  });

  it("does not mutate a previously rendered turn", () => {
    const before = fold([{event:"assistant",data:{content:"first"}}]);
    const after = fold([{event:"assistant",data:{content:"second"}}], before);
    expect(before[0]!.blocks[0]).toMatchObject({content:"first"});
    expect(after[0]!.blocks[0]).toMatchObject({content:"first\n\nsecond"});
  });
  it("groups consecutive tool calls into one batch", () => {
    const turns = fold([
      { event: "tool_start", data: { tool_name: "subfinder_scan", tool_call_id: "a" } },
      { event: "tool_start", data: { tool_name: "crt_sh_query", tool_call_id: "b" } },
    ]);
    const assistant = turns[turns.length - 1]!;
    expect(assistant.role).toBe("assistant");
    expect(assistant.blocks).toHaveLength(1);
    expect(assistant.blocks[0]!.kind).toBe("tools");
    const block = assistant.blocks[0]!;
    if (block.kind !== "tools") throw new Error("expected tools block");
    expect(block.calls.map((c) => c.id)).toEqual(["a", "b"]);
  });

  it("starts a fresh batch after intervening text", () => {
    const turns = fold([
      { event: "tool_start", data: { tool_name: "subfinder_scan", tool_call_id: "a" } },
      { event: "assistant", data: { content: "Found some names." } },
      { event: "tool_start", data: { tool_name: "httpx_probe", tool_call_id: "b" } },
    ]);
    const kinds = turns[turns.length - 1]!.blocks.map((b) => b.kind);
    expect(kinds).toEqual(["tools", "text", "tools"]);
  });

  it("resolves a tool_end onto the matching running call", () => {
    const turns = fold([
      { event: "tool_start", data: { tool_name: "nmap_service_scan", tool_call_id: "x" } },
      {
        event: "tool_end",
        data: { tool_name: "nmap_service_scan", tool_call_id: "x", success: true, duration_seconds: 3.2, result: "open: 443" },
      },
    ]);
    const block = turns[turns.length - 1]!.blocks[0]!;
    if (block.kind !== "tools") throw new Error("expected tools block");
    expect(block.calls[0]!.status).toBe("ok");
    expect(block.calls[0]!.result).toBe("open: 443");
    expect(block.calls[0]!.durationSeconds).toBe(3.2);
  });

  it("marks a failed tool_end as fail", () => {
    const turns = fold([
      { event: "tool_start", data: { tool_name: "sqlmap_scan", tool_call_id: "x" } },
      { event: "tool_end", data: { tool_name: "sqlmap_scan", tool_call_id: "x", success: false, duration_seconds: 1, result: "ERROR" } },
    ]);
    const block = turns[turns.length - 1]!.blocks[0]!;
    if (block.kind !== "tools") throw new Error("expected tools block");
    expect(block.calls[0]!.status).toBe("fail");
  });

  it("appends a question block and can mark it answered", () => {
    let turns = fold([
      {
        event: "question",
        data: {
          id: "q1",
          text: "Proceed to exploitation?",
          options: [
            { value: "go", label: "Go" },
            { value: "stop", label: "Stop" },
          ],
          kind: "gate",
        },
      },
    ]);
    const qBlock = turns[turns.length - 1]!.blocks.find((b) => b.kind === "question");
    expect(qBlock).toBeTruthy();
    turns = answerQuestionBlock(turns, "q1", "go");
    const answered = turns[turns.length - 1]!.blocks.find((b) => b.kind === "question");
    if (!answered || answered.kind !== "question") throw new Error("expected question block");
    expect(answered.answered).toBe("go");
  });

  it("flips streaming off on done", () => {
    const turns = fold([
      { event: "assistant", data: { content: "Here's the summary." } },
      { event: "done", data: { content: "Here's the summary." } },
    ]);
    expect(turns[turns.length - 1]!.streaming).toBe(false);
  });

  it("keeps a user turn separate from the assistant reply", () => {
    const turns = fold(
      [
        { event: "thinking", data: { content: "planning" } },
        { event: "assistant", data: { content: "done" } },
      ],
      [userTurn("map the surface")],
    );
    expect(turns[0]!.role).toBe("user");
    expect(turns[0]!.text).toBe("map the surface");
    expect(turns[1]!.role).toBe("assistant");
  });
});
