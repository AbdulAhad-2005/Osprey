import { describe, expect, it } from "vitest";
import { readEvents } from "./sse";

describe("SSE framing", () => {
  for (const newline of ["\r\n", "\n", "\r"]) {
    it(`reads ${JSON.stringify(newline)} frames across every byte boundary`, async () => {
      const encoded = new TextEncoder().encode(`: keepalive${newline}${newline}event: tool_start${newline}data: {"tool_name":"httpx_probe","tool_call_id":"t1"}${newline}${newline}event: assistant${newline}data: {"content":"résumé ✓"}${newline}${newline}`);
      const body = new ReadableStream<Uint8Array>({ start(controller) {
        for (const byte of encoded) controller.enqueue(Uint8Array.of(byte));
        controller.close();
      }});
      const events = [];
      for await (const event of readEvents(body)) events.push(event);
      expect(events.map((event) => event.event)).toEqual(["tool_start", "assistant"]);
      expect(events[1]?.data).toEqual({content:"résumé ✓"});
    });
  }
});
