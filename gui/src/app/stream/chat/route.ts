import type { NextRequest } from "next/server";

// Streaming proxy for the agent chat SSE.
//
// Next's next.config `rewrites()` proxy BUFFERS the whole upstream response, so
// routing the chat stream through /api/* would hold every Server-Sent Event
// until the run ends — a chat stuck on "Thinking" showing nothing. This Route
// Handler lives OUTSIDE /api (so the rewrite doesn't catch it) and pumps the
// upstream body chunk-by-chunk into a fresh ReadableStream, which flushes to
// the browser as each event arrives. Passing undici's `upstream.body` straight
// to `new Response()` does not flush incrementally — the manual pump does.
export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const BACKEND = process.env.OSPREY_API_BASE || "http://localhost:9000";

export async function POST(req: NextRequest): Promise<Response> {
  const body = await req.text();
  let upstream: Response;
  try {
    upstream = await fetch(`${BACKEND}/api/v1/agent/chat`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "text/event-stream" },
      body,
      signal: req.signal, // client disconnect (Stop / navigate) → release the backend run
      // @ts-expect-error — Node fetch streaming flag, absent from DOM lib types
      duplex: "half",
    });
  } catch (e) {
    const msg = e instanceof Error ? e.message : "backend unreachable";
    return sse(`event: error\ndata: ${JSON.stringify({ message: `Could not reach the backend: ${msg}` })}\n\nevent: done\ndata: {}\n\n`);
  }
  if (!upstream.body) {
    return sse('event: error\ndata: {"message":"empty backend response"}\n\nevent: done\ndata: {}\n\n');
  }
  return new Response(pump(upstream.body, req.signal), { status: upstream.status, headers: sseHeaders() });
}

function pump(body: ReadableStream<Uint8Array>, signal: AbortSignal): ReadableStream<Uint8Array> {
  const reader = body.getReader();
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        const { value, done } = await reader.read();
        if (done) {
          controller.close();
          return;
        }
        controller.enqueue(value);
      } catch {
        controller.close();
      }
    },
    cancel() {
      reader.cancel().catch(() => {});
    },
  });
}

function sseHeaders(): HeadersInit {
  return {
    "content-type": "text/event-stream; charset=utf-8",
    "cache-control": "no-cache, no-transform",
    connection: "keep-alive",
    "x-accel-buffering": "no",
  };
}
function sse(text: string): Response {
  return new Response(text, { status: 200, headers: sseHeaders() });
}
