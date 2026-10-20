import type { NextRequest } from "next/server";

// Streaming proxy for the persistent engagement event stream — same buffering
// rationale as /stream/chat. Lives outside /api and pumps the upstream body
// through unbuffered.
export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const BACKEND = process.env.OSPREY_API_BASE || "http://localhost:9000";

export async function GET(req: NextRequest, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  const { id } = await ctx.params;
  const replay = req.nextUrl.searchParams.get("replay");
  const qs = replay != null ? `?replay=${encodeURIComponent(replay)}` : "";
  let upstream: Response;
  try {
    upstream = await fetch(`${BACKEND}/api/v1/agent/events/${encodeURIComponent(id)}${qs}`, {
      headers: { accept: "text/event-stream" },
      signal: req.signal,
    });
  } catch (e) {
    const msg = e instanceof Error ? e.message : "backend unreachable";
    return new Response(`event: error\ndata: ${JSON.stringify({ message: msg })}\n\n`, { status: 200, headers: sseHeaders() });
  }
  if (!upstream.body) return new Response(null, { status: 502 });
  const reader = upstream.body.getReader();
  const stream = new ReadableStream<Uint8Array>({
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
  return new Response(stream, { status: upstream.status, headers: sseHeaders() });
}

function sseHeaders(): HeadersInit {
  return {
    "content-type": "text/event-stream; charset=utf-8",
    "cache-control": "no-cache, no-transform",
    connection: "keep-alive",
    "x-accel-buffering": "no",
  };
}
