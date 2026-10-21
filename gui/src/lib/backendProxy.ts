import type { NextRequest } from "next/server";

/** One same-origin boundary for JSON and streaming API traffic. Follow
 * FastAPI's canonical-URL redirects on the server, never in the browser. */
export async function forwardBackend(req: NextRequest, path: string): Promise<Response> {
  const base = process.env.OSPREY_API_BASE || "http://localhost:9000";
  try {
    const upstream = await fetch(`${base}${path}`, {
      method: req.method,
      headers: {
        accept: req.headers.get("accept") || "application/json",
        ...(req.headers.get("content-type") ? {"content-type":req.headers.get("content-type")!} : {}),
      },
      body: ["GET", "HEAD"].includes(req.method) ? undefined : await req.arrayBuffer(),
      signal: req.signal,
      redirect: "follow",
      cache: "no-store",
    });
    const headers = new Headers({
      "content-type": upstream.headers.get("content-type") || "application/json",
      "cache-control": "no-store, no-transform",
      "x-accel-buffering": "no",
    });
    if (upstream.headers.has("content-disposition")) headers.set("content-disposition", upstream.headers.get("content-disposition")!);
    if (!upstream.body) return new Response(null, {status:upstream.status,headers});
    const reader = upstream.body.getReader();
    const body = new ReadableStream<Uint8Array>({
      async pull(controller) {
        try {
          const chunk = await reader.read();
          if (chunk.done) controller.close();
          else controller.enqueue(chunk.value);
        } catch (error) { controller.error(error); }
      },
      async cancel() { await reader.cancel().catch(() => {}); },
    });
    return new Response(body, {status:upstream.status,headers});
  } catch {
    return Response.json({detail:"The Osprey backend could not be reached."}, {status:502});
  }
}
