import type { NextRequest } from "next/server";
import { forwardBackend } from "@/lib/backendProxy";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(req: NextRequest, ctx: {params: Promise<{id: string}>}) {
  const {id} = await ctx.params;
  return forwardBackend(req, `/api/v1/agent/events/${encodeURIComponent(id)}${req.nextUrl.search}`);
}
