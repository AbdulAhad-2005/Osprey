import type { NextRequest } from "next/server";
import { forwardBackend } from "@/lib/backendProxy";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export function POST(req: NextRequest) {
  return forwardBackend(req, "/api/v1/agent/chat");
}
