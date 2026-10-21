import type { NextRequest } from "next/server";
import { forwardBackend } from "@/lib/backendProxy";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const proxy = (req: NextRequest) => forwardBackend(req, req.nextUrl.pathname + req.nextUrl.search);
export { proxy as GET, proxy as HEAD, proxy as POST, proxy as PUT, proxy as PATCH, proxy as DELETE };
