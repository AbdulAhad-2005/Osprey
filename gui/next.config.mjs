import { PHASE_DEVELOPMENT_SERVER } from "next/constants.js";

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Preserve FastAPI's canonical collection URLs. Removing the slash makes
  // FastAPI redirect to its own origin, bypassing the same-origin proxy.
  skipTrailingSlashRedirect: true,
  // API and SSE use one streaming Route Handler proxy (lib/backendProxy.ts).
  // Following canonical redirects server-side keeps requests same-origin.
  async rewrites() {
    const base = process.env.OSPREY_API_BASE || "http://localhost:9000";
    return [{ source: "/health", destination: `${base}/health` }];
  },
};

// next dev and next build must never overwrite each other's manifests/chunks.
// Both share .next in Next 15 by default; a build can break a running dev server.
export default function config(phase) {
  return {
    ...nextConfig,
    distDir:
      process.env.OSPREY_NEXT_DIST ||
      (phase === PHASE_DEVELOPMENT_SERVER ? ".next-dev" : ".next"),
  };
}
