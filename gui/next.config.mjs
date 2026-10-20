/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // The GUI is a pure client of the Osprey FastAPI backend. In dev we proxy
  // /api and /health to the backend so the browser sees one origin.
  //
  // NOTE: Next's rewrite proxy BUFFERS responses, so it must NOT carry the
  // agent Server-Sent Event streams (chat + live events) — buffered SSE never
  // reaches the browser until the run ends, which looks like a chat stuck on
  // "Thinking" showing nothing. Those go through streaming Route Handlers under
  // /stream/* instead (see src/app/stream/*), which are outside this /api
  // rewrite and pump the upstream body through unbuffered.
  async rewrites() {
    const base = process.env.OSPREY_API_BASE || "http://localhost:9000";
    return [
      { source: "/api/:path*", destination: `${base}/api/:path*` },
      { source: "/health", destination: `${base}/health` },
    ];
  },
};

export default nextConfig;
