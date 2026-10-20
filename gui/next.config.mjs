/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // The GUI is a pure client of the Osprey FastAPI backend. In dev we proxy
  // /api and the SSE stream to the backend so the browser sees one origin
  // (no CORS preflight on EventSource, which cannot send custom headers).
  async rewrites() {
    const base = process.env.OSPREY_API_BASE || "http://localhost:9000";
    return [
      { source: "/api/:path*", destination: `${base}/api/:path*` },
      { source: "/health", destination: `${base}/health` },
    ];
  },
};

export default nextConfig;
