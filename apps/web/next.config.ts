import type { NextConfig } from "next";

// IMPORTANT: do NOT use rewrites() to forward /api/proxy/* to the backend.
// The proxy is implemented as a Route Handler at app/api/proxy/[...path]/route.ts
// so we can inject the X-API-Key header server-side without exposing it to the
// browser. Adding a rewrite here would short-circuit the route handler.
const nextConfig: NextConfig = {
  output: "standalone",
};

export default nextConfig;
