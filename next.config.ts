import type { NextConfig } from "next";

const isDev = process.env.NODE_ENV === "development";

// Next.js inlines its bootstrap scripts, so script-src needs 'unsafe-inline'
// without nonces (which would make every page dynamic). We never render
// user or upstream HTML, which is what keeps that safe.
const cspDirectives = [
  "default-src 'self'",
  `script-src 'self' 'unsafe-inline'${isDev ? " 'unsafe-eval'" : ""}`,
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self'",
  `connect-src 'self'${isDev ? " ws:" : ""}`,
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
  "upgrade-insecure-requests",
];
const contentSecurityPolicy = cspDirectives.join("; ");
// The OAuth approval form redirects to the connecting app's callback URL, which
// can be any host or a custom scheme, and browsers apply form-action to that redirect.
const connectContentSecurityPolicy = cspDirectives.filter((d) => !d.startsWith("form-action")).join("; ");

const securityHeaders = [
  { key: "Content-Security-Policy", value: contentSecurityPolicy },
  { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "no-referrer" },
  { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), browsing-topics=()" },
];

const nextConfig: NextConfig = {
  cacheComponents: true,
  partialPrefetching: true,
  cacheLife: {
    // Public vulnerability data changes when the OSV sync runs (every 15 minutes).
    // After a sync writes new data it also invalidates the "vulns" tag.
    sync: { stale: 300, revalidate: 900, expire: 86_400 },
  },
  poweredByHeader: false,
  // We don't use next/image; turning the optimizer off removes /_next/image entirely.
  images: { unoptimized: true },
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
  async headers() {
    return [
      { source: "/:path*", headers: securityHeaders },
      // Later entries override earlier ones for the same header.
      { source: "/connect", headers: [{ key: "Content-Security-Policy", value: connectContentSecurityPolicy }] },
    ];
  },
  async rewrites() {
    // Markdown version of every vulnerability page, for LLMs: /vulns/<id>.md
    return [{ source: "/vulns/:id([^/]+)\\.md", destination: "/api/vulns/:id/markdown" }];
  },
};

export default nextConfig;
