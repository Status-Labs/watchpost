import type { MetadataRoute } from "next";
import { siteUrl } from "@/lib/site";

// Public pages are open to search and AI crawlers. Private and machine-only
// paths are off limits; private pages also send noindex in case this is ignored.
export default function robots(): MetadataRoute.Robots {
  return {
    rules: {
      userAgent: "*",
      allow: "/",
      disallow: ["/dashboard", "/connect", "/key", "/oauth/", "/login/", "/api/mcp", "/api/cron/"],
    },
    sitemap: siteUrl("/sitemap.xml"),
  };
}
