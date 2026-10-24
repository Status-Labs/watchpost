import type { NextRequest } from "next/server";
import { LIST_DEFAULTS, describeFilter, filterQuery, parseFilters } from "@/lib/filters";
import { PUBLIC_CACHE_HEADERS } from "@/lib/route-params";
import { buildRss } from "@/lib/rss";
import { SITE_NAME, siteUrl, vulnPath } from "@/lib/site";
import { listVulnsCached } from "@/lib/cached";

const FEED_SIZE = 50;

// Public feed of new vulnerabilities. Takes the same filters as the list page
// (build one at /rss). Public data only: nothing identifies the subscriber.
export async function GET(request: NextRequest) {
  const { filter } = parseFilters(Object.fromEntries(request.nextUrl.searchParams));
  const vulns = await listVulnsCached(filter, { limit: FEED_SIZE });
  const scope = describeFilter(filter);
  const query = filterQuery({ filter });

  const xml = buildRss({
    title: scope ? `${SITE_NAME}: ${scope}` : `${SITE_NAME}: new vulnerabilities`,
    // The list page defaults to critical, so the same view may need an explicit severity there.
    link: siteUrl(`/vulns${filterQuery({ filter }, LIST_DEFAULTS)}`),
    selfLink: siteUrl(`/feed.xml${query}`),
    description:
      "New CVEs and security advisories from OSV (CC BY 4.0) and CISA's Known Exploited Vulnerabilities catalog.",
    items: vulns.map((vuln) => {
      const where = vuln.product
        ? `Product: ${vuln.product.vendor} ${vuln.product.product}`
        : vuln.packages.length
          ? `Packages: ${vuln.packages.map((p) => `${p.ecosystem}/${p.name}`).join(", ")}`
          : "";
      const tags = [vuln.product ? null : (vuln.severity ?? "unknown"), vuln.exploited ? "exploited" : null]
        .filter(Boolean)
        .join(" · ")
        .toUpperCase();
      return {
        title: `[${tags}] ${vuln.id}${vuln.summary ? `: ${vuln.summary}` : ""}`,
        link: siteUrl(vulnPath(vuln.id)),
        guid: vuln.id,
        pubDate: vuln.published,
        description: [
          vuln.summary,
          where,
          vuln.exploited ? "Listed in CISA's Known Exploited Vulnerabilities catalog." : null,
        ]
          .filter(Boolean)
          .join("\n"),
      };
    }),
  });

  return new Response(xml, {
    headers: { "Content-Type": "application/rss+xml; charset=utf-8", ...PUBLIC_CACHE_HEADERS },
  });
}
