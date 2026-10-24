import { URLS_PER_SITEMAP, XML_HEADERS, urlSet } from "@/lib/sitemap";
import { siteUrl, vulnPath } from "@/lib/site";
import { listVulnIdsForSitemap } from "@/lib/vulns";

const STATIC_PATHS = ["/", "/check", "/vulns", "/rss", "/docs"];

export async function GET(_request: Request, { params }: RouteContext<"/sitemaps/[name]">) {
  const { name } = await params;

  if (name === "pages.xml") {
    return new Response(urlSet(STATIC_PATHS.map((path) => ({ loc: siteUrl(path) }))), {
      headers: XML_HEADERS,
    });
  }

  const match = /^vulns-(\d{1,4})\.xml$/.exec(name);
  if (!match) return new Response("Not found\n", { status: 404 });

  const rows = await listVulnIdsForSitemap(Number(match[1]) * URLS_PER_SITEMAP, URLS_PER_SITEMAP);
  if (rows.length === 0) return new Response("Not found\n", { status: 404 });

  const urls = rows.map((row) => ({ loc: siteUrl(vulnPath(row.id)), lastmod: row.modified }));
  return new Response(urlSet(urls), { headers: XML_HEADERS });
}
