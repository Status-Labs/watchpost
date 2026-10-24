import { connection } from "next/server";
import { URLS_PER_SITEMAP, XML_HEADERS, sitemapIndex } from "@/lib/sitemap";
import { siteUrl } from "@/lib/site";
import { countVulns } from "@/lib/vulns";

// A sitemap index: one file for the fixed pages, then vulnerability pages in chunks.
export async function GET() {
  await connection();
  const chunks = Math.ceil((await countVulns()) / URLS_PER_SITEMAP);
  const locations = [
    siteUrl("/sitemaps/pages.xml"),
    ...Array.from({ length: chunks }, (_, i) => siteUrl(`/sitemaps/vulns-${i}.xml`)),
  ];
  return new Response(sitemapIndex(locations), { headers: XML_HEADERS });
}
