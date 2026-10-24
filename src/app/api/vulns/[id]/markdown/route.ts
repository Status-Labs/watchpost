import { kevToMarkdown, vulnToMarkdown } from "@/lib/markdown";
import { PUBLIC_CACHE_HEADERS, parseVulnId } from "@/lib/route-params";
import { lookupVuln } from "@/lib/cached";

// Served at /vulns/<id>.md through a rewrite in next.config.ts.
export async function GET(_request: Request, { params }: RouteContext<"/api/vulns/[id]/markdown">) {
  const id = parseVulnId((await params).id);
  const { vuln, exploit } = id ? await lookupVuln(id) : { vuln: null, exploit: null };
  if (exploit) {
    return new Response(kevToMarkdown(exploit), {
      headers: { "Content-Type": "text/markdown; charset=utf-8", ...PUBLIC_CACHE_HEADERS },
    });
  }
  if (!vuln) {
    return new Response("Not found\n", { status: 404, headers: { "Content-Type": "text/plain; charset=utf-8" } });
  }
  return new Response(vulnToMarkdown(vuln), {
    headers: { "Content-Type": "text/markdown; charset=utf-8", ...PUBLIC_CACHE_HEADERS },
  });
}
