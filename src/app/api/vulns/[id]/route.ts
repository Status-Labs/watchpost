import { affectedPackages } from "@/lib/affected";
import { PUBLIC_CACHE_HEADERS, parseVulnId } from "@/lib/route-params";
import { KEV_CATALOG_URL, OSV_ATTRIBUTION, siteUrl, vulnPath } from "@/lib/site";
import type { KevEntry } from "@/lib/vulns";
import { lookupVuln } from "@/lib/cached";

// Public, read-only JSON for one vulnerability. CVE IDs resolve through aliases.
export async function GET(_request: Request, { params }: RouteContext<"/api/vulns/[id]">) {
  const id = parseVulnId((await params).id);
  if (!id) return Response.json({ error: "not_found" }, { status: 404 });

  const { vuln, aliasMatches: matches, exploit } = await lookupVuln(id);
  if (exploit) {
    return Response.json(
      {
        id: exploit.cveId,
        source: "CISA Known Exploited Vulnerabilities catalog",
        vendor: exploit.vendor,
        product: exploit.product,
        name: exploit.name,
        description: exploit.description,
        known_exploited: [kevFields(exploit)],
        url: siteUrl(vulnPath(exploit.cveId)),
        catalog_url: KEV_CATALOG_URL,
      },
      { headers: PUBLIC_CACHE_HEADERS },
    );
  }
  if (!vuln) {
    if (matches.length === 0) return Response.json({ error: "not_found" }, { status: 404 });
    return Response.json(
      { alias: id, matches: matches.map((match) => ({ id: match, url: siteUrl(`/api/vulns/${encodeURIComponent(match)}`) })) },
      { headers: PUBLIC_CACHE_HEADERS },
    );
  }

  return Response.json(
    {
      id: vuln.id,
      aliases: vuln.aliases,
      summary: vuln.summary,
      details: vuln.details,
      severity: vuln.severity,
      cvss_score: vuln.cvssScore,
      published: vuln.published,
      modified: vuln.modified,
      withdrawn: vuln.withdrawn,
      known_exploited: vuln.exploits.map(kevFields),
      affected: affectedPackages(vuln.record),
      url: siteUrl(vulnPath(vuln.id)),
      osv_url: `https://osv.dev/vulnerability/${encodeURIComponent(vuln.id)}`,
      attribution: OSV_ATTRIBUTION,
    },
    { headers: PUBLIC_CACHE_HEADERS },
  );
}

function kevFields(entry: KevEntry) {
  return {
    cve: entry.cveId,
    date_added: entry.dateAdded.toISOString().slice(0, 10),
    due_date: entry.dueDate?.toISOString().slice(0, 10) ?? null,
    known_ransomware_use: entry.ransomware,
    required_action: entry.requiredAction,
  };
}
