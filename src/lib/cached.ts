import { cacheLife, cacheTag } from "next/cache";
import { isVulnId } from "./sanitize";
import {
  countRecent,
  findIdsByAlias,
  getKevEntry,
  getVuln,
  listVulns,
  type KevEntry,
  type Sort,
  type VulnDetail,
  type VulnFilter,
} from "./vulns";

// Cached reads of public vulnerability data, so most page views and crawls
// never reach the database. Everything here is public and the same for every
// visitor: never cache workspace data this way (see AGENTS.md).
//
// All entries carry the "vulns" tag; the sync invalidates it after writing.
export const VULNS_TAG = "vulns";

export type VulnLookup = {
  id: string | null;
  vuln: VulnDetail | null;
  aliasMatches: string[];
  // A CVE in CISA's exploited catalog that no package advisory covers.
  exploit: KevEntry | null;
};

// Detail pages use plain `use cache`, which lets each CVE page become a static
// page after its first visit, served from the CDN.
export async function lookupVuln(id: string): Promise<VulnLookup> {
  "use cache";
  cacheLife("sync");
  cacheTag(VULNS_TAG);
  if (!isVulnId(id)) return { id: null, vuln: null, aliasMatches: [], exploit: null };
  const vuln = await getVuln(id);
  if (vuln) return { id, vuln, aliasMatches: [], exploit: null };
  const aliasMatches = await findIdsByAlias(id);
  const exploit = aliasMatches.length === 0 && id.startsWith("CVE-") ? await getKevEntry(id) : null;
  return { id, vuln: null, aliasMatches, exploit };
}

// Lists change with filters and the clock, so these pages stay dynamic; their
// queries are shared across server instances through the remote cache.
export async function listVulnsCached(
  filter: VulnFilter,
  options: { page?: number; limit?: number; sort?: Sort },
) {
  "use cache: remote";
  cacheLife("sync");
  cacheTag(VULNS_TAG);
  return listVulns(filter, options);
}

const OVERVIEW_WINDOW_DAYS = 7;

// The window is computed inside the cache so every visitor shares one entry.
export async function homeOverview({ priority, latest }: { priority: number; latest: number }) {
  "use cache: remote";
  cacheLife("sync");
  cacheTag(VULNS_TAG);
  const since = new Date(Date.now() - OVERVIEW_WINDOW_DAYS * 86_400_000);
  const [counts, critical, recent] = await Promise.all([
    countRecent(since),
    listVulns({ severities: ["critical", "high"], publishedSince: since, kind: "advisories" }, { limit: priority, sort: "severity" }),
    listVulns({ kind: "advisories" }, { limit: latest }),
  ]);
  return { windowDays: OVERVIEW_WINDOW_DAYS, counts, critical, recent };
}
