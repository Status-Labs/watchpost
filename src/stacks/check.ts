import { inArray } from "drizzle-orm";
import type { Db } from "@/db";
import { kev, vulns, type Severity } from "@/db/schema";
import { oneLine, truncate } from "@/lib/sanitize";
import { siteUrl, vulnPath } from "@/lib/site";
import { toRows } from "@/osv/record";
import { fetchRecord, mapUntil } from "@/osv/sync";
import { isLocalMode } from "@/local/mode";
import { matchLocally } from "@/match/local";
import { queryOsv } from "./osv-query";
import { SEVERITY_ORDER, dedupeAliases, fixedVersions } from "./results";
import type { RejectedItem, StackItem } from "./validate";

// A one-off check that stores nothing: no workspace, no stack, no log of the
// package list. OSV says which advisories affect each package version; details
// come from our public copy of OSV, or are fetched into memory when missing.

const MAX_RECORD_FETCHES = 300;
const FETCH_CONCURRENCY = 16;
const FETCH_BUDGET_MS = 30_000;
const LOOKUP_CHUNK = 1_000;

type Fetch = typeof fetch;

export type CheckResult = {
  id: string;
  aliases: string[];
  severity: Severity | null;
  ecosystem: string;
  package: string;
  version: string;
  fixed_versions: string[];
  // Listed in CISA's Known Exploited Vulnerabilities catalog.
  known_exploited: boolean;
  // Upstream text, one short line. Not included in MCP tool output.
  summary: string | null;
  url: string;
};

type Advisory = {
  // Whether we have our own page for it; older advisories link to osv.dev.
  local: boolean;
  aliases: string[];
  severity: Severity | null;
  summary: string | null;
  withdrawn: boolean;
  record: unknown;
};

export async function checkPackages(db: Db, items: StackItem[], fetchFn: Fetch = fetch): Promise<CheckResult[]> {
  // Local mode matches against its own full copy of OSV, and never asks OSV
  // anything that would reveal the package list or which advisories matched.
  const local = isLocalMode();
  const found = local ? (await matchLocally(db, items)).found : await queryOsv(fetchFn, items);
  const advisories = await loadAdvisories(db, local ? null : fetchFn, found);

  const rows = found.flatMap(({ item, vulnId }) => {
    const advisory = advisories.get(vulnId);
    if (advisory?.withdrawn) return [];
    return [
      {
        id: vulnId,
        aliases: advisory?.aliases ?? [],
        severity: advisory?.severity ?? null,
        ecosystem: item.ecosystem,
        name: item.name,
        version: item.version,
        record: advisory?.record,
        summary: advisory?.summary ?? null,
        local: advisory?.local ?? false,
      },
    ];
  });

  const deduped = dedupeAliases(rows);
  const exploited = await exploitedCves(db, deduped.flatMap((row) => [row.id, ...row.aliases]));
  const isExploited = (row: (typeof deduped)[number]) => [row.id, ...row.aliases].some((id) => exploited.has(id));

  // Known exploited first, then worst first.
  return deduped
    .map((row) => ({ ...row, exploited: isExploited(row) }))
    .sort(
      (a, b) =>
        Number(b.exploited) - Number(a.exploited) ||
        (SEVERITY_ORDER[a.severity ?? ""] ?? 4) - (SEVERITY_ORDER[b.severity ?? ""] ?? 4) ||
        a.name.localeCompare(b.name) ||
        a.id.localeCompare(b.id),
    )
    .map((row) => ({
      id: row.id,
      aliases: row.aliases.filter((a) => a.startsWith("CVE-")),
      severity: row.severity,
      ecosystem: row.ecosystem,
      package: row.name,
      version: row.version,
      fixed_versions: fixedVersions(row.record, row.ecosystem, row.name),
      known_exploited: row.exploited,
      summary: row.summary ? truncate(oneLine(row.summary), 200) : null,
      url: row.local ? siteUrl(vulnPath(row.id)) : `https://osv.dev/vulnerability/${encodeURIComponent(row.id)}`,
    }));
}

async function exploitedCves(db: Db, ids: string[]): Promise<Set<string>> {
  const cves = [...new Set(ids.filter((id) => id.startsWith("CVE-")))];
  const found = new Set<string>();
  for (let i = 0; i < cves.length; i += LOOKUP_CHUNK) {
    const rows = await db.select({ cveId: kev.cveId }).from(kev).where(inArray(kev.cveId, cves.slice(i, i + LOOKUP_CHUNK)));
    for (const row of rows) found.add(row.cveId);
  }
  return found;
}

async function loadAdvisories(
  db: Db,
  // Null: use only what's stored.
  fetchFn: Fetch | null,
  found: { item: StackItem; vulnId: string; modified: string }[],
): Promise<Map<string, Advisory>> {
  const ids = [...new Set(found.map((f) => f.vulnId))];
  const advisories = new Map<string, Advisory>();
  for (let i = 0; i < ids.length; i += LOOKUP_CHUNK) {
    const rows = await db
      .select({ id: vulns.id, aliases: vulns.aliases, severity: vulns.severity, summary: vulns.summary, withdrawn: vulns.withdrawn, record: vulns.record })
      .from(vulns)
      .where(inArray(vulns.id, ids.slice(i, i + LOOKUP_CHUNK)));
    for (const row of rows) advisories.set(row.id, { ...row, local: true, withdrawn: row.withdrawn !== null });
  }

  // Older advisories aren't in our copy; fetch them, but don't store them, so
  // the database never reflects what anyone checked.
  if (!fetchFn) return advisories;
  const missing = new Map<string, { ecosystem: string; id: string; modified: string }>();
  for (const f of found) {
    if (!advisories.has(f.vulnId) && !missing.has(f.vulnId)) {
      missing.set(f.vulnId, { ecosystem: f.item.ecosystem, id: f.vulnId, modified: f.modified });
    }
  }
  const entries = [...missing.values()].slice(0, MAX_RECORD_FETCHES);
  const outcomes = await mapUntil(entries, FETCH_CONCURRENCY, Date.now() + FETCH_BUDGET_MS, (entry) =>
    fetchRecord(fetchFn, entry),
  );
  for (const outcome of outcomes) {
    if (outcome?.kind !== "record") continue;
    const { vuln } = toRows(outcome.record);
    advisories.set(vuln.id, {
      local: false,
      aliases: vuln.aliases,
      severity: vuln.severity,
      summary: vuln.summary,
      withdrawn: vuln.withdrawn !== null,
      record: vuln.record,
    });
  }
  return advisories;
}

// Plain-text summary for cron jobs and terminals (?format=text).
export function formatText(checked: number, results: CheckResult[], rejected: RejectedItem[]): string {
  const packages = `${checked} ${checked === 1 ? "package" : "packages"}`;
  const lines = [
    results.length
      ? `${results.length} known ${results.length === 1 ? "vulnerability" : "vulnerabilities"} in ${packages} checked.`
      : `No known vulnerabilities in ${packages} checked.`,
  ];
  for (const r of results) {
    const fix = r.fixed_versions.length ? `fixed in ${r.fixed_versions.join(", ")}` : "no fix listed";
    const exploited = r.known_exploited ? "  EXPLOITED (CISA KEV)" : "";
    lines.push(`${(r.severity ?? "unknown").toUpperCase().padEnd(8)} ${r.ecosystem}/${r.package}@${r.version}  ${r.id}  ${fix}  ${r.url}${exploited}`);
  }
  if (rejected.length) lines.push(`Skipped ${rejected.length} entries that didn't look like package names and versions.`);
  return `${lines.join("\n")}\n`;
}
