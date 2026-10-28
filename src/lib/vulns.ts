import { and, asc, count, desc, eq, gte, inArray, isNull, or, sql, type SQL } from "drizzle-orm";
import { getDb, queryRows } from "@/db";
import { kev, vulnPackages, vulns, type Severity } from "@/db/schema";
import { categoryEcosystems, categoryPattern, type CategoryId } from "./categories";

export const PAGE_SIZE = 50;

export const SORTS = {
  newest: "Newest",
  severity: "Worst first",
  updated: "Recently updated",
} as const;
export type Sort = keyof typeof SORTS;

export const KINDS = {
  advisories: "CVEs and advisories",
  exploited: "Known exploited (CISA KEV)",
  packages: "Package advisories only",
  malware: "Malicious packages",
  all: "Everything",
} as const;
export type Kind = keyof typeof KINDS;
export const MAX_PAGE = 100;
export const MAX_QUERY_LENGTH = 100;

export type VulnSummary = {
  id: string;
  aliases: string[];
  summary: string | null;
  severity: Severity | null;
  published: Date | null;
  packages: { ecosystem: string; name: string }[];
  // Listed in CISA's Known Exploited Vulnerabilities catalog.
  exploited: boolean;
  ransomware: boolean;
  // Set for CISA KEV entries that have no package advisory.
  product: { vendor: string; product: string } | null;
};

export type VulnFilter = {
  ecosystems?: string[];
  packages?: string[];
  categories?: CategoryId[];
  severities?: Severity[];
  // Free text: an advisory or CVE ID, part of a package name, or a word in the summary.
  query?: string;
  publishedSince?: Date;
  kind?: Kind;
};

// OSV's malicious-package reports (MAL-...) arrive by the hundred, mostly typosquats.
const isMalware = sql<boolean>`${vulns.id} like 'MAL-%'`;

const packagesOf = sql<{ ecosystem: string; name: string }[]>`coalesce((
  select json_agg(json_build_object('ecosystem', p.ecosystem, 'name', p.name) order by p.ecosystem, p.name)
  from ${vulnPackages} p where p.vuln_id = ${vulns.id}
), '[]'::json)`;

// The KEV entry for an advisory, through its CVE alias (or its own ID for CVE records).
const exploitOf = sql`left join lateral (
  select ek.ransomware from ${kev} ek where ek.cve_id = any(${vulns.aliases} || ${vulns.id})
  order by ek.ransomware desc limit 1
) exploit on true`;

// Advisories listed in CISA KEV, through an alias or their own ID. A few
// hundred, so Postgres checks membership with one hash lookup per row.
const isExploited = sql<boolean>`${vulns.id} in (
  select v.id from ${vulns} v join ${kev} k on v.aliases @> array[k.cve_id]
  union select v.id from ${vulns} v join ${kev} k on v.id = k.cve_id
)`;

// KEV entries without a (non-withdrawn) advisory of their own. Two checks
// rather than one with "or", so each can use its index (aliases GIN, id key).
const kevOnly = sql`not exists (
    select 1 from ${vulns} v where v.aliases @> array[${kev.cveId}] and v.withdrawn is null
  ) and not exists (
    select 1 from ${vulns} v where v.id = ${kev.cveId} and v.withdrawn is null
  )`;

const likePattern = (text: string) => `%${text.replace(/[\\%_]/g, "\\$&")}%`;

function osvConditions({
  ecosystems,
  packages,
  categories,
  severities,
  query,
  publishedSince,
  kind = "all",
}: VulnFilter): SQL[] {
  const conditions: SQL[] = [isNull(vulns.withdrawn)];
  if (kind === "advisories" || kind === "packages") conditions.push(sql`not ${isMalware}`);
  if (kind === "malware") conditions.push(isMalware);
  if (kind === "exploited") conditions.push(isExploited);
  if (severities?.length) conditions.push(inArray(vulns.severity, severities));
  if (publishedSince) conditions.push(gte(vulns.published, publishedSince));
  if (ecosystems?.length || packages?.length) {
    const packageMatch = and(
      sql`p.vuln_id = ${vulns.id}`,
      ecosystems?.length ? sql`p.ecosystem in ${ecosystems}` : undefined,
      packages?.length ? sql`p.name in ${packages}` : undefined,
    );
    conditions.push(sql`exists (select 1 from ${vulnPackages} p where ${packageMatch})`);
  }
  if (categories?.length) {
    const byCategory = categories.map((id) => {
      const ecosystemsOf = categoryEcosystems(id);
      return or(
        sql`p.name ~* ${categoryPattern(id)}`,
        ecosystemsOf.length ? sql`p.ecosystem in ${ecosystemsOf}` : undefined,
      );
    });
    conditions.push(sql`exists (select 1 from ${vulnPackages} p where p.vuln_id = ${vulns.id} and (${or(...byCategory)}))`);
  }
  if (query) {
    const like = likePattern(query);
    conditions.push(sql`(
      lower(${vulns.id}) = lower(${query})
      or upper(${query}) = any(${vulns.aliases})
      or ${vulns.summary} ilike ${like}
      or exists (select 1 from ${vulnPackages} p where p.vuln_id = ${vulns.id} and p.name ilike ${like})
    )`);
  }
  return conditions;
}

// KEV entries have no packages or severity score, so package and severity
// filters leave them out. Entries with a package advisory show as that advisory.
function kevConditions({ ecosystems, packages, categories, severities, query, publishedSince, kind = "all" }: VulnFilter): SQL[] | null {
  if (kind === "packages" || kind === "malware") return null;
  if (severities?.length || ecosystems?.length || packages?.length) return null;
  const conditions: SQL[] = [
    kevOnly,
  ];
  if (publishedSince) conditions.push(gte(kev.dateAdded, publishedSince));
  if (categories?.length) {
    // Vendor and product only: vulnerability names say things like "SQL Injection".
    conditions.push(or(...categories.map((id) => sql`(${kev.vendor} || ' ' || ${kev.product}) ~* ${categoryPattern(id)}`))!);
  }
  if (query) {
    const like = likePattern(query);
    conditions.push(sql`(
      ${kev.cveId} = upper(${query})
      or ${kev.vendor} ilike ${like} or ${kev.product} ilike ${like} or ${kev.name} ilike ${like}
    )`);
  }
  return conditions;
}

// Raw queries get timestamps as strings: Drizzle turns off pg's date parsing.
type ListRow = Omit<VulnSummary, "product" | "published"> & {
  published: string | null;
  vendor: string | null;
  kev_product: string | null;
};

export async function listVulns(
  filter: VulnFilter = {},
  {
    page = 1,
    limit = PAGE_SIZE,
    sort = "newest",
  }: { page?: number; limit?: number; sort?: Sort } = {},
): Promise<VulnSummary[]> {
  // Pick the page from narrow rows first, then fetch the details for just
  // those rows: with a full local copy of OSV there are hundreds of thousands.
  const advisories = sql`select 'osv' as source, ${vulns.id} as id, ${vulns.severity} as severity,
      ${vulns.published} as published, ${vulns.modified} as updated, ${isExploited} as exploited
    from ${vulns}
    where ${and(...osvConditions(filter))}`;
  const kevWhere = kevConditions(filter);
  const exploitedOnly = kevWhere
    ? sql`union all
    select 'kev', ${kev.cveId}, null::text, ${kev.dateAdded}, ${kev.dateAdded}, true
    from ${kev}
    where ${and(...kevWhere)}`
    : sql``;

  const rows = await queryRows<ListRow>(getDb(), sql`
    select listed.id, listed.severity, listed.published, listed.exploited,
      coalesce(${vulns.aliases}, array[]::text[]) as aliases, coalesce(${vulns.summary}, ${kev.name}) as summary,
      ${packagesOf} as packages, coalesce(exploit.ransomware, ${kev.ransomware}, false) as ransomware,
      ${kev.vendor} as vendor, ${kev.product} as kev_product
    from (
      select * from (${advisories} ${exploitedOnly}) as candidates
      order by ${orderFor(sort)}, id asc
      limit ${limit} offset ${(page - 1) * limit}
    ) as listed
    left join ${vulns} on listed.source = 'osv' and ${vulns.id} = listed.id
    left join ${kev} on listed.source = 'kev' and ${kev.cveId} = listed.id
    ${exploitOf}
    order by ${orderFor(sort, "listed")}, listed.id asc`);
  return rows.map(({ vendor, kev_product, published, ...row }) => ({
    ...row,
    published: published === null ? null : new Date(published),
    product: vendor !== null && kev_product !== null ? { vendor, product: kev_product } : null,
  }));
}

// Column names, optionally qualified (the outer query also joins tables with
// columns of the same names).
function orderFor(sort: Sort, from?: string): SQL {
  const col = (name: string) => sql.raw(from ? `${from}.${name}` : name);
  const newest = sql`${col("published")} desc nulls last`;
  switch (sort) {
    case "severity":
      // CISA publishes no score, but being exploited ranks an advisory with high ones.
      return sql`case ${col("severity")} when 'critical' then 0 when 'high' then 1 when 'medium' then 2 when 'low' then 3
        else case when ${col("exploited")} then 1 else 4 end end, ${newest}`;
    case "updated":
      return sql`${col("updated")} desc`;
    case "newest":
      return newest;
  }
}

export type KevEntry = typeof kev.$inferSelect;

export async function getVuln(id: string) {
  const [row] = await getDb()
    .select({
      id: vulns.id,
      aliases: vulns.aliases,
      summary: vulns.summary,
      details: vulns.details,
      severity: vulns.severity,
      cvssScore: vulns.cvssScore,
      published: vulns.published,
      modified: vulns.modified,
      withdrawn: vulns.withdrawn,
      record: vulns.record,
      packages: packagesOf,
    })
    .from(vulns)
    .where(eq(vulns.id, id));
  if (!row) return null;
  const exploits = await getDb()
    .select()
    .from(kev)
    .where(inArray(kev.cveId, [...row.aliases, row.id]))
    .orderBy(asc(kev.cveId));
  return { ...row, exploits };
}

export type VulnDetail = NonNullable<Awaited<ReturnType<typeof getVuln>>>;

export async function getKevEntry(cveId: string): Promise<KevEntry | null> {
  const [row] = await getDb().select().from(kev).where(eq(kev.cveId, cveId));
  return row ?? null;
}

// CVE IDs usually appear as aliases of GHSA/PYSEC/GO records rather than as records.
export async function findIdsByAlias(alias: string): Promise<string[]> {
  const rows = await getDb()
    .select({ id: vulns.id })
    .from(vulns)
    .where(sql`${vulns.aliases} @> array[${alias}]::text[]`)
    .orderBy(asc(vulns.id))
    .limit(20);
  return rows.map((r) => r.id);
}

export async function listEcosystems(): Promise<{ ecosystem: string; count: number }[]> {
  return getDb()
    .select({ ecosystem: vulnPackages.ecosystem, count: count() })
    .from(vulnPackages)
    .groupBy(vulnPackages.ecosystem)
    .orderBy(desc(count()));
}

export type RecentCounts = Record<Severity | "unknown" | "malware" | "exploited", number>;

// Advisories published since a date, by severity, with malicious packages
// counted apart, plus CVEs CISA added to its exploited catalog.
export async function countRecent(since: Date): Promise<RecentCounts> {
  const [rows, [exploited]] = await Promise.all([
    getDb()
      .select({ severity: vulns.severity, malware: isMalware, n: count() })
      .from(vulns)
      .where(and(isNull(vulns.withdrawn), gte(vulns.published, since)))
      .groupBy(vulns.severity, isMalware),
    getDb().select({ n: count() }).from(kev).where(gte(kev.dateAdded, since)),
  ]);
  const counts: RecentCounts = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0, malware: 0, exploited: exploited?.n ?? 0 };
  for (const row of rows) counts[row.malware ? "malware" : (row.severity ?? "unknown")] += row.n;
  return counts;
}


export async function countVulns(): Promise<number> {
  const [[advisories], [exploits]] = await Promise.all([
    getDb().select({ n: count() }).from(vulns).where(isNull(vulns.withdrawn)),
    getDb().select({ n: count() }).from(kev).where(kevOnly),
  ]);
  return (advisories?.n ?? 0) + (exploits?.n ?? 0);
}

export async function listVulnIdsForSitemap(offset: number, limit: number): Promise<{ id: string; modified: Date }[]> {
  const rows = await queryRows<{ id: string; modified: string }>(getDb(), sql`
    select id, modified from (
      select ${vulns.id} as id, ${vulns.modified} as modified from ${vulns} where ${isNull(vulns.withdrawn)}
      union all
      select ${kev.cveId}, ${kev.dateAdded} from ${kev} where ${kevOnly}
    ) as pages
    order by id limit ${limit} offset ${offset}`);
  return rows.map((row) => ({ id: row.id, modified: new Date(row.modified) }));
}
