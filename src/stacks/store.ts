import { and, asc, count, desc, eq, gte, inArray, isNull, sql } from "drizzle-orm";
import type { Db } from "@/db";
import { kev, matches, stackItems, stacks, vulns, workspaces, type Severity } from "@/db/schema";
import { fetchRecord, mapUntil, upsertRecords } from "@/osv/sync";
import { siteUrl, vulnPath } from "@/lib/site";
import { queryOsv } from "./osv-query";
import { dedupeAliases, fixedVersions } from "./results";
import type { StackItem } from "./validate";

export const MAX_STACKS = 50;
// Across all stacks in a workspace, so one key can't fill the database.
export const MAX_WORKSPACE_ITEMS = 20_000;
const INSERT_CHUNK = 1_000;
// Advisories OSV matched but we don't have yet are fetched while reporting, up
// to a limit; the rest show as IDs until a later report or sync fills them in.
const MAX_RECORD_FETCHES = 300;
const FETCH_CONCURRENCY = 16;
const FETCH_BUDGET_MS = 60_000;
const MAX_ALERTS = 200;

type Fetch = typeof fetch;

export class StackError extends Error {}

export type Alert = {
  id: string;
  aliases: string[];
  severity: Severity | null;
  stack: string;
  ecosystem: string;
  package: string;
  version: string;
  fixed_versions: string[];
  known_exploited: boolean;
  first_seen: string;
  url: string;
  osv_url: string;
};

export type ReportResult = {
  stack: string;
  items: number;
  alerts: Alert[];
  matching: "ok" | "unavailable";
};

// Replaces a stack's packages, asks OSV which of them are affected, and records
// the matches. Matches already known keep their first_seen date.
export async function reportStack(
  db: Db,
  { workspaceId, name, items, fetchFn = fetch }: { workspaceId: string; name: string; items: StackItem[]; fetchFn?: Fetch },
): Promise<ReportResult> {
  const stackId = await saveStack(db, workspaceId, name, items);

  let matching: ReportResult["matching"] = "ok";
  try {
    const found = await queryOsv(fetchFn, items);
    await saveMatches(db, stackId, found.map(({ item, vulnId }) => ({ ...item, vulnId })));
    await fetchMissingRecords(db, fetchFn, found);
  } catch {
    // Keep the stack and earlier matches; the assistant can try again.
    matching = "unavailable";
  }

  const alerts = await getAlerts(db, { workspaceId, stack: name });
  return { stack: name, items: items.length, alerts, matching };
}

async function saveStack(db: Db, workspaceId: string, name: string, items: StackItem[]): Promise<string> {
  return db.transaction(async (tx) => {
    // Serializes reports within a workspace, so concurrent calls can't both
    // create the same stack or slip past the limits below.
    await tx.execute(sql`select 1 from ${workspaces} where ${workspaces.id} = ${workspaceId} for update`);
    const [{ total }] = await tx
      .select({ total: count() })
      .from(stackItems)
      .innerJoin(stacks, eq(stacks.id, stackItems.stackId))
      .where(and(eq(stacks.workspaceId, workspaceId), sql`${stacks.name} <> ${name}`));
    if (total + items.length > MAX_WORKSPACE_ITEMS) {
      throw new StackError(`A workspace can hold at most ${MAX_WORKSPACE_ITEMS} packages across its stacks.`);
    }
    const [existing] = await tx
      .select({ id: stacks.id })
      .from(stacks)
      .where(and(eq(stacks.workspaceId, workspaceId), eq(stacks.name, name)));
    let stackId = existing?.id;
    if (stackId) {
      await tx.update(stacks).set({ updatedAt: new Date() }).where(eq(stacks.id, stackId));
      await tx.delete(stackItems).where(eq(stackItems.stackId, stackId));
    } else {
      const [{ n }] = await tx.select({ n: count() }).from(stacks).where(eq(stacks.workspaceId, workspaceId));
      if (n >= MAX_STACKS) throw new StackError(`A workspace can have at most ${MAX_STACKS} stacks. Delete one first.`);
      [{ id: stackId }] = await tx.insert(stacks).values({ workspaceId, name }).returning({ id: stacks.id });
    }
    for (let i = 0; i < items.length; i += INSERT_CHUNK) {
      await tx.insert(stackItems).values(items.slice(i, i + INSERT_CHUNK).map((item) => ({ stackId, ...item })));
    }
    return stackId;
  });
}

async function saveMatches(db: Db, stackId: string, found: (StackItem & { vulnId: string })[]) {
  const key = (m: { ecosystem: string; name: string; version: string; vulnId: string }) =>
    `${m.ecosystem}\u0000${m.name}\u0000${m.version}\u0000${m.vulnId}`;
  const unique = [...new Map(found.map((m) => [key(m), m])).values()];

  await db.transaction(async (tx) => {
    const existing = await tx.select().from(matches).where(eq(matches.stackId, stackId));
    const current = new Set(unique.map(key));
    const gone = existing.filter((m) => !current.has(key(m)));
    for (const m of gone) {
      await tx
        .delete(matches)
        .where(
          and(
            eq(matches.stackId, stackId),
            eq(matches.ecosystem, m.ecosystem),
            eq(matches.name, m.name),
            eq(matches.version, m.version),
            eq(matches.vulnId, m.vulnId),
          ),
        );
    }
    for (let i = 0; i < unique.length; i += INSERT_CHUNK) {
      await tx
        .insert(matches)
        .values(unique.slice(i, i + INSERT_CHUNK).map((m) => ({ stackId, ...m })))
        .onConflictDoNothing();
    }
  });
}

async function fetchMissingRecords(db: Db, fetchFn: Fetch, found: { item: StackItem; vulnId: string; modified: string }[]) {
  const ids = [...new Set(found.map((f) => f.vulnId))];
  if (ids.length === 0) return;
  const have = new Set<string>();
  for (let i = 0; i < ids.length; i += INSERT_CHUNK) {
    const rows = await db
      .select({ id: vulns.id })
      .from(vulns)
      .where(inArray(vulns.id, ids.slice(i, i + INSERT_CHUNK)));
    for (const row of rows) have.add(row.id);
  }
  const missing = new Map<string, { ecosystem: string; id: string; modified: string }>();
  for (const f of found) {
    if (!have.has(f.vulnId) && !missing.has(f.vulnId)) {
      missing.set(f.vulnId, { ecosystem: f.item.ecosystem, id: f.vulnId, modified: f.modified });
    }
  }
  const entries = [...missing.values()].slice(0, MAX_RECORD_FETCHES);
  const outcomes = await mapUntil(entries, FETCH_CONCURRENCY, Date.now() + FETCH_BUDGET_MS, (entry) =>
    fetchRecord(fetchFn, entry),
  );
  const records = outcomes.flatMap((o) => (o?.kind === "record" ? [o.record] : []));
  if (records.length) await upsertRecords(db, records);
}

const severityRank = sql<number>`case ${vulns.severity}
  when 'critical' then 0 when 'high' then 1 when 'medium' then 2 when 'low' then 3 else 4 end`;

// Structured fields only: no advisory text, which is written by whoever files
// the advisory and could try to steer an assistant.
export async function getAlerts(
  db: Db,
  { workspaceId, stack, since }: { workspaceId: string; stack?: string; since?: Date },
): Promise<Alert[]> {
  const rows = await db
    .select({
      id: matches.vulnId,
      severity: vulns.severity,
      aliases: vulns.aliases,
      stack: stacks.name,
      ecosystem: matches.ecosystem,
      name: matches.name,
      version: matches.version,
      firstSeen: matches.firstSeenAt,
      record: vulns.record,
      exploited: sql<boolean>`exists (select 1 from ${kev} k where k.cve_id = any(${vulns.aliases} || ${matches.vulnId}))`,
    })
    .from(matches)
    .innerJoin(stacks, eq(stacks.id, matches.stackId))
    .leftJoin(vulns, eq(vulns.id, matches.vulnId))
    .where(
      and(
        eq(stacks.workspaceId, workspaceId),
        stack ? eq(stacks.name, stack) : undefined,
        since ? gte(matches.firstSeenAt, since) : undefined,
        isNull(vulns.withdrawn),
      ),
    )
    .orderBy(severityRank, desc(matches.firstSeenAt), asc(matches.vulnId))
    .limit(MAX_ALERTS);

  return dedupeAliases(rows).map((row) => ({
    id: row.id,
    aliases: (row.aliases ?? []).filter((a) => a.startsWith("CVE-")),
    severity: row.severity,
    stack: row.stack,
    ecosystem: row.ecosystem,
    package: row.name,
    version: row.version,
    fixed_versions: fixedVersions(row.record, row.ecosystem, row.name),
    known_exploited: row.exploited,
    first_seen: row.firstSeen.toISOString(),
    url: siteUrl(vulnPath(row.id)),
    osv_url: `https://osv.dev/vulnerability/${encodeURIComponent(row.id)}`,
  }));
}

export async function listStacks(db: Db, workspaceId: string) {
  const rows = await db
    .select({
      name: stacks.name,
      updatedAt: stacks.updatedAt,
      items: sql<number>`(select count(*)::int from ${stackItems} where ${stackItems.stackId} = ${stacks.id})`,
      alerts: sql<number>`(select count(*)::int from ${matches} where ${matches.stackId} = ${stacks.id})`,
    })
    .from(stacks)
    .where(eq(stacks.workspaceId, workspaceId))
    .orderBy(asc(stacks.name));
  return rows.map((r) => ({ name: r.name, items: r.items, alerts: r.alerts, updated: r.updatedAt.toISOString() }));
}

export async function deleteStack(db: Db, workspaceId: string, name: string): Promise<boolean> {
  const deleted = await db
    .delete(stacks)
    .where(and(eq(stacks.workspaceId, workspaceId), eq(stacks.name, name)))
    .returning({ id: stacks.id });
  return deleted.length > 0;
}
