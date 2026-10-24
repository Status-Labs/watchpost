import { and, asc, eq, inArray, lt, sql } from "drizzle-orm";
import type { Db } from "@/db";
import { syncFailures, vulnPackages, vulns } from "@/db/schema";
import { loadSyncState, saveSyncState } from "@/db/sync-state";
import { LANGUAGES } from "@/lib/ecosystems";
import { osvRecordSchema, toRows, type OsvRecord } from "./record";

export const OSV_BUCKET = "https://osv-vulnerabilities.storage.googleapis.com";

// Language package ecosystems. OS distros (Debian, Ubuntu, Alpine...) change
// ~25k records a day and come later, with OS package matching.
export const SYNCED_ECOSYSTEMS: ReadonlySet<string> = new Set(LANGUAGES.map((l) => l.ecosystem));

const SOURCE = "osv";
const INITIAL_LOOKBACK_DAYS = 7;
const MAX_RECORDS_PER_RUN = 500;
const FETCH_CONCURRENCY = 16;
const LIST_TIMEOUT_MS = 60_000;
const RECORD_TIMEOUT_MS = 15_000;
const MAX_RECORD_BYTES = 2_000_000;
// Stop starting fetches well before the function's 300s limit, leaving time to write.
const FETCH_BUDGET_MS = 180_000;
const MAX_ATTEMPTS = 5;
const RETRIES_PER_RUN = 50;
const INSERT_CHUNK = 500;

type Fetch = typeof fetch;

export type ChangedEntry = { modified: string; ecosystem: string; id: string };

export type FetchOutcome =
  | { kind: "record"; record: OsvRecord }
  | { kind: "deleted" }
  | { kind: "failed"; error: string };

export type SyncResult = {
  cursor: string;
  processed: number;
  upserted: number;
  failed: number;
  retried: number;
  remaining: number;
};

export async function runOsvSync({
  db,
  fetchFn = fetch,
  now = new Date(),
}: {
  db: Db;
  fetchFn?: Fetch;
  now?: Date;
}): Promise<SyncResult> {
  const state = await loadSyncState(db, SOURCE);
  const cursor =
    state?.cursor ??
    cursorKey({
      modified: normalizeTimestamp(new Date(now.getTime() - INITIAL_LOOKBACK_DAYS * 86_400_000).toISOString()),
      ecosystem: "",
      id: "",
    });
  const deadline = Date.now() + FETCH_BUDGET_MS;

  try {
    const changes = await readChangesSince(fetchFn, cursor);
    const batch = nextBatch(changes, MAX_RECORDS_PER_RUN);
    const retries = await dueRetries(db);

    const fetched = await mapUntil([...batch, ...retries], FETCH_CONCURRENCY, deadline, (entry) =>
      fetchRecord(fetchFn, entry),
    );

    // The cursor only moves over the leading run of batch entries we actually
    // attempted; anything after a time-budget cutoff is picked up next run.
    let attempted = 0;
    while (attempted < batch.length && fetched[attempted] !== undefined) attempted++;
    const done = [...batch.slice(0, attempted), ...retries].flatMap((entry, i) => {
      const outcome = fetched[i < attempted ? i : batch.length + (i - attempted)];
      return outcome ? [{ entry, outcome }] : [];
    });

    const records = done.flatMap(({ outcome }) => (outcome.kind === "record" ? [outcome.record] : []));
    const { upserted, rejected } = await upsertRecords(db, records);
    for (const item of done) {
      const error = rejected.get(item.entry.id);
      if (error) item.outcome = { kind: "failed", error };
    }
    await recordFailures(db, done, now);

    const nextCursor = attempted ? cursorKey(batch[attempted - 1]) : cursor;
    await saveSyncState(db, { source: SOURCE, cursor: nextCursor, now, error: null });
    return {
      cursor: nextCursor,
      processed: attempted,
      upserted,
      failed: done.filter(({ outcome }) => outcome.kind === "failed").length,
      retried: retries.length,
      remaining: changes.length - attempted,
    };
  } catch (error) {
    await saveSyncState(db, { source: SOURCE, cursor, now, error: String(error).slice(0, 1000) });
    throw error;
  }
}

// OSV's modified_id.csv lists every record as "<modified>,<ecosystem>/<id>",
// newest first. Stream it and stop once lines are older than the cursor.
export async function readChangesSince(fetchFn: Fetch, cursor: string): Promise<ChangedEntry[]> {
  // OSV serves this with max-age=3600; never let a cache hand us an old copy.
  const res = await fetchFn(`${OSV_BUCKET}/modified_id.csv`, {
    cache: "no-store",
    signal: AbortSignal.timeout(LIST_TIMEOUT_MS),
  });
  if (!res.ok || !res.body) throw new Error(`OSV modified_id.csv: HTTP ${res.status}`);

  const cursorModified = cursor.split("\t")[0];
  const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
  const changes: ChangedEntry[] = [];
  let buffered = "";

  try {
    while (true) {
      const { done, value } = await reader.read();
      buffered += value ?? "";
      const lines = buffered.split("\n");
      buffered = done ? "" : (lines.pop() ?? "");

      for (const line of lines) {
        const entry = parseLine(line);
        if (!entry) continue;
        if (entry.modified < cursorModified) return changes;
        if (SYNCED_ECOSYSTEMS.has(entry.ecosystem) && cursorKey(entry) > cursor) changes.push(entry);
      }
      if (done) return changes;
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
}

// Oldest changes first, in a fixed order, so the cursor only moves forward.
export function nextBatch(changes: ChangedEntry[], limit: number): ChangedEntry[] {
  return [...changes].sort((a, b) => (cursorKey(a) < cursorKey(b) ? -1 : 1)).slice(0, limit);
}

export function cursorKey(entry: ChangedEntry): string {
  return `${entry.modified}\t${entry.ecosystem}/${entry.id}`;
}

export function parseLine(line: string): ChangedEntry | null {
  const comma = line.indexOf(",");
  const slash = line.lastIndexOf("/");
  if (comma < 0 || slash < comma) return null;
  const modified = normalizeTimestamp(line.slice(0, comma));
  const ecosystem = line.slice(comma + 1, slash);
  const id = line.slice(slash + 1).trim();
  if (!modified || !ecosystem || !id) return null;
  return { modified, ecosystem, id };
}

// OSV timestamps have 0 to 9 fractional digits. Pad to 9 so plain string
// comparison orders them correctly ("05.1Z" would otherwise sort after "05.12Z").
export function normalizeTimestamp(ts: string): string {
  const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z$/.exec(ts.trim());
  if (!match) return "";
  return `${match[1]}.${(match[2] ?? "").padEnd(9, "0")}Z`;
}

// Never throws: one bad record becomes a failure entry, not a failed run.
export async function fetchRecord(fetchFn: Fetch, entry: ChangedEntry): Promise<FetchOutcome> {
  const url = `${OSV_BUCKET}/${encodeURIComponent(entry.ecosystem)}/${encodeURIComponent(entry.id)}.json`;
  try {
    const res = await fetchFn(url, { signal: AbortSignal.timeout(RECORD_TIMEOUT_MS) });
    // A record can be deleted between the listing and the fetch.
    if (res.status === 404) return { kind: "deleted" };
    if (!res.ok) return { kind: "failed", error: `HTTP ${res.status}` };
    if (Number(res.headers.get("content-length") ?? 0) > MAX_RECORD_BYTES) {
      return { kind: "failed", error: "record too large" };
    }

    const text = await res.text();
    if (text.length > MAX_RECORD_BYTES) return { kind: "failed", error: "record too large" };

    const parsed = osvRecordSchema.safeParse(JSON.parse(text));
    if (!parsed.success) return { kind: "failed", error: "record does not match the OSV schema" };
    if (parsed.data.id !== entry.id) return { kind: "failed", error: "record ID does not match the listing" };
    return { kind: "record", record: parsed.data };
  } catch (error) {
    return { kind: "failed", error: String(error).slice(0, 500) };
  }
}

// Writes records, skipping any older than what's stored so a late retry can't
// overwrite newer data. If the database rejects a batch, records are written one
// at a time and the rejected ones are returned instead of failing the whole run.
export async function upsertRecords(
  db: Db,
  records: OsvRecord[],
): Promise<{ upserted: number; rejected: Map<string, string> }> {
  const rejected = new Map<string, string>();
  // One row per ID: Postgres rejects an upsert that touches the same row twice.
  const byId = new Map<string, OsvRecord>();
  for (const record of records) {
    const seen = byId.get(record.id);
    if (!seen || record.modified > seen.modified) byId.set(record.id, record);
  }
  const rows = [...byId.values()].map(toRows);
  if (rows.length === 0) return { upserted: 0, rejected };

  const stored = await db
    .select({ id: vulns.id, modified: vulns.modified })
    .from(vulns)
    .where(inArray(vulns.id, rows.map((r) => r.vuln.id)));
  const storedModified = new Map(stored.map((s) => [s.id, s.modified.getTime()]));
  const fresh = rows.filter((r) => r.vuln.modified.getTime() >= (storedModified.get(r.vuln.id) ?? 0));
  if (fresh.length === 0) return { upserted: 0, rejected };

  try {
    await writeRows(db, fresh);
    return { upserted: fresh.length, rejected };
  } catch {
    let upserted = 0;
    for (const row of fresh) {
      try {
        await writeRows(db, [row]);
        upserted++;
      } catch (error) {
        rejected.set(row.vuln.id, `database rejected record: ${String(error).slice(0, 300)}`);
      }
    }
    return { upserted, rejected };
  }
}

async function writeRows(db: Db, rows: ReturnType<typeof toRows>[]) {
  await db.transaction(async (tx) => {
    for (const chunk of chunks(rows, INSERT_CHUNK)) {
      await tx
        .insert(vulns)
        .values(chunk.map((r) => r.vuln))
        .onConflictDoUpdate({
          target: vulns.id,
          set: {
            aliases: sql`excluded.aliases`,
            summary: sql`excluded.summary`,
            details: sql`excluded.details`,
            severity: sql`excluded.severity`,
            cvssScore: sql`excluded.cvss_score`,
            published: sql`excluded.published`,
            modified: sql`excluded.modified`,
            withdrawn: sql`excluded.withdrawn`,
            record: sql`excluded.record`,
            syncedAt: sql`now()`,
          },
        });
      await tx.delete(vulnPackages).where(
        inArray(
          vulnPackages.vulnId,
          chunk.map((r) => r.vuln.id),
        ),
      );
      for (const packages of chunks(chunk.flatMap((r) => r.packages), INSERT_CHUNK * 4)) {
        await tx.insert(vulnPackages).values(packages).onConflictDoNothing();
      }
    }
  });
}

async function dueRetries(db: Db): Promise<ChangedEntry[]> {
  const rows = await db
    .select()
    .from(syncFailures)
    .where(and(eq(syncFailures.source, SOURCE), lt(syncFailures.attempts, MAX_ATTEMPTS)))
    .orderBy(asc(syncFailures.updatedAt))
    .limit(RETRIES_PER_RUN);
  return rows.map((row) => ({ modified: row.modified, ecosystem: row.ecosystem, id: row.vulnId }));
}

async function recordFailures(
  db: Db,
  done: { entry: ChangedEntry; outcome: FetchOutcome }[],
  now: Date,
) {
  // A record that now fetches cleanly no longer needs retrying.
  const recovered = done.filter(({ outcome }) => outcome.kind !== "failed").map(({ entry }) => entry.id);
  if (recovered.length) {
    await db
      .delete(syncFailures)
      .where(and(eq(syncFailures.source, SOURCE), inArray(syncFailures.vulnId, recovered)));
  }

  for (const { entry, outcome } of done) {
    if (outcome.kind !== "failed") continue;
    console.warn(`OSV ${entry.ecosystem}/${entry.id}: ${outcome.error}`);
    await db
      .insert(syncFailures)
      .values({
        source: SOURCE,
        ecosystem: entry.ecosystem,
        vulnId: entry.id,
        modified: entry.modified,
        lastError: outcome.error,
        updatedAt: now,
      })
      .onConflictDoUpdate({
        target: [syncFailures.source, syncFailures.ecosystem, syncFailures.vulnId],
        set: {
          attempts: sql`${syncFailures.attempts} + 1`,
          modified: entry.modified,
          lastError: outcome.error,
          updatedAt: now,
        },
      });
  }
}

// Runs fn over items with limited concurrency, starting no new item after the
// deadline. Items never started are left undefined.
export async function mapUntil<T, R>(
  items: T[],
  concurrency: number,
  deadline: number,
  fn: (item: T) => Promise<R>,
): Promise<(R | undefined)[]> {
  const results = new Array<R | undefined>(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (next < items.length && Date.now() < deadline) {
      const index = next++;
      results[index] = await fn(items[index]);
    }
  });
  await Promise.all(workers);
  return results;
}

function chunks<T>(items: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}
