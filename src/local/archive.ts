import { createWriteStream } from "node:fs";
import { mkdir, rm } from "node:fs/promises";
import path from "node:path";
import { Readable, Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import type { ReadableStream as WebReadableStream } from "node:stream/web";
import { inArray, like, sql } from "drizzle-orm";
import type { Db } from "@/db";
import { syncState } from "@/db/schema";
import { loadSyncState, saveSyncState } from "@/db/sync-state";
import { osvRecordSchema, type OsvRecord } from "@/osv/record";
import { OSV_BUCKET, SYNCED_ECOSYSTEMS, normalizeTimestamp, upsertRecords } from "@/osv/sync";
import { dataDir } from "./mode";
import { readZip } from "./zip";

// The first run of the local app downloads OSV's full history, one archive per
// ecosystem (about 300 MB compressed). After that, the regular incremental sync
// keeps it current. Each finished ecosystem is recorded, so an interrupted
// import picks up where it stopped.

const STATE_PREFIX = "osv-archive:";
const MAX_ARCHIVE_BYTES = 2_000_000_000;
const MAX_RECORD_BYTES = 2_000_000;
const DOWNLOAD_TIMEOUT_MS = 30 * 60_000;
const BATCH = 500;
// Archives can lag the live data; the incremental sync starts this far before
// the earliest download so nothing falls in between. Replaying a day of
// changes is cheap; upserts are idempotent.
const CURSOR_MARGIN_MS = 24 * 3_600_000;

type Fetch = typeof fetch;

export type ArchiveProgress = { ecosystem: string; done: number; total: number; records: number };

// npm is by far the largest (mostly malicious-package reports), so it goes last
// and everything else is ready sooner.
export function archiveOrder(): string[] {
  return [...SYNCED_ECOSYSTEMS].sort((a, b) => Number(a === "npm") - Number(b === "npm"));
}

export async function importArchives({
  db,
  fetchFn = fetch,
  now = () => new Date(),
  onProgress = () => {},
}: {
  db: Db;
  fetchFn?: Fetch;
  now?: () => Date;
  onProgress?: (progress: ArchiveProgress) => void;
}): Promise<{ imported: number; skipped: number }> {
  const ecosystems = archiveOrder();
  const done = await importedEcosystems(db);
  let imported = 0;
  let skipped = 0;

  for (const [index, ecosystem] of ecosystems.entries()) {
    if (done.has(ecosystem)) continue;
    const source = `${STATE_PREFIX}${ecosystem}`;
    try {
      const result = await importArchive(db, fetchFn, ecosystem, (records) =>
        onProgress({ ecosystem, done: index, total: ecosystems.length, records }),
      );
      imported += result.imported;
      skipped += result.skipped;
      // The cursor notes when OSV last changed the archive; last_success_at, when we downloaded it.
      await saveSyncState(db, { source, cursor: result.changedAt, now: now(), error: null });
    } catch (error) {
      await saveSyncState(db, { source, cursor: "", now: now(), error: String(error).slice(0, 1000) });
      throw error;
    }
  }

  await startIncrementalSync(db);
  // PGlite has no autovacuum: after a bulk load, the planner has no statistics
  // and the aliases index has a long pending list, which makes lists 10-40x slower.
  if (imported > 0) await db.execute(sql`vacuum analyze`);
  return { imported, skipped };
}

export async function importComplete(db: Db): Promise<boolean> {
  const done = await importedEcosystems(db);
  return archiveOrder().every((e) => done.has(e));
}

export async function importedEcosystems(db: Db): Promise<Set<string>> {
  const rows = await db.select().from(syncState).where(like(syncState.source, `${STATE_PREFIX}%`));
  return new Set(rows.filter((row) => row.lastSuccessAt && row.lastError === null).map((row) => row.source.slice(STATE_PREFIX.length)));
}

async function importArchive(db: Db, fetchFn: Fetch, ecosystem: string, onRecords: (records: number) => void) {
  const folder = path.join(dataDir(), "downloads");
  await mkdir(folder, { recursive: true });
  const file = path.join(folder, `${ecosystem.replace(/[^A-Za-z0-9.-]/g, "_")}.zip`);

  try {
    const changedAt = await download(fetchFn, `${OSV_BUCKET}/${encodeURIComponent(ecosystem)}/all.zip`, file);
    let imported = 0;
    let skipped = 0;
    let batch: OsvRecord[] = [];
    const flush = async () => {
      const { upserted, rejected } = await upsertRecords(db, batch);
      imported += upserted;
      skipped += rejected.size;
      batch = [];
      onRecords(imported);
    };

    for await (const { data } of readZip(file, { maxEntryBytes: MAX_RECORD_BYTES })) {
      const record = data ? parseRecord(data) : null;
      if (!record) {
        skipped++;
        continue;
      }
      batch.push(record);
      if (batch.length >= BATCH) await flush();
    }
    if (batch.length) await flush();
    return { imported, skipped, changedAt };
  } finally {
    await rm(file, { force: true });
  }
}

function parseRecord(data: Buffer): OsvRecord | null {
  try {
    const parsed = osvRecordSchema.safeParse(JSON.parse(data.toString("utf8")));
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}

// Streams the archive to disk with a size cap. Returns when OSV last changed it.
async function download(fetchFn: Fetch, url: string, file: string): Promise<string> {
  const res = await fetchFn(url, { cache: "no-store", signal: AbortSignal.timeout(DOWNLOAD_TIMEOUT_MS) });
  if (!res.ok || !res.body) throw new Error(`OSV archive: HTTP ${res.status}`);
  if (Number(res.headers.get("content-length") ?? 0) > MAX_ARCHIVE_BYTES) throw new Error("OSV archive: too large");

  let received = 0;
  const cap = new Transform({
    transform(chunk: Buffer, _encoding, callback) {
      received += chunk.length;
      callback(received > MAX_ARCHIVE_BYTES ? new Error("OSV archive: too large") : null, chunk);
    },
  });
  await pipeline(Readable.fromWeb(res.body as WebReadableStream), cap, createWriteStream(file));

  const lastModified = Date.parse(res.headers.get("last-modified") ?? "");
  return new Date(Number.isNaN(lastModified) ? Date.now() : lastModified).toISOString();
}

// Points the incremental sync at the earliest download, minus a margin. (Not
// the archives' Last-Modified: a quiet ecosystem's archive can be weeks old and
// still current.)
async function startIncrementalSync(db: Db) {
  const rows = await db
    .select()
    .from(syncState)
    .where(inArray(syncState.source, archiveOrder().map((e) => `${STATE_PREFIX}${e}`)));
  const downloaded = rows.flatMap((row) => (row.lastSuccessAt ? [row.lastSuccessAt.getTime()] : []));
  if (downloaded.length === 0) return;

  const start = normalizeTimestamp(new Date(Math.min(...downloaded) - CURSOR_MARGIN_MS).toISOString());
  const osv = await loadSyncState(db, "osv");
  const current = osv?.cursor.split("\t")[0];
  // Never move an existing cursor forward past changes it hasn't seen.
  if (current && current <= start) return;
  await saveSyncState(db, { source: "osv", cursor: `${start}\t/`, now: new Date(), error: null });
}
