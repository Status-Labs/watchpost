import { z } from "zod";
import type { Db } from "@/db";
import { kev } from "@/db/schema";
import { loadSyncState, saveSyncState } from "@/db/sync-state";
import { oneLine, stripUnsafe, truncate } from "@/lib/sanitize";

export const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

const SOURCE = "kev";
const TIMEOUT_MS = 60_000;
const MAX_BYTES = 20_000_000;
const MAX_SHORT = 300;
const MAX_LONG = 2_000;
const INSERT_CHUNK = 500;
// The catalog only grows (1,500+ entries). A much smaller or mostly invalid
// file means something is wrong upstream, so keep what we have.
const MIN_ENTRIES = 500;
const MIN_VALID_SHARE = 0.9;

type Fetch = typeof fetch;

const isoDate = z.string().regex(/^\d{4}-\d{2}-\d{2}$/);

const entrySchema = z.looseObject({
  cveID: z.string().regex(/^CVE-\d{4}-\d{4,}$/),
  vendorProject: z.string(),
  product: z.string(),
  vulnerabilityName: z.string(),
  dateAdded: isoDate,
  dueDate: isoDate.optional().catch(undefined),
  shortDescription: z.string(),
  requiredAction: z.string(),
  knownRansomwareCampaignUse: z.string().optional(),
});

const catalogSchema = z.looseObject({ vulnerabilities: z.array(z.unknown()) });

export type KevRow = typeof kev.$inferInsert;

export type KevSyncResult = { changed: boolean; entries: number; skipped: number };

// CISA's server ignores ETags but honors If-Modified-Since, so the cursor holds
// the Last-Modified header of the file we stored.
export async function runKevSync({
  db,
  fetchFn = fetch,
  now = new Date(),
}: {
  db: Db;
  fetchFn?: Fetch;
  now?: Date;
}): Promise<KevSyncResult> {
  const state = await loadSyncState(db, SOURCE);
  const lastModified = state?.cursor ?? "";

  try {
    const res = await fetchFn(KEV_URL, {
      cache: "no-store",
      headers: lastModified ? { "If-Modified-Since": lastModified } : {},
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (res.status === 304) {
      await saveSyncState(db, { source: SOURCE, cursor: lastModified, now, error: null });
      return { changed: false, entries: 0, skipped: 0 };
    }
    if (!res.ok) throw new Error(`CISA KEV: HTTP ${res.status}`);
    if (Number(res.headers.get("content-length") ?? 0) > MAX_BYTES) throw new Error("CISA KEV: file too large");
    const text = await res.text();
    if (text.length > MAX_BYTES) throw new Error("CISA KEV: file too large");

    const { rows, skipped } = parseCatalog(JSON.parse(text));
    await replaceCatalog(db, rows);
    await saveSyncState(db, { source: SOURCE, cursor: res.headers.get("last-modified") ?? "", now, error: null });
    return { changed: true, entries: rows.length, skipped };
  } catch (error) {
    await saveSyncState(db, { source: SOURCE, cursor: lastModified, now, error: String(error).slice(0, 1000) });
    throw error;
  }
}

export function parseCatalog(json: unknown): { rows: KevRow[]; skipped: number } {
  const catalog = catalogSchema.parse(json);
  const rows = new Map<string, KevRow>();
  let skipped = 0;
  for (const raw of catalog.vulnerabilities) {
    const parsed = entrySchema.safeParse(raw);
    if (!parsed.success) {
      skipped++;
      continue;
    }
    rows.set(parsed.data.cveID, toRow(parsed.data));
  }

  const total = catalog.vulnerabilities.length;
  if (rows.size < MIN_ENTRIES || rows.size < total * MIN_VALID_SHARE) {
    throw new Error(`CISA KEV: only ${rows.size} of ${total} entries are valid; keeping the current catalog`);
  }
  return { rows: [...rows.values()], skipped };
}

function toRow(entry: z.infer<typeof entrySchema>): KevRow {
  // CISA is a trusted source, but the text still goes to browsers, feeds and
  // AI assistants, so it gets the same sanitizing as any upstream text.
  const short = (value: string) => truncate(oneLine(value), MAX_SHORT);
  return {
    cveId: entry.cveID,
    vendor: short(entry.vendorProject),
    product: short(entry.product),
    name: short(entry.vulnerabilityName),
    description: truncate(stripUnsafe(entry.shortDescription).trim(), MAX_LONG),
    requiredAction: truncate(stripUnsafe(entry.requiredAction).trim(), MAX_LONG),
    dateAdded: new Date(`${entry.dateAdded}T00:00:00Z`),
    dueDate: entry.dueDate ? new Date(`${entry.dueDate}T00:00:00Z`) : null,
    ransomware: entry.knownRansomwareCampaignUse?.toLowerCase() === "known",
  };
}

async function replaceCatalog(db: Db, rows: KevRow[]) {
  await db.transaction(async (tx) => {
    await tx.delete(kev);
    for (let i = 0; i < rows.length; i += INSERT_CHUNK) {
      await tx.insert(kev).values(rows.slice(i, i + INSERT_CHUNK));
    }
  });
}
