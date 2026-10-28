import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { sql } from "drizzle-orm";
import { Pool } from "pg";
import { afterAll, beforeEach, describe, expect, inject, it } from "vitest";
import { createDb } from "@/db";
import { syncState, vulnPackages, vulns } from "@/db/schema";
import { loadSyncState } from "@/db/sync-state";
import { matchLocally } from "@/match/local";
import { OSV_BUCKET } from "@/osv/sync";
import { archiveOrder, importArchives, importComplete } from "./archive";

const pool = new Pool({ connectionString: inject("databaseUrl") });
const db = createDb(pool);
const downloads = mkdtempSync(path.join(tmpdir(), "watchpost-archive-"));
process.env.WATCHPOST_DATA_DIR = downloads;

const archive = readFileSync("fixtures/osv-archive/all.zip");
const LAST_MODIFIED = "Tue, 27 Oct 2026 10:00:00 GMT";
const now = new Date("2026-10-28T12:00:00Z");

// Serves the same small archive for every ecosystem, and fails for those in `failing`.
function osvBucket(failing: Set<string> = new Set()) {
  const requested: string[] = [];
  const fetchFn = (async (input: RequestInfo | URL) => {
    const url = String(input);
    const ecosystem = decodeURIComponent(url.slice(OSV_BUCKET.length + 1, -"/all.zip".length));
    requested.push(ecosystem);
    if (failing.has(ecosystem)) return new Response("unavailable", { status: 503 });
    return new Response(archive, { headers: { "last-modified": LAST_MODIFIED } });
  }) as typeof fetch;
  return { fetchFn, requested };
}

beforeEach(async () => {
  await db.execute(sql`truncate ${syncState}, ${vulns}, ${vulnPackages}`);
});

afterAll(async () => {
  await pool.end();
  rmSync(downloads, { recursive: true, force: true });
});

describe("importArchives", () => {
  it("imports every ecosystem's archive and starts the incremental sync before the download", async () => {
    const { fetchFn, requested } = osvBucket();
    const result = await importArchives({ db, fetchFn, now: () => now });

    expect(requested).toEqual(archiveOrder());
    expect(requested.at(-1)).toBe("npm");
    // The same two valid records in every archive; the broken entry is skipped each time.
    expect(await db.$count(vulns)).toBe(2);
    expect(await db.$count(vulnPackages)).toBe(2);
    expect(result.skipped).toBe(archiveOrder().length);
    expect(await importComplete(db)).toBe(true);

    const osv = await loadSyncState(db, "osv");
    expect(osv?.cursor).toBe("2026-10-27T12:00:00.000000000Z\t/");
    // Downloads are deleted once imported.
    const folder = path.join(downloads, "downloads");
    expect(existsSync(folder) ? readdirSync(folder) : []).toEqual([]);
  });

  it("resumes after a failure without downloading finished ecosystems again", async () => {
    const first = osvBucket(new Set(["Maven"]));
    await expect(importArchives({ db, fetchFn: first.fetchFn, now: () => now })).rejects.toThrow(/HTTP 503/);
    expect(await importComplete(db)).toBe(false);
    expect(await loadSyncState(db, "osv")).toBeNull();

    const second = osvBucket();
    await importArchives({ db, fetchFn: second.fetchFn, now: () => now });
    expect(second.requested).not.toContain("PyPI");
    expect(second.requested).toContain("Maven");
    expect(await importComplete(db)).toBe(true);
  });

  it("never moves an earlier cursor forward", async () => {
    await db.insert(syncState).values({ source: "osv", cursor: "2026-10-01T00:00:00.000000000Z\t/", lastRunAt: now });
    await importArchives({ db, fetchFn: osvBucket().fetchFn, now: () => now });
    expect((await loadSyncState(db, "osv"))?.cursor).toBe("2026-10-01T00:00:00.000000000Z\t/");
  });
});

describe("matchLocally", () => {
  it("matches imported advisories by range and version list, with registry name rules", async () => {
    await importArchives({ db, fetchFn: osvBucket().fetchFn, now: () => now });
    const { found } = await matchLocally(db, [
      { ecosystem: "PyPI", name: "Example_Pkg", version: "1.1.9" },
      { ecosystem: "PyPI", name: "example-pkg", version: "1.2.0" },
      { ecosystem: "PyPI", name: "other.pkg", version: "2.0" },
      { ecosystem: "npm", name: "example-pkg", version: "1.0.0" },
    ]);
    expect(found.map((f) => `${f.item.name}@${f.item.version} ${f.vulnId}`)).toEqual([
      "Example_Pkg@1.1.9 GHSA-aaaa-bbbb-cccc",
      "other.pkg@2.0 PYSEC-2026-1",
    ]);
  });
});
