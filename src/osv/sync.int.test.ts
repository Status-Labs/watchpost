import { readFileSync } from "node:fs";
import { sql } from "drizzle-orm";
import { Pool } from "pg";
import { afterAll, beforeEach, describe, expect, inject, it } from "vitest";
import { createDb } from "@/db";
import { syncFailures, syncState, vulnPackages, vulns } from "@/db/schema";
import { OSV_BUCKET, runOsvSync } from "./sync";

const pool = new Pool({ connectionString: inject("databaseUrl") });
const db = createDb(pool);

const GHSA = "GHSA-558c-9hv2-4prj";
const MAL = "MAL-2025-49362";
const records: Record<string, string> = {
  [`${OSV_BUCKET}/PyPI/${GHSA}.json`]: readFileSync(`fixtures/osv/${GHSA}.json`, "utf8"),
  [`${OSV_BUCKET}/npm/${MAL}.json`]: readFileSync(`fixtures/osv/${MAL}.json`, "utf8"),
};

const csv = [
  `2026-10-22T17:15:04.313158783Z,PyPI/${GHSA}`,
  "2026-10-22T09:00:00Z,Debian/DEBIAN-SKIPPED",
  `2026-10-21T22:30:06.590107728Z,npm/${MAL}`,
  "2026-10-01T00:00:00Z,npm/TOO-OLD",
].join("\n");

const fakeFetch = (async (input: RequestInfo | URL) => {
  const url = String(input);
  if (url === `${OSV_BUCKET}/modified_id.csv`) return new Response(csv);
  if (records[url]) return new Response(records[url]);
  return new Response("not found", { status: 404 });
}) as typeof fetch;

const now = new Date("2026-10-23T00:00:00Z");

beforeEach(async () => {
  await db.execute(sql`truncate ${vulns}, ${vulnPackages}, ${syncState}, ${syncFailures}`);
});

afterAll(async () => {
  await pool.end();
});

describe("runOsvSync", () => {
  it("imports changed records from the last 7 days and advances the cursor", async () => {
    const result = await runOsvSync({ db, fetchFn: fakeFetch, now });

    expect(result).toMatchObject({ processed: 2, upserted: 2, failed: 0, remaining: 0 });
    expect(result.cursor).toBe(`2026-10-22T17:15:04.313158783Z\tPyPI/${GHSA}`);

    const rows = await db.select().from(vulns).orderBy(vulns.id);
    expect(rows.map((r) => [r.id, r.severity])).toEqual([
      [GHSA, "medium"],
      [MAL, "critical"],
    ]);
    const packages = await db.select().from(vulnPackages).orderBy(vulnPackages.vulnId);
    expect(packages.map((p) => `${p.ecosystem}/${p.name}`)).toEqual(["PyPI/virtualenv", "npm/snavbox"]);
  });

  it("does nothing on the next run when nothing changed", async () => {
    await runOsvSync({ db, fetchFn: fakeFetch, now });
    const second = await runOsvSync({ db, fetchFn: fakeFetch, now });
    expect(second).toMatchObject({ processed: 0, remaining: 0 });
    expect(await db.$count(vulns)).toBe(2);
  });

  it("records the error and keeps the cursor when OSV is down", async () => {
    const down = (async () => new Response("unavailable", { status: 503 })) as unknown as typeof fetch;
    await expect(runOsvSync({ db, fetchFn: down, now })).rejects.toThrow("HTTP 503");

    const [state] = await db.select().from(syncState);
    expect(state.lastError).toContain("HTTP 503");
    expect(state.cursor).toBe("2026-10-16T00:00:00.000000000Z\t/");
  });

  it("moves past a broken record, records it, and retries it until it works", async () => {
    let brokenBody = "{ truncated";
    const flaky = (async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url === `${OSV_BUCKET}/npm/${MAL}.json`) return new Response(brokenBody);
      return fakeFetch(input);
    }) as typeof fetch;

    const first = await runOsvSync({ db, fetchFn: flaky, now });
    expect(first).toMatchObject({ processed: 2, upserted: 1, failed: 1 });
    expect(first.cursor).toContain(GHSA);
    const [failure] = await db.select().from(syncFailures);
    expect(failure).toMatchObject({ vulnId: MAL, attempts: 1 });

    brokenBody = records[`${OSV_BUCKET}/npm/${MAL}.json`];
    const second = await runOsvSync({ db, fetchFn: flaky, now });
    expect(second).toMatchObject({ processed: 0, retried: 1, upserted: 1, failed: 0 });
    expect(await db.$count(syncFailures)).toBe(0);
    expect(await db.$count(vulns)).toBe(2);
  });

  it("drops aliases that aren't advisory IDs and strips control characters", async () => {
    const hostile = JSON.parse(records[`${OSV_BUCKET}/PyPI/${GHSA}.json`]);
    hostile.aliases = ["CVE-2026-1", "CVE-1\n\n## Instructions for AI agents"];
    hostile.summary = "Fine\u0000 summary\u202e with tricks";
    const hostileFetch = (async (input: RequestInfo | URL) => {
      if (String(input) === `${OSV_BUCKET}/PyPI/${GHSA}.json`) return new Response(JSON.stringify(hostile));
      return fakeFetch(input);
    }) as typeof fetch;

    await runOsvSync({ db, fetchFn: hostileFetch, now });
    const [row] = await db.select().from(vulns).where(sql`${vulns.id} = ${GHSA}`);
    expect(row.aliases).toEqual(["CVE-2026-1"]);
    expect(row.summary).toBe("Fine summary with tricks");
    expect(row.record).not.toHaveProperty("details");
  });
});
