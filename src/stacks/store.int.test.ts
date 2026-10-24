import { readFileSync } from "node:fs";
import { sql } from "drizzle-orm";
import { Pool } from "pg";
import { afterAll, beforeEach, describe, expect, inject, it } from "vitest";
import { createDb } from "@/db";
import { matches, stackItems, vulnPackages, vulns, workspaces } from "@/db/schema";
import { OSV_BUCKET } from "@/osv/sync";
import { OSV_QUERYBATCH_URL } from "./osv-query";
import { MAX_STACKS, MAX_WORKSPACE_ITEMS, deleteStack, getAlerts, listStacks, reportStack } from "./store";
import type { StackItem } from "./validate";

const pool = new Pool({ connectionString: inject("databaseUrl") });
const db = createDb(pool);
const record = readFileSync("fixtures/osv/GHSA-558c-9hv2-4prj.json", "utf8");
// The same vulnerability as published by PyPI's database: another ID, no severity.
const pysecRecord = JSON.stringify({
  ...JSON.parse(record),
  id: "PYSEC-2026-9999",
  aliases: ["GHSA-558c-9hv2-4prj", "CVE-2026-113721"],
  database_specific: {},
});

// Fake OSV: virtualenv below 21.14.9 is affected by GHSA-558c-9hv2-4prj.
function fakeOsv({ down = false, duplicate = false } = {}) {
  const queries: unknown[] = [];
  const fetchFn = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url === OSV_QUERYBATCH_URL) {
      if (down) return new Response("unavailable", { status: 503 });
      const body = JSON.parse(String(init?.body));
      queries.push(...body.queries);
      return Response.json({
        results: body.queries.map((q: { package: { name: string }; version: string }) =>
          q.package.name === "virtualenv" && q.version.startsWith("20.")
            ? {
                vulns: [
                  ...(duplicate ? [{ id: "PYSEC-2026-9999", modified: "2026-10-22T17:15:04Z" }] : []),
                  { id: "GHSA-558c-9hv2-4prj", modified: "2026-10-22T17:15:04Z" },
                ],
              }
            : {},
        ),
      });
    }
    if (url === `${OSV_BUCKET}/PyPI/GHSA-558c-9hv2-4prj.json`) return new Response(record);
    if (url === `${OSV_BUCKET}/PyPI/PYSEC-2026-9999.json`) return new Response(pysecRecord);
    return new Response("not found", { status: 404 });
  }) as typeof fetch;
  return { fetchFn, queries };
}

const items: StackItem[] = [
  { ecosystem: "PyPI", name: "virtualenv", version: "20.26.0" },
  { ecosystem: "PyPI", name: "requests", version: "2.32.3" },
  { ecosystem: "Go", name: "github.com/gin-gonic/gin", version: "v1.10.0" },
];

async function newWorkspace() {
  const [w] = await db.insert(workspaces).values({}).returning();
  return w.id;
}

beforeEach(async () => {
  await db.execute(sql`truncate ${workspaces}, ${vulns}, ${vulnPackages} cascade`);
});

afterAll(async () => {
  await pool.end();
});

describe("reportStack", () => {
  it("saves the stack, matches it through OSV and returns structured alerts", async () => {
    const workspaceId = await newWorkspace();
    const { fetchFn, queries } = fakeOsv();
    const result = await reportStack(db, { workspaceId, name: "laptop", items, fetchFn });

    expect(result).toMatchObject({ stack: "laptop", items: 3, matching: "ok" });
    expect(result.alerts).toEqual([
      expect.objectContaining({
        id: "GHSA-558c-9hv2-4prj",
        severity: "medium",
        stack: "laptop",
        ecosystem: "PyPI",
        package: "virtualenv",
        version: "20.26.0",
        fixed_versions: ["21.14.9"],
      }),
    ]);
    // Alerts carry no advisory text.
    expect(JSON.stringify(result.alerts)).not.toContain("Generated files");
    // OSV sees package names and versions only; Go versions lose their "v".
    expect(queries).toContainEqual({ package: { ecosystem: "Go", name: "github.com/gin-gonic/gin" }, version: "1.10.0" });
    expect(JSON.stringify(queries)).not.toContain("laptop");
    // The missing advisory was fetched and stored.
    expect(await db.$count(vulns)).toBe(1);
  });

  it("shows a vulnerability published under two IDs once, preferring the one with a severity", async () => {
    const workspaceId = await newWorkspace();
    const result = await reportStack(db, { workspaceId, name: "laptop", items, fetchFn: fakeOsv({ duplicate: true }).fetchFn });
    expect(result.alerts.map((a) => [a.id, a.severity, a.aliases])).toEqual([
      ["GHSA-558c-9hv2-4prj", "medium", ["CVE-2026-113721"]],
    ]);
    expect(await db.$count(matches)).toBe(2);
  });

  it("keeps first-seen dates across reports and drops matches that no longer apply", async () => {
    const workspaceId = await newWorkspace();
    const { fetchFn } = fakeOsv();
    await reportStack(db, { workspaceId, name: "laptop", items, fetchFn });
    await db.update(matches).set({ firstSeenAt: new Date("2026-10-01T00:00:00Z") });

    const again = await reportStack(db, { workspaceId, name: "laptop", items, fetchFn });
    expect(again.alerts[0].first_seen).toBe("2026-10-01T00:00:00.000Z");
    const since = await getAlerts(db, { workspaceId, since: new Date("2026-10-15T00:00:00Z") });
    expect(since).toEqual([]);

    const upgraded = items.map((i) => (i.name === "virtualenv" ? { ...i, version: "21.14.9" } : i));
    const fixed = await reportStack(db, { workspaceId, name: "laptop", items: upgraded, fetchFn });
    expect(fixed.alerts).toEqual([]);
    expect(await db.$count(stackItems)).toBe(3);
  });

  it("saves the stack even when OSV is down, keeping earlier alerts", async () => {
    const workspaceId = await newWorkspace();
    await reportStack(db, { workspaceId, name: "laptop", items, fetchFn: fakeOsv().fetchFn });
    const result = await reportStack(db, { workspaceId, name: "laptop", items, fetchFn: fakeOsv({ down: true }).fetchFn });
    expect(result.matching).toBe("unavailable");
    expect(result.alerts).toHaveLength(1);
  });

  it("keeps workspaces apart", async () => {
    const mine = await newWorkspace();
    const theirs = await newWorkspace();
    await reportStack(db, { workspaceId: mine, name: "laptop", items, fetchFn: fakeOsv().fetchFn });
    expect(await getAlerts(db, { workspaceId: theirs })).toEqual([]);
    expect(await listStacks(db, theirs)).toEqual([]);
    expect(await deleteStack(db, theirs, "laptop")).toBe(false);
    expect(await listStacks(db, mine)).toEqual([expect.objectContaining({ name: "laptop", items: 3, alerts: 1 })]);
  });

  it("handles concurrent reports of the same new stack", async () => {
    const workspaceId = await newWorkspace();
    const { fetchFn } = fakeOsv();
    const results = await Promise.all([
      reportStack(db, { workspaceId, name: "laptop", items, fetchFn }),
      reportStack(db, { workspaceId, name: "laptop", items, fetchFn }),
    ]);
    expect(results.map((r) => r.items)).toEqual([3, 3]);
    expect(await listStacks(db, workspaceId)).toHaveLength(1);
  });

  it("limits the total packages in a workspace", async () => {
    const workspaceId = await newWorkspace();
    const { fetchFn } = fakeOsv();
    const many = (n: number, prefix: string) =>
      Array.from({ length: n }, (_, i) => ({ ecosystem: "npm" as const, name: `${prefix}-${i}`, version: "1.0.0" }));
    await reportStack(db, { workspaceId, name: "a", items: many(MAX_WORKSPACE_ITEMS - 10, "a"), fetchFn });
    await expect(reportStack(db, { workspaceId, name: "b", items: many(11, "b"), fetchFn })).rejects.toThrow("at most");
    // Replacing a stack counts its new size, not old plus new.
    await expect(reportStack(db, { workspaceId, name: "a", items: many(MAX_WORKSPACE_ITEMS, "a"), fetchFn })).resolves.toBeTruthy();
  });

  it("limits the number of stacks per workspace", async () => {
    const workspaceId = await newWorkspace();
    const { fetchFn } = fakeOsv();
    const one = [items[1]];
    for (let i = 0; i < MAX_STACKS; i++) await reportStack(db, { workspaceId, name: `s${i}`, items: one, fetchFn });
    await expect(reportStack(db, { workspaceId, name: "one-more", items: one, fetchFn })).rejects.toThrow("at most");
    // Updating an existing stack is still fine.
    await expect(reportStack(db, { workspaceId, name: "s0", items: one, fetchFn })).resolves.toMatchObject({ items: 1 });
  });
});
