import { readFileSync } from "node:fs";
import { sql } from "drizzle-orm";
import { Pool } from "pg";
import { afterAll, beforeEach, describe, expect, inject, it } from "vitest";
import { createDb } from "@/db";
import { kev, stacks, vulnPackages, vulns, workspaces } from "@/db/schema";
import { OSV_BUCKET } from "@/osv/sync";
import { checkPackages, formatText } from "./check";
import { OSV_QUERYBATCH_URL } from "./osv-query";
import type { StackItem } from "./validate";

const pool = new Pool({ connectionString: inject("databaseUrl") });
const db = createDb(pool);
const record = readFileSync("fixtures/osv/GHSA-558c-9hv2-4prj.json", "utf8");

const fetchFn = (async (input: RequestInfo | URL, init?: RequestInit) => {
  const url = String(input);
  if (url === OSV_QUERYBATCH_URL) {
    const body = JSON.parse(String(init?.body));
    return Response.json({
      results: body.queries.map((q: { package: { name: string }; version: string }) =>
        q.package.name === "virtualenv" && q.version.startsWith("20.")
          ? { vulns: [{ id: "GHSA-558c-9hv2-4prj", modified: "2026-10-22T17:15:04Z" }] }
          : {},
      ),
    });
  }
  if (url === `${OSV_BUCKET}/PyPI/GHSA-558c-9hv2-4prj.json`) return new Response(record);
  return new Response("not found", { status: 404 });
}) as typeof fetch;

const items: StackItem[] = [
  { ecosystem: "PyPI", name: "virtualenv", version: "20.26.0" },
  { ecosystem: "npm", name: "react", version: "19.2.0" },
];

beforeEach(async () => {
  await db.execute(sql`truncate ${workspaces}, ${vulns}, ${vulnPackages}, ${kev} cascade`);
});

afterAll(async () => {
  await pool.end();
});

describe("checkPackages", () => {
  it("returns structured results and stores nothing", async () => {
    const results = await checkPackages(db, items, fetchFn);
    expect(results).toEqual([
      expect.objectContaining({
        id: "GHSA-558c-9hv2-4prj",
        aliases: ["CVE-2026-113721"],
        severity: "medium",
        package: "virtualenv",
        version: "20.26.0",
        fixed_versions: ["21.14.9"],
        known_exploited: false,
      }),
    ]);
    // The advisory was fetched into memory only; no stack, workspace or record was written.
    expect(await db.$count(vulns)).toBe(0);
    expect(await db.$count(stacks)).toBe(0);
    expect(await db.$count(workspaces)).toBe(0);
  });

  it("formats a plain-text summary for cron jobs", async () => {
    const text = formatText(2, await checkPackages(db, items, fetchFn), []);
    expect(text).toMatch(/^1 known vulnerability in 2 packages checked\.\n/);
    expect(text).toContain("MEDIUM   PyPI/virtualenv@20.26.0  GHSA-558c-9hv2-4prj  fixed in 21.14.9");
    expect(formatText(1, [], [])).toBe("No known vulnerabilities in 1 package checked.\n");
  });

  it("marks results whose CVE is in CISA's exploited catalog", async () => {
    await db.insert(kev).values({
      cveId: "CVE-2026-113721",
      vendor: "pypa",
      product: "virtualenv",
      name: "virtualenv link following",
      description: "d",
      requiredAction: "a",
      dateAdded: new Date("2026-10-23T00:00:00Z"),
    });
    const [result] = await checkPackages(db, items, fetchFn);
    expect(result.known_exploited).toBe(true);
    expect(formatText(2, [result], [])).toContain("EXPLOITED (CISA KEV)");
  });
});
