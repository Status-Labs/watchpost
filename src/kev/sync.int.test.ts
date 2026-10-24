import { readFileSync } from "node:fs";
import { sql } from "drizzle-orm";
import { Pool } from "pg";
import { afterAll, beforeEach, describe, expect, inject, it } from "vitest";
import { createDb } from "@/db";
import { kev, syncState, vulnPackages, vulns } from "@/db/schema";
import { getVuln, listVulns } from "@/lib/vulns";
import { osvRecordSchema } from "@/osv/record";
import { upsertRecords } from "@/osv/sync";
import { KEV_URL, parseCatalog, runKevSync } from "./sync";

// listVulns and getVuln use the app's own connection; point it at the test database.
process.env.DATABASE_URL = inject("databaseUrl");
const pool = new Pool({ connectionString: inject("databaseUrl") });
const db = createDb(pool);

const catalog = readFileSync("fixtures/kev/known_exploited_vulnerabilities.json", "utf8");
const LAST_MODIFIED = "Fri, 23 Oct 2026 17:00:09 GMT";
const CVE = "CVE-2026-113721";
const now = new Date("2026-10-23T18:00:00Z");

// Serves the catalog, honoring If-Modified-Since like CISA's server does.
const cisa = (async (input: RequestInfo | URL, init?: RequestInit) => {
  if (String(input) !== KEV_URL) return new Response("not found", { status: 404 });
  const since = new Headers(init?.headers).get("if-modified-since");
  if (since === LAST_MODIFIED) return new Response(null, { status: 304 });
  return new Response(catalog, { headers: { "last-modified": LAST_MODIFIED } });
}) as typeof fetch;

const loadRecord = (id: string) => osvRecordSchema.parse(JSON.parse(readFileSync(`fixtures/osv/${id}.json`, "utf8")));

beforeEach(async () => {
  await db.execute(sql`truncate ${kev}, ${syncState}, ${vulns}, ${vulnPackages}`);
});

afterAll(async () => {
  await pool.end();
});

describe("runKevSync", () => {
  it("stores the catalog, then skips the download when nothing changed", async () => {
    const first = await runKevSync({ db, fetchFn: cisa, now });
    expect(first).toEqual({ changed: true, entries: 601, skipped: 0 });

    const [entry] = await db.select().from(kev).where(sql`${kev.cveId} = ${CVE}`);
    expect(entry).toMatchObject({ vendor: "pypa", ransomware: true });
    expect(entry.dueDate?.toISOString()).toBe("2026-11-13T00:00:00.000Z");

    const second = await runKevSync({ db, fetchFn: cisa, now });
    expect(second.changed).toBe(false);
    expect(await db.$count(kev)).toBe(601);
  });

  it("keeps the current catalog if a new file looks truncated", async () => {
    await runKevSync({ db, fetchFn: cisa, now });
    const truncated = JSON.parse(catalog);
    truncated.vulnerabilities = truncated.vulnerabilities.slice(0, 10);
    const broken = (async () => new Response(JSON.stringify(truncated))) as unknown as typeof fetch;
    await db.execute(sql`update ${syncState} set cursor = '' where source = 'kev'`);

    await expect(runKevSync({ db, fetchFn: broken, now })).rejects.toThrow("keeping the current catalog");
    expect(await db.$count(kev)).toBe(601);
  });
});

describe("listVulnIdsForSitemap", () => {
  it("lists advisories and CISA entries without one, with dates", async () => {
    await runKevSync({ db, fetchFn: cisa, now });
    await upsertRecords(db, [loadRecord("GHSA-558c-9hv2-4prj")]);
    const { countVulns, listVulnIdsForSitemap } = await import("@/lib/vulns");
    expect(await countVulns()).toBe(601);
    const [first] = await listVulnIdsForSitemap(0, 1);
    expect(first).toEqual({ id: "CVE-2025-90000", modified: new Date("2026-01-01T00:00:00Z") });
  });
});

describe("parseCatalog", () => {
  it("skips malformed entries without failing the whole file", () => {
    const json = JSON.parse(catalog);
    json.vulnerabilities.push({ cveID: "not-a-cve", vendorProject: "x" });
    const { rows, skipped } = parseCatalog(json);
    expect(rows).toHaveLength(601);
    expect(skipped).toBe(1);
  });
});

describe("listVulns with the KEV catalog", () => {
  beforeEach(async () => {
    await runKevSync({ db, fetchFn: cisa, now });
    await upsertRecords(db, [loadRecord("GHSA-558c-9hv2-4prj"), loadRecord("MAL-2025-49362")]);
  });

  it("shows an advisory whose CVE is in the catalog once, marked exploited", async () => {
    const exploited = await listVulns({ kind: "exploited" }, { limit: 1000 });
    expect(exploited).toHaveLength(601);
    expect(exploited.filter((v) => v.id === CVE)).toHaveLength(0);
    const advisory = exploited.find((v) => v.id === "GHSA-558c-9hv2-4prj");
    expect(advisory).toMatchObject({ exploited: true, ransomware: true, product: null });

    const vuln = await getVuln("GHSA-558c-9hv2-4prj");
    expect(vuln?.exploits.map((e) => e.cveId)).toEqual([CVE]);
  });

  it("lists CISA entries alongside advisories, but not under package or severity filters", async () => {
    const everything = await listVulns({ kind: "advisories" }, { limit: 1000 });
    expect(everything).toHaveLength(601);
    const windows = everything.find((v) => v.id === "CVE-2025-90000");
    expect(windows?.product).toEqual({ vendor: "Microsoft", product: "Windows" });
    expect(windows?.published).toEqual(new Date("2026-01-01T00:00:00Z"));
    expect(everything.find((v) => v.id === "GHSA-558c-9hv2-4prj")?.published).toEqual(new Date("2026-10-22T17:03:12Z"));

    expect(await listVulns({ kind: "packages" })).toHaveLength(1);
    expect((await listVulns({ kind: "advisories", ecosystems: ["PyPI"] })).map((v) => v.id)).toEqual(["GHSA-558c-9hv2-4prj"]);
    expect((await listVulns({ kind: "advisories", severities: ["medium"] })).map((v) => v.id)).toEqual(["GHSA-558c-9hv2-4prj"]);
    expect((await listVulns({ kind: "malware" })).map((v) => v.id)).toEqual(["MAL-2025-49362"]);
  });

  it("filters by category across packages and CISA products", async () => {
    const os = await listVulns({ kind: "advisories", categories: ["os"] }, { limit: 1000 });
    // Cisco IOS XE is a network operating system, so it's in both categories.
    expect(new Set(os.map((v) => v.product?.vendor))).toEqual(new Set(["Microsoft", "Apple", "Cisco"]));

    const databases = await listVulns({ kind: "advisories", categories: ["databases"] }, { limit: 1000 });
    expect(new Set(databases.map((v) => v.product?.product))).toEqual(new Set(["Database Server"]));
  });

  it("searches IDs, CVE aliases, package names and product names", async () => {
    expect((await listVulns({ query: CVE })).map((v) => v.id)).toEqual(["GHSA-558c-9hv2-4prj"]);
    expect((await listVulns({ query: "ghsa-558c-9hv2-4prj" })).map((v) => v.id)).toEqual(["GHSA-558c-9hv2-4prj"]);
    expect((await listVulns({ query: "virtualenv", kind: "packages" })).map((v) => v.id)).toEqual(["GHSA-558c-9hv2-4prj"]);
    expect((await listVulns({ query: "fortios" }, { limit: 1000 })).length).toBe(75);
    // LIKE wildcards in the search box are matched literally.
    expect(await listVulns({ query: "%" })).toHaveLength(0);
  });

  it("ranks exploited entries with high severity when sorting worst first", async () => {
    const [first] = await listVulns({ kind: "all" }, { sort: "severity", limit: 1 });
    expect(first.id).toBe("MAL-2025-49362");
  });
});
