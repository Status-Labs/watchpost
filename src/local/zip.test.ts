import { describe, expect, it } from "vitest";
import { readZip } from "./zip";

const FIXTURE = "fixtures/osv-archive/all.zip";

async function entries(maxEntryBytes = 1_000_000) {
  const out: { name: string; text: string | null }[] = [];
  for await (const { name, data } of readZip(FIXTURE, { maxEntryBytes })) out.push({ name, text: data?.toString("utf8") ?? null });
  return out;
}

describe("readZip", () => {
  it("reads deflated and stored entries from a ZIP64 archive", async () => {
    const found = await entries();
    expect(found.map((e) => e.name)).toEqual(["GHSA-aaaa-bbbb-cccc.json", "PYSEC-2026-1.json", "broken.json"]);
    expect(JSON.parse(found[0].text!).id).toBe("GHSA-aaaa-bbbb-cccc");
    expect(JSON.parse(found[1].text!).id).toBe("PYSEC-2026-1");
    expect(found[2].text).toBe("{ not json");
  });

  it("skips entries over the size cap", async () => {
    const found = await entries(20);
    expect(found.every((e) => e.text === null || e.text.length <= 20)).toBe(true);
    expect(found[0].text).toBeNull();
  });

  it("rejects files that aren't zip archives", async () => {
    await expect(async () => {
      for await (const entry of readZip("package.json", { maxEntryBytes: 1_000 })) void entry;
    }).rejects.toThrow(/zip/);
  });
});
