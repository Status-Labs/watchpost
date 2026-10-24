import { describe, expect, it } from "vitest";
import { cursorKey, nextBatch, normalizeTimestamp, parseLine, readChangesSince, type ChangedEntry } from "./sync";

function entry(modified: string, id: string): ChangedEntry {
  return { modified: normalizeTimestamp(modified), ecosystem: "npm", id };
}

describe("normalizeTimestamp", () => {
  it("pads fractions so string order matches time order", () => {
    const short = normalizeTimestamp("2026-10-23T02:45:05.1Z");
    const long = normalizeTimestamp("2026-10-23T02:45:05.12Z");
    expect(short).toBe("2026-10-23T02:45:05.100000000Z");
    expect(short < long).toBe(true);
    expect(normalizeTimestamp("2026-10-23T02:45:05Z")).toBe("2026-10-23T02:45:05.000000000Z");
  });

  it("rejects anything else", () => {
    expect(normalizeTimestamp("yesterday")).toBe("");
  });
});

describe("parseLine", () => {
  it("splits timestamp, ecosystem and ID, including ecosystems with spaces", () => {
    expect(parseLine("2026-10-23T13:00:05.43Z,GitHub Actions/GHSA-abcd-efgh-ijkl")).toEqual({
      modified: "2026-10-23T13:00:05.430000000Z",
      ecosystem: "GitHub Actions",
      id: "GHSA-abcd-efgh-ijkl",
    });
  });

  it("ignores malformed lines", () => {
    expect(parseLine("")).toBeNull();
    expect(parseLine("not,a line")).toBeNull();
  });
});

describe("nextBatch", () => {
  const changes = [
    entry("2026-10-23T00:00:04Z", "E"),
    entry("2026-10-23T00:00:02Z", "C"),
    entry("2026-10-23T00:00:02Z", "B"),
    entry("2026-10-23T00:00:01Z", "A"),
  ];

  it("takes the oldest entries first, in a fixed order", () => {
    expect(nextBatch(changes, 10).map((e) => e.id)).toEqual(["A", "B", "C", "E"]);
  });

  it("caps the batch even inside a group sharing one timestamp", () => {
    expect(nextBatch(changes, 2).map((e) => e.id)).toEqual(["A", "B"]);
  });
});

describe("readChangesSince", () => {
  it("streams lines newest first, stops at the cursor and keeps synced ecosystems", async () => {
    const csv = [
      "2026-10-23T00:00:05Z,npm/NEW-2",
      "2026-10-23T00:00:04Z,Debian/DEBIAN-1",
      "2026-10-23T00:00:03Z,PyPI/NEW-1",
      "2026-10-23T00:00:02Z,npm/OLD-1",
      "2026-10-23T00:00:01Z,npm/OLD-2",
    ].join("\n");
    // Split mid-line to check lines that span chunks.
    const chunks = [csv.slice(0, 20), csv.slice(20, 61), csv.slice(61)];
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        for (const chunk of chunks) controller.enqueue(new TextEncoder().encode(chunk));
        controller.close();
      },
    });
    const fakeFetch = (async () => new Response(body)) as unknown as typeof fetch;

    const cursor = cursorKey({ modified: normalizeTimestamp("2026-10-23T00:00:02Z"), ecosystem: "", id: "" });
    const changes = await readChangesSince(fakeFetch, cursor);
    // OLD-1 shares the cursor's timestamp but sorts after it, so it's still new.
    expect(changes.map((c) => c.id)).toEqual(["NEW-2", "NEW-1", "OLD-1"]);
  });
});
