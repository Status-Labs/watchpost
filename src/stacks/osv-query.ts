import { z } from "zod";
import { isVulnId } from "@/lib/sanitize";
import type { StackItem } from "./validate";

// Asks OSV which known vulnerabilities affect each package version. OSV does
// the version matching for every ecosystem, against its full history.
//
// Privacy: this sends package names and versions to OSV (Google) from our
// server. Nothing identifies the workspace or the person: no stack names, no
// IDs, and requests come from our servers, mixed with everyone else's.
export const OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch";

const BATCH_SIZE = 1_000;
const MAX_PAGES = 3;
const TIMEOUT_MS = 30_000;
const MAX_BYTES = 20_000_000;

type Fetch = typeof fetch;

const responseSchema = z.object({
  results: z.array(
    z.object({
      vulns: z.array(z.object({ id: z.string(), modified: z.string().optional() })).optional(),
      next_page_token: z.string().optional(),
    }),
  ),
});

export type PackageVuln = { item: StackItem; vulnId: string; modified: string };

export async function queryOsv(fetchFn: Fetch, items: StackItem[]): Promise<PackageVuln[]> {
  const found: PackageVuln[] = [];
  for (let i = 0; i < items.length; i += BATCH_SIZE) {
    let pending = items.slice(i, i + BATCH_SIZE).map((item) => ({ item, pageToken: undefined as string | undefined }));
    for (let page = 0; page < MAX_PAGES && pending.length > 0; page++) {
      const results = await postBatch(fetchFn, pending);
      const next: typeof pending = [];
      results.forEach((result, index) => {
        const { item } = pending[index];
        // IDs are stored and returned to assistants, so they must look like advisory IDs.
        for (const vuln of (result.vulns ?? []).filter((v) => isVulnId(v.id))) found.push({ item, vulnId: vuln.id, modified: vuln.modified ?? "" });
        if (result.next_page_token) next.push({ item, pageToken: result.next_page_token });
      });
      pending = next;
    }
  }
  return found;
}

async function postBatch(fetchFn: Fetch, queries: { item: StackItem; pageToken?: string }[]) {
  const res = await fetchFn(OSV_QUERYBATCH_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      queries: queries.map(({ item, pageToken }) => ({
        package: { ecosystem: item.ecosystem, name: item.name },
        version: osvVersion(item),
        ...(pageToken ? { page_token: pageToken } : {}),
      })),
    }),
    cache: "no-store",
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`OSV querybatch: HTTP ${res.status}`);
  const text = await res.text();
  if (text.length > MAX_BYTES) throw new Error("OSV querybatch: response too large");
  const { results } = responseSchema.parse(JSON.parse(text));
  if (results.length !== queries.length) throw new Error("OSV querybatch: result count mismatch");
  return results;
}

// OSV's Go versions have no "v" prefix; go.mod has one.
function osvVersion(item: StackItem): string {
  return item.ecosystem === "Go" ? item.version.replace(/^v(?=\d)/, "") : item.version;
}
