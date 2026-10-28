// Compares offline matching with OSV's API, before a release:
//
//   WATCHPOST_MODE=local WATCHPOST_DATA_DIR=<data folder> pnpm exec tsx scripts/parity.mts [per-ecosystem]
//
// Needs a local data folder with the full history imported, and the local app
// stopped (PGlite allows one process per folder). Test packages and versions
// come from the advisories themselves (each range's boundary versions), so no
// real dependency list is sent anywhere.

import { mkdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { getDb } from "@/db";
import { matchLocally } from "@/match/local";
import { normalizeName } from "@/match/names";
import { OSV_BUCKET } from "@/osv/sync";
import { queryOsv } from "@/stacks/osv-query";
import { STACK_ECOSYSTEMS, type StackEcosystem, type StackItem } from "@/stacks/validate";
import { readZip } from "@/local/zip";
import { dataDir } from "@/local/mode";

const perEcosystem = Number(process.argv[2] ?? 150);
const SKIP = new Set<string>(["GitHub Actions", "SwiftURL"]);

type Affected = { package?: { ecosystem?: string; name?: string }; ranges?: { type?: string; events?: Record<string, string>[] }[]; versions?: string[] };

async function sample(ecosystem: StackEcosystem): Promise<StackItem[]> {
  const folder = path.join(dataDir(), "parity");
  await mkdir(folder, { recursive: true });
  const file = path.join(folder, "archive.zip");
  const res = await fetch(`${OSV_BUCKET}/${encodeURIComponent(ecosystem)}/all.zip`);
  await writeFile(file, Buffer.from(await res.arrayBuffer()));

  const items = new Map<string, StackItem>();
  let seen = 0;
  for await (const { name, data } of readZip(file, { maxEntryBytes: 2_000_000 })) {
    // Malicious-package reports affect every version; they say little about comparators.
    if (!data || name.startsWith("MAL-")) continue;
    // Spread the sample across the archive.
    if (seen++ % 7 !== 0) continue;
    const record = JSON.parse(data.toString("utf8")) as { affected?: Affected[] };
    for (const affected of record.affected ?? []) {
      const pkg = affected.package;
      if (!pkg?.name || pkg.ecosystem?.split(":")[0] !== ecosystem) continue;
      const versions = new Set<string>();
      for (const range of affected.ranges ?? []) {
        if (range.type === "GIT") continue;
        for (const event of range.events ?? []) {
          for (const v of Object.values(event)) if (v && v !== "0") versions.add(v);
        }
      }
      for (const v of (affected.versions ?? []).slice(0, 2)) versions.add(v);
      for (const version of versions) {
        if (version.length > 100) continue;
        items.set(`${pkg.name}@${version}`, { ecosystem, name: pkg.name, version });
      }
    }
    if (items.size >= perEcosystem) break;
  }
  await rm(folder, { recursive: true, force: true });
  return [...items.values()].slice(0, perEcosystem);
}

const key = (item: StackItem) => `${item.ecosystem}/${normalizeName(item.ecosystem, item.name)}@${item.version}`;

let total = 0;
let mismatches = 0;
for (const ecosystem of STACK_ECOSYSTEMS) {
  if (SKIP.has(ecosystem)) continue;
  const items = await sample(ecosystem);
  const [local, remote] = await Promise.all([matchLocally(getDb(), items), queryOsv(fetch, items)]);

  const localIds = new Map<string, Set<string>>();
  for (const f of local.found) localIds.set(key(f.item), (localIds.get(key(f.item)) ?? new Set()).add(f.vulnId));
  const remoteIds = new Map<string, Set<string>>();
  for (const f of remote) remoteIds.set(key(f.item), (remoteIds.get(key(f.item)) ?? new Set()).add(f.vulnId));

  const missing: string[] = [];
  const extra: string[] = [];
  for (const item of items) {
    const l = localIds.get(key(item)) ?? new Set();
    const r = remoteIds.get(key(item)) ?? new Set();
    for (const id of r) if (!l.has(id)) missing.push(`missing ${id} for ${key(item)}`);
    for (const id of l) if (!r.has(id)) extra.push(`extra ${id} for ${key(item)}`);
  }
  const pairs = remote.length;
  total += pairs;
  mismatches += missing.length + extra.length;
  console.log(
    `${ecosystem.padEnd(10)} ${items.length} versions, ${pairs} OSV matches, ${missing.length} missing, ${extra.length} extra, ${local.unknown} unreadable`,
  );
  for (const line of [...missing, ...extra].slice(0, 8)) console.log(`  ${line}`);
}
console.log(`\n${mismatches} differences across ${total} OSV matches`);
process.exit(0);
