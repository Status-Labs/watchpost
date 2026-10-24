import type { Severity } from "@/db/schema";
import { VERSION_SHAPE } from "@/lib/sanitize";

// Shared by stored-stack alerts and stateless checks.

// OSV often has the same vulnerability under several IDs (GHSA-…, GO-…,
// PYSEC-…), each listing the others as aliases. Show it once per package,
// preferring the record with a severity, then the GHSA one.
export function dedupeAliases<T extends { id: string; aliases: string[] | null; severity: Severity | null; stack?: string; ecosystem: string; name: string; version: string }>(
  rows: T[],
): T[] {
  const preference = (row: T) => (row.severity ? 0 : 2) + (row.id.startsWith("GHSA-") ? 0 : 1);
  const kept: T[] = [];
  const seen = new Map<string, Set<string>>();
  for (const row of [...rows].sort((a, b) => preference(a) - preference(b))) {
    const group = `${row.stack ?? ""}\u0000${row.ecosystem}\u0000${row.name}\u0000${row.version}`;
    const ids = seen.get(group) ?? new Set<string>();
    const names = [row.id, ...(row.aliases ?? [])];
    if (names.some((name) => ids.has(name))) continue;
    for (const name of names) ids.add(name);
    seen.set(group, ids);
    kept.push(row);
  }
  // Back to the query's order (worst first, newest first).
  const order = new Map(rows.map((row, i) => [row, i]));
  return kept.sort((a, b) => order.get(a)! - order.get(b)!);
}

// "fixed" versions from the advisory's ranges for this package.
export function fixedVersions(record: unknown, ecosystem: string, name: string): string[] {
  const affected = (record as { affected?: unknown })?.affected;
  if (!Array.isArray(affected)) return [];
  const fixed = new Set<string>();
  for (const entry of affected) {
    const pkg = entry?.package;
    if (!pkg || pkg.name !== name || String(pkg.ecosystem).split(":")[0] !== ecosystem) continue;
    for (const range of Array.isArray(entry.ranges) ? entry.ranges : []) {
      if (range?.type === "GIT") continue;
      for (const event of Array.isArray(range?.events) ? range.events : []) {
        // Upstream values: only version-shaped strings get through.
        if (typeof event?.fixed === "string" && VERSION_SHAPE.test(event.fixed)) fixed.add(event.fixed);
      }
    }
  }
  return [...fixed].slice(0, 10);
}


export const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
