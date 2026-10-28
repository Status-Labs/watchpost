import { and, eq, inArray, isNull, sql } from "drizzle-orm";
import type { Db } from "@/db";
import { vulnPackages, vulns } from "@/db/schema";
import type { StackItem } from "@/stacks/validate";
import { osvVersion, type PackageVuln } from "@/stacks/osv-query";
import { affects } from "./affected";
import { normalizeName } from "./names";

// Offline version of OSV's batch query: finds the advisories affecting each
// package version from the local copy of OSV. Nothing leaves the machine.

const LOOKUP_CHUNK = 500;

// A loose key that's equal whenever the registry names are, so the database can
// narrow the candidates; normalizeName then decides exactly.
const looseKey = (name: string) => name.toLowerCase().replace(/[-_.]+/g, "-");
const looseKeySql = sql`lower(regexp_replace(${vulnPackages.name}, '[-_.]+', '-', 'g'))`;

export async function matchLocally(db: Db, items: StackItem[]): Promise<{ found: PackageVuln[]; unknown: number }> {
  const found: PackageVuln[] = [];
  let unknown = 0;

  const byEcosystem = Map.groupBy(items, (item) => item.ecosystem);
  for (const [ecosystem, group] of byEcosystem) {
    const keys = [...new Set(group.map((item) => looseKey(item.name)))];
    for (let i = 0; i < keys.length; i += LOOKUP_CHUNK) {
      const chunk = new Set(keys.slice(i, i + LOOKUP_CHUNK));
      const candidates = await db
        .selectDistinct({ id: vulns.id, modified: vulns.modified, record: vulns.record, name: vulnPackages.name })
        .from(vulnPackages)
        .innerJoin(vulns, eq(vulns.id, vulnPackages.vulnId))
        .where(
          and(
            eq(vulnPackages.ecosystem, ecosystem),
            inArray(looseKeySql, [...chunk]),
            isNull(vulns.withdrawn),
          ),
        );

      const byName = Map.groupBy(candidates, (c) => normalizeName(ecosystem, c.name));
      for (const item of group) {
        if (!chunk.has(looseKey(item.name))) continue;
        const seen = new Set<string>();
        for (const candidate of byName.get(normalizeName(ecosystem, item.name)) ?? []) {
          if (seen.has(candidate.id)) continue;
          seen.add(candidate.id);
          const verdict = affects(candidate.record, ecosystem, item.name, osvVersion(item));
          if (verdict === "affected") {
            found.push({ item, vulnId: candidate.id, modified: candidate.modified.toISOString() });
          } else if (verdict === "unknown") {
            unknown++;
          }
        }
      }
    }
  }
  return { found, unknown };
}
