import { baseEcosystem, normalizeName } from "./names";
import { parseVersion, type Version } from "./versions";

// Decides whether an OSV record affects one package version, following the
// OSV schema's evaluation rules: https://ossf.github.io/osv-schema/#evaluation
//
// "unknown" means a range couldn't be read (a version our comparators can't
// parse). Callers treat it as not affected, and count it.

type Event = { introduced?: unknown; fixed?: unknown; last_affected?: unknown };
type Range = { type?: unknown; events?: unknown };
type Affected = { package?: { ecosystem?: unknown; name?: unknown }; ranges?: unknown; versions?: unknown };

export type Verdict = "affected" | "not-affected" | "unknown";

export function affects(record: unknown, ecosystem: string, name: string, version: string): Verdict {
  const entries = (record as { affected?: unknown } | null)?.affected;
  if (!Array.isArray(entries)) return "not-affected";
  const wanted = normalizeName(ecosystem, name);
  const parsed = parseVersion(ecosystem, version);
  let unknown = false;

  for (const entry of entries as Affected[]) {
    const pkg = entry?.package;
    if (typeof pkg?.ecosystem !== "string" || typeof pkg.name !== "string") continue;
    if (baseEcosystem(pkg.ecosystem) !== ecosystem || normalizeName(ecosystem, pkg.name) !== wanted) continue;

    if (Array.isArray(entry.versions) && listed(entry.versions, version, parsed, ecosystem)) return "affected";

    for (const range of Array.isArray(entry.ranges) ? (entry.ranges as Range[]) : []) {
      if (range?.type !== "SEMVER" && range?.type !== "ECOSYSTEM") continue;
      const result = parsed ? inRange(range, parsed, ecosystem) : "unknown";
      if (result === "affected") return "affected";
      if (result === "unknown") unknown = true;
    }
  }
  return unknown ? "unknown" : "not-affected";
}

function listed(versions: unknown[], version: string, parsed: Version | null, ecosystem: string): boolean {
  for (const v of versions) {
    if (typeof v !== "string") continue;
    if (v === version) return true;
    // "1.0" and "1.0.0" are the same PyPI version, for example.
    const other = parsed && parseVersion(ecosystem, v);
    if (other && parsed.compare(other) === 0) return true;
  }
  return false;
}

type Point = { kind: "introduced" | "fixed" | "last_affected"; at: Version | null };

// The version is affected if the last event at or below it opened a range.
function inRange(range: Range, version: Version, ecosystem: string): Verdict {
  if (!Array.isArray(range.events)) return "not-affected";
  const points: Point[] = [];
  for (const event of range.events as Event[]) {
    for (const kind of ["introduced", "fixed", "last_affected"] as const) {
      const value = event?.[kind];
      if (typeof value !== "string") continue;
      // "0" means before every version.
      if (kind === "introduced" && value === "0") {
        points.push({ kind, at: null });
        continue;
      }
      const at = parseVersion(ecosystem, value);
      if (!at) return "unknown";
      points.push({ kind, at });
    }
  }

  points.sort((a, b) => (a.at === null ? -1 : b.at === null ? 1 : a.at.compare(b.at)));
  let affected = false;
  for (const point of points) {
    if (point.kind === "introduced") {
      if (point.at === null || version.compare(point.at) >= 0) affected = true;
    } else if (point.kind === "fixed") {
      if (point.at && version.compare(point.at) >= 0) affected = false;
    } else if (point.at && version.compare(point.at) > 0) {
      affected = false;
    }
  }
  return affected ? "affected" : "not-affected";
}
