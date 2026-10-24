import { z } from "zod";
import { PACKAGE_NAME_SHAPE, VERSION_SHAPE, oneLine } from "./sanitize";

const MAX_RANGES = 20;
const MAX_EVENTS = 20;
const MAX_PACKAGES = 50;

// Reads affected version ranges from a stored OSV record, for display.
const affectedSchema = z.array(
  z.looseObject({
    package: z.looseObject({ ecosystem: z.string(), name: z.string() }).optional(),
    ranges: z
      .array(
        z.looseObject({
          type: z.string(),
          events: z.array(z.record(z.string(), z.string())),
        }),
      )
      .optional(),
    versions: z.array(z.string()).optional(),
  }),
);

export type AffectedPackage = {
  ecosystem: string;
  name: string;
  ranges: string[];
  versionCount: number;
};

export function affectedPackages(record: unknown): AffectedPackage[] {
  const parsed = affectedSchema.safeParse((record as { affected?: unknown })?.affected ?? []);
  if (!parsed.success) return [];

  return parsed.data.slice(0, MAX_PACKAGES).flatMap((entry) => {
    // Names that don't look like package names are dropped: these fields reach
    // pages, feeds and AI assistants as plain values, not as labeled text.
    if (!entry.package || !PACKAGE_NAME_SHAPE.test(entry.package.name)) return [];
    if (!PACKAGE_NAME_SHAPE.test(entry.package.ecosystem)) return [];
    const ranges = (entry.ranges ?? [])
      .filter((range) => range.type !== "GIT")
      .slice(0, MAX_RANGES)
      .map((range) => describeEvents(range.events));
    return [
      {
        ecosystem: oneLine(entry.package.ecosystem),
        name: oneLine(entry.package.name),
        ranges,
        versionCount: entry.versions?.length ?? 0,
      },
    ];
  });
}

// Turns OSV range events into text like ">= 1.0.0, < 1.4.2".
function describeEvents(events: Record<string, string>[]): string {
  const parts: string[] = [];
  // Upstream values are untrusted: anything that isn't version-shaped is replaced.
  const v = (value: string) => (VERSION_SHAPE.test(value) ? value : "(unrecognized version)");
  for (const event of events.slice(0, MAX_EVENTS)) {
    // "0" means from the first release, so it only needs saying when nothing else bounds the range.
    if (event.introduced && event.introduced !== "0") parts.push(`>= ${v(event.introduced)}`);
    if (event.fixed) parts.push(`< ${v(event.fixed)} (fixed in ${v(event.fixed)})`);
    if (event.last_affected) parts.push(`<= ${v(event.last_affected)}`);
    if (event.limit) parts.push(`< ${v(event.limit)}`);
  }
  return parts.length ? parts.join(", ") : "all versions";
}
