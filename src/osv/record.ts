import { z } from "zod";
import type { Severity } from "@/db/schema";
import { isVulnId, oneLine, stripUnsafe, truncate, VULN_ID_PATTERN } from "@/lib/sanitize";
import { cvss3BaseScore, severityFromScore } from "./cvss";

// The subset of the OSV schema we read. Unknown fields pass through untouched.
// https://ossf.github.io/osv-schema/
export const osvRecordSchema = z.looseObject({
  id: z.string().regex(VULN_ID_PATTERN),
  modified: z.iso.datetime({ offset: true }),
  published: z.iso.datetime({ offset: true }).optional(),
  withdrawn: z.iso.datetime({ offset: true }).nullish(),
  // Aliases that don't look like advisory IDs are dropped, not stored.
  aliases: z
    .array(z.string())
    .nullish()
    .transform((aliases) => (aliases ?? []).filter(isVulnId)),
  summary: z.string().nullish(),
  details: z.string().nullish(),
  severity: z
    .array(z.looseObject({ type: z.string(), score: z.string() }))
    .nullish(),
  affected: z
    .array(
      z.looseObject({
        package: z
          .looseObject({ ecosystem: z.string(), name: z.string() })
          .optional(),
      }),
    )
    .nullish(),
  database_specific: z.looseObject({ severity: z.string().optional() }).nullish(),
});

export type OsvRecord = z.infer<typeof osvRecordSchema>;

export type VulnRow = {
  id: string;
  aliases: string[];
  summary: string | null;
  details: string | null;
  severity: Severity | null;
  cvssScore: number | null;
  published: Date | null;
  modified: Date;
  withdrawn: Date | null;
  record: StoredRecord;
};

// The raw record minus free text, which lives (sanitized) in its own columns.
type StoredRecord = Omit<OsvRecord, "details">;

export type VulnPackageRow = { vulnId: string; ecosystem: string; name: string };

// Caps keep a malformed or hostile upstream record from bloating the database.
const MAX_SUMMARY = 500;
const MAX_DETAILS = 20_000;
const MAX_PACKAGE_NAME = 300;

const ADVISORY_SEVERITY: Record<string, Severity> = {
  CRITICAL: "critical",
  HIGH: "high",
  MODERATE: "medium",
  MEDIUM: "medium",
  LOW: "low",
};

export function toRows(record: OsvRecord): {
  vuln: VulnRow;
  packages: VulnPackageRow[];
} {
  const cvssScore = cvssScoreOf(record);
  const advisorySeverity =
    ADVISORY_SEVERITY[record.database_specific?.severity?.toUpperCase() ?? ""];

  const packages = new Map<string, VulnPackageRow>();
  for (const affected of record.affected ?? []) {
    const pkg = affected.package;
    // Ecosystems can carry a release suffix, like "Debian:12". Match on the base name.
    const ecosystem = oneLine(pkg?.ecosystem ?? "").split(":")[0];
    const name = oneLine(pkg?.name ?? "");
    if (!ecosystem || !name || name.length > MAX_PACKAGE_NAME) continue;
    packages.set(`${ecosystem}\u0000${name}`, { vulnId: record.id, ecosystem, name });
  }

  const { details, ...rest } = record;
  // Postgres jsonb rejects NUL characters anywhere in the document.
  const stored = JSON.parse(JSON.stringify(rest).replaceAll("\\u0000", "")) as StoredRecord;
  const summary = oneLine(record.summary ?? "");
  const cleanDetails = stripUnsafe(details ?? "").trim();

  return {
    vuln: {
      id: record.id,
      aliases: record.aliases,
      summary: summary ? truncate(summary, MAX_SUMMARY) : null,
      details: cleanDetails ? truncate(cleanDetails, MAX_DETAILS) : null,
      severity: advisorySeverity ?? severityFromScore(cvssScore) ?? malwareSeverity(record.id),
      cvssScore,
      published: record.published ? new Date(record.published) : null,
      modified: new Date(record.modified),
      withdrawn: record.withdrawn ? new Date(record.withdrawn) : null,
      record: stored,
    },
    packages: [...packages.values()],
  };
}

// MAL- records are known malicious packages: installing one is a compromise.
function malwareSeverity(id: string): Severity | null {
  return id.startsWith("MAL-") ? "critical" : null;
}

function cvssScoreOf(record: OsvRecord): number | null {
  for (const entry of record.severity ?? []) {
    if (entry.type === "CVSS_V3") {
      const score = cvss3BaseScore(entry.score);
      if (score !== null) return score;
    }
  }
  return null;
}
