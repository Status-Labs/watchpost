import type { Severity } from "@/db/schema";

const DOT: Record<Severity | "unknown", string> = {
  critical: "bg-severity-critical",
  high: "bg-severity-high",
  medium: "bg-severity-medium",
  low: "bg-severity-low",
  unknown: "bg-severity-unknown",
};

// Color always comes with a text label, never on its own.
export function SeverityBadge({ severity }: { severity: Severity | null }) {
  const level = severity ?? "unknown";
  return (
    <span className="label inline-flex items-center gap-1.5 whitespace-nowrap">
      <span className={`size-2 ${DOT[level]}`} aria-hidden="true" />
      {level}
    </span>
  );
}
