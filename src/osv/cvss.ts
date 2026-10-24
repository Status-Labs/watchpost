import type { Severity } from "@/db/schema";

// CVSS v3.x base score, per https://www.first.org/cvss/v3.1/specification-document#7-1-Base-Metrics-Equations
const WEIGHTS = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
} as const;

const PRIVILEGES = {
  unchanged: { N: 0.85, L: 0.62, H: 0.27 },
  changed: { N: 0.85, L: 0.68, H: 0.5 },
} as const;

export function cvss3BaseScore(vector: string): number | null {
  const [prefix, ...parts] = vector.split("/");
  if (!/^CVSS:3\.[01]$/.test(prefix)) return null;

  const metrics: Record<string, string> = {};
  for (const part of parts) {
    const [key, value] = part.split(":");
    if (key && value) metrics[key] = value;
  }

  const scopeChanged = metrics.S === "C";
  if (!scopeChanged && metrics.S !== "U") return null;

  const av = pick(WEIGHTS.AV, metrics.AV);
  const ac = pick(WEIGHTS.AC, metrics.AC);
  const pr = pick(PRIVILEGES[scopeChanged ? "changed" : "unchanged"], metrics.PR);
  const ui = pick(WEIGHTS.UI, metrics.UI);
  const c = pick(WEIGHTS.CIA, metrics.C);
  const i = pick(WEIGHTS.CIA, metrics.I);
  const a = pick(WEIGHTS.CIA, metrics.A);
  if ([av, ac, pr, ui, c, i, a].some((w) => w === undefined)) return null;

  const iss = 1 - (1 - c!) * (1 - i!) * (1 - a!);
  const impact = scopeChanged
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;
  if (impact <= 0) return 0;

  const exploitability = 8.22 * av! * ac! * pr! * ui!;
  const total = scopeChanged ? 1.08 * (impact + exploitability) : impact + exploitability;
  return roundUp(Math.min(total, 10));
}

export function severityFromScore(score: number | null): Severity | null {
  if (score === null || score === 0) return null;
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  return "low";
}

function pick<T extends Record<string, number>>(table: T, key: string | undefined) {
  return key !== undefined && key in table ? table[key as keyof T] : undefined;
}

// The spec's Roundup, which avoids floating point surprises like 4.000001 -> 4.1.
function roundUp(value: number): number {
  const scaled = Math.round(value * 100_000);
  if (scaled % 10_000 === 0) return scaled / 100_000;
  return (Math.floor(scaled / 10_000) + 1) / 10;
}
