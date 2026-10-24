import { z } from "zod";

// What an assistant may send in report_stack. We don't trust the assistant to
// leave out sensitive data, so anything that doesn't look like a package name
// and version is dropped and listed back, never stored or logged.

export const STACK_ECOSYSTEMS = [
  "npm",
  "PyPI",
  "Go",
  "crates.io",
  "Maven",
  "NuGet",
  "Packagist",
  "RubyGems",
  "Hex",
  "Pub",
  "GitHub Actions",
  "Hackage",
  "CRAN",
  "SwiftURL",
] as const;
export type StackEcosystem = (typeof STACK_ECOSYSTEMS)[number];

export const MAX_ITEMS = 5_000;
export const STACK_NAME_PATTERN = /^[a-z0-9-]{1,32}$/;

const MODULE_PATH = /^[A-Za-z0-9][A-Za-z0-9._~+-]*(\/[A-Za-z0-9._~+-]+)*$/;

// Each ecosystem's package name format, loosely: tight enough to keep out
// paths, hostnames with ports, emails and prose.
const NAME_PATTERNS: Record<StackEcosystem, RegExp> = {
  npm: /^(@[a-z0-9~-][a-z0-9._~-]*\/)?[a-z0-9~-][a-z0-9._~-]*$/,
  PyPI: /^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$/,
  Go: MODULE_PATH,
  "crates.io": /^[A-Za-z0-9_-]+$/,
  Maven: /^[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+$/,
  NuGet: /^[A-Za-z0-9_.-]+$/,
  Packagist: /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/,
  RubyGems: /^[A-Za-z0-9_.-]+$/,
  Hex: /^[A-Za-z0-9_]+$/,
  Pub: /^[A-Za-z0-9_]+$/,
  "GitHub Actions": /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_./-]+$/,
  Hackage: /^[A-Za-z0-9-]+$/,
  CRAN: /^[A-Za-z0-9.]+$/,
  SwiftURL: MODULE_PATH,
};

const MAX_NAME = 214;
const MAX_VERSION = 100;
// A colon only as an epoch prefix ("1:2.3"), so "host:8443" isn't a version.
const VERSION_PATTERN = /^(\d+:)?[A-Za-z0-9][A-Za-z0-9.+_~!-]*$/;
// Hosts that only exist inside a company network. A module path on one of
// these names the company and its internal infrastructure.
const INTERNAL_HOST = /(^|[./])(localhost|[^./]+\.(internal|intranet|corp|local|lan|home|private|localdomain|home\.arpa))(\/|:|$)/i;

// Prefixes of common API keys and tokens, followed by a token-length run (so a
// package like "disk-usage" doesn't match "sk-").
const SECRET_PREFIXES =
  /(^|[^A-Za-z0-9])(ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|glpat-|sk-|sk_live_|sk_test_|rk_live_|xox[abprs]-|AKIA|ASIA|AIza|wp[arkc]_|npm_|pypi-|dop_v1_|hf_)[A-Za-z0-9_-]{16,}/;
const IPV4 = /(^|[^0-9])\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}([^0-9]|$)/;

export type StackItem = { ecosystem: StackEcosystem; name: string; version: string };
export type RejectedItem = { ecosystem: string; name: string; version: string; reason: string };

export const stackItemInput = z.object({
  ecosystem: z.string().max(40),
  name: z.string().max(500),
  version: z.string().max(200),
});

export function validateItems(input: z.infer<typeof stackItemInput>[]): { items: StackItem[]; rejected: RejectedItem[] } {
  const items = new Map<string, StackItem>();
  const rejected: RejectedItem[] = [];
  for (const raw of input) {
    const reason = rejectReason(raw);
    if (reason) {
      rejected.push({
        ecosystem: raw.ecosystem.slice(0, 40),
        // A value that looked like a secret isn't echoed back.
        name: reason === "looks like a secret" ? "[hidden]" : raw.name.slice(0, 80),
        version: reason === "looks like a secret" ? "[hidden]" : raw.version.slice(0, 40),
        reason,
      });
      continue;
    }
    const item = { ecosystem: raw.ecosystem as StackEcosystem, name: raw.name, version: raw.version };
    items.set(`${item.ecosystem}\u0000${item.name}\u0000${item.version}`, item);
  }
  return { items: [...items.values()], rejected };
}

function rejectReason({ ecosystem, name, version }: z.infer<typeof stackItemInput>): string | null {
  if (!(STACK_ECOSYSTEMS as readonly string[]).includes(ecosystem)) return "unsupported ecosystem";
  if (looksSecret(name) || looksSecret(version)) return "looks like a secret";
  if (!name || name.length > MAX_NAME) return "invalid package name";
  if (!version || version.length > MAX_VERSION || !VERSION_PATTERN.test(version)) return "invalid version";
  if (name.includes("://") || name.includes("\\") || name.includes("..") || /^[/~.]/.test(name)) {
    return "looks like a path or URL";
  }
  if (/[^@\s]+@[^@\s]+\.[^@\s]+/.test(name)) return "looks like an email address";
  if (IPV4.test(name)) return "looks like an IP address";
  if (INTERNAL_HOST.test(name)) return "looks like an internal hostname";
  if (!NAME_PATTERNS[ecosystem as StackEcosystem].test(name)) return "invalid package name";
  return null;
}

// Known key prefixes, or a long random-looking run of characters.
export function looksSecret(value: string): boolean {
  if (SECRET_PREFIXES.test(value)) return true;
  for (const run of value.match(/[A-Za-z0-9+/=_-]{32,}/g) ?? []) {
    if (/[0-9]/.test(run) && /[A-Za-z]/.test(run) && entropy(run) >= 4) return true;
  }
  return false;
}

function entropy(value: string): number {
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let bits = 0;
  for (const n of counts.values()) {
    const p = n / value.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}
