// Version parsing and comparison for each ecosystem's own rules, ported from
// google/osv-scalibr's semantic package (Apache-2.0) at commit 733765f. The
// mapping below follows its parse.go.

import { parseCranVersion } from "./cran";
import { parseHackageVersion } from "./hackage";
import { parseMavenVersion } from "./maven";
import { parseNuGetVersion } from "./nuget";
import { parsePackagistVersion } from "./packagist";
import { parsePubVersion } from "./pub";
import { parsePyPIVersion } from "./pypi";
import { parseRubyGemsVersion } from "./rubygems";
import { parseSemverVersion } from "./semver";
import type { Version } from "./version";

export type { Version } from "./version";

const PARSERS = new Map<string, (value: string) => Version | null>([
  ["CRAN", parseCranVersion],
  ["crates.io", parseSemverVersion],
  // Not in osv-scalibr. Actions are tagged with semver versions.
  ["GitHub Actions", parseSemverVersion],
  ["Go", parseSemverVersion],
  ["Hackage", parseHackageVersion],
  ["Hex", parseSemverVersion],
  ["Maven", parseMavenVersion],
  ["npm", parseSemverVersion],
  ["NuGet", parseNuGetVersion],
  ["Packagist", parsePackagistVersion],
  ["Pub", parsePubVersion],
  ["PyPI", parsePyPIVersion],
  ["RubyGems", parseRubyGemsVersion],
  ["SwiftURL", parseSemverVersion],
]);

// Returns null for an unsupported ecosystem or a version its scheme rejects.
// Versions from different ecosystems can't be compared with each other.
export function parseVersion(ecosystem: string, value: string): Version | null {
  // OSV ecosystems can carry a suffix, as in "Debian:12".
  const parser = PARSERS.get(ecosystem.split(":")[0]);
  return parser ? parser(value) : null;
}
