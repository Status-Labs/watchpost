// Ported from google/osv-scalibr semantic/version-semver.go (Apache-2.0) at commit 733765f.

import { parseSemverLikeVersion, type SemverLikeVersion } from "./semver-like";
import { compareBigInts, compareStrings, toBigInt } from "./utilities";
import { compareComponents, notSameScheme, type Version } from "./version";

// Semver 2.0.0, as used by npm, crates.io, Go and others.
// See https://semver.org/spec/v2.0.0.html
export class SemverVersion implements Version {
  constructor(private readonly version: SemverLikeVersion) {}

  compare(other: Version): number {
    if (!(other instanceof SemverVersion)) throw notSameScheme();

    return (
      compareComponents(this.version.components, other.version.components) ||
      compareBuildComponents(this.version.build, other.version.build)
    );
  }
}

export function parseSemverVersion(str: string): SemverVersion {
  return new SemverVersion(parseSemverLikeVersion(str, 3));
}

export function compareBuildComponents(a: string, b: string): number {
  // Build metadata is ignored: https://semver.org/spec/v2.0.0.html#spec-item-10
  a = a.split("+")[0];
  b = b.split("+")[0];

  // The spec doesn't say to skip the hyphen, but node-semver does.
  if (a.startsWith("-")) a = a.slice(1);
  if (b.startsWith("-")) b = b.slice(1);

  // A version with a prerelease is lower than one without.
  if (a === "" && b !== "") return 1;
  if (a !== "" && b === "") return -1;

  return compareSemverBuildComponents(a.split("."), b.split("."));
}

function compareSemverBuildComponents(a: string[], b: string[]): number {
  const length = Math.min(a.length, b.length);

  for (let i = 0; i < length; i++) {
    const ai = toBigInt(a[i]);
    const bi = toBigInt(b[i]);

    let diff: number;
    if (ai !== null && bi !== null) {
      diff = compareBigInts(ai, bi);
    } else if (ai === null && bi === null) {
      diff = compareStrings(a[i], b[i]);
    } else {
      // Numeric identifiers are lower than non-numeric ones.
      diff = ai !== null ? -1 : 1;
    }

    if (diff !== 0) return diff;
  }

  return Math.sign(a.length - b.length);
}
