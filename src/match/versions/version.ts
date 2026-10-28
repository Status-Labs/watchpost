// Ported from google/osv-scalibr semantic/version.go (Apache-2.0) at commit 733765f.

import { compareBigInts } from "./utilities";

export interface Version {
  // -1 if this version is lower than other, 0 if equal, 1 if higher. Throws if
  // other came from a different version scheme.
  compare(other: Version): number;
}

export function notSameScheme(): Error {
  return new Error("version is not of the same ecosystem");
}

// Missing components count as zero, so 1.2 equals 1.2.0.
export function compareComponents(a: bigint[], b: bigint[]): number {
  const zero = BigInt(0);
  const length = Math.max(a.length, b.length);

  for (let i = 0; i < length; i++) {
    const diff = compareBigInts(a[i] ?? zero, b[i] ?? zero);
    if (diff !== 0) return diff;
  }

  return 0;
}
