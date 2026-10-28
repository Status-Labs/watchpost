// Ported from google/osv-scalibr semantic/version-hackage.go (Apache-2.0) at commit 733765f.

import { parseSemverLikeVersion } from "./semver-like";
import { compareComponents, notSameScheme, type Version } from "./version";

// Numeric components only, where 1.0 is lower than 1.0.0.
// See https://hackage-content.haskell.org/package/Cabal-syntax-3.16.1.0/docs/Distribution-Types-Version.html
export class HackageVersion implements Version {
  constructor(private readonly components: bigint[]) {}

  compare(other: Version): number {
    if (!(other instanceof HackageVersion)) throw notSameScheme();

    // The Go code also compares build strings here, but parsing rejects any
    // version that has one.
    return (
      compareComponents(this.components, other.components) ||
      Math.sign(this.components.length - other.components.length)
    );
  }
}

export function parseHackageVersion(str: string): HackageVersion | null {
  const { components, build } = parseSemverLikeVersion(str, -1);
  if (build !== "") return null;
  return new HackageVersion(components);
}
