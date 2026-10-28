// Ported from google/osv-scalibr semantic/version-pub.go (Apache-2.0) at commit 733765f.

import { compareBuildComponents } from "./semver";
import { parseSemverLikeVersion, type SemverLikeVersion } from "./semver-like";
import { compareStrings } from "./utilities";
import { compareComponents, notSameScheme, type Version } from "./version";

// Semver, except build metadata breaks ties instead of being ignored.
// See https://pub.dev/packages/pub_semver
export class PubVersion implements Version {
  constructor(private readonly version: SemverLikeVersion) {}

  compare(other: Version): number {
    if (!(other instanceof PubVersion)) throw notSameScheme();

    return (
      compareComponents(this.version.components, other.version.components) ||
      compareBuildComponents(this.version.build, other.version.build) ||
      compareStrings(buildMetadata(this.version.build), buildMetadata(other.version.build))
    );
  }
}

export function parsePubVersion(str: string): PubVersion {
  return new PubVersion(parseSemverLikeVersion(str, 3));
}

function buildMetadata(build: string): string {
  const plus = build.indexOf("+");
  return plus === -1 ? "" : build.slice(plus + 1);
}
