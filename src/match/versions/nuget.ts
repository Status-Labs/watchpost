// Ported from google/osv-scalibr semantic/version-nuget.go (Apache-2.0) at commit 733765f.

import { compareBuildComponents } from "./semver";
import { parseSemverLikeVersion } from "./semver-like";
import { goToLower } from "./utilities";
import { compareComponents, notSameScheme, type Version } from "./version";

// Semver with up to four numeric components and case-insensitive prerelease labels.
// See https://learn.microsoft.com/en-us/nuget/concepts/package-versioning
export class NuGetVersion implements Version {
  constructor(
    private readonly components: bigint[],
    private readonly build: string,
  ) {}

  compare(other: Version): number {
    if (!(other instanceof NuGetVersion)) throw notSameScheme();

    return (
      compareComponents(this.components, other.components) ||
      compareBuildComponents(this.build, other.build)
    );
  }
}

export function parseNuGetVersion(str: string): NuGetVersion {
  const { components, build } = parseSemverLikeVersion(str, 4);
  return new NuGetVersion(components, goToLower(build));
}
