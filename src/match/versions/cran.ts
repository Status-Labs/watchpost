// Ported from google/osv-scalibr semantic/version-cran.go (Apache-2.0) at commit 733765f.

import { toBigInt } from "./utilities";
import { compareComponents, notSameScheme, type Version } from "./version";

// Non-negative integers separated by "." or "-".
// See https://astrostatistics.psu.edu/su07/R/html/base/html/package_version.html
export class CranVersion implements Version {
  constructor(private readonly components: bigint[]) {}

  compare(other: Version): number {
    if (!(other instanceof CranVersion)) throw notSameScheme();

    // Unlike most schemes, 1.0 is lower than 1.0.0.
    return (
      compareComponents(this.components, other.components) ||
      Math.sign(this.components.length - other.components.length)
    );
  }
}

export function parseCranVersion(str: string): CranVersion | null {
  if (str === "") return new CranVersion([]);

  const components: bigint[] = [];
  for (const part of str.replaceAll("-", ".").split(".")) {
    const component = toBigInt(part);
    if (component === null) return null;
    components.push(component);
  }

  return new CranVersion(components);
}
