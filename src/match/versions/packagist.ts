// Ported from google/osv-scalibr semantic/version-packagist.go (Apache-2.0) at commit 733765f.

import { compareBigInts, toBigInt } from "./utilities";
import { notSameScheme, type Version } from "./version";

// Matches PHP's version_compare, plus Composer's trimming of a leading "v".
export class PackagistVersion implements Version {
  constructor(private readonly components: string[]) {}

  compare(other: Version): number {
    if (!(other instanceof PackagistVersion)) throw notSameScheme();
    return compareComponents(this.components, other.components);
  }
}

export function parsePackagistVersion(str: string): PackagistVersion {
  return new PackagistVersion(canonicalize(str).split("."));
}

function canonicalize(str: string): string {
  if (str.startsWith("v")) str = str.slice(1);
  if (str.startsWith("V")) str = str.slice(1);

  return str
    .replace(/[-_+]/g, ".")
    .replace(/([^\d.])(\d)/g, "$1.$2")
    .replace(/(\d)([^\d.])/g, "$1.$2");
}

// Unknown labels weigh the same as "dev". "#" stands for any number.
const SPECIALS = ["dev", "a", "b", "rc", "#", "p"];

function weigh(component: string): number {
  if (component.startsWith("RC")) return 3;

  const index = SPECIALS.findIndex((special) => component.startsWith(special));
  return index === -1 ? 0 : index;
}

function compareSpecial(a: string, b: string): number {
  return Math.sign(weigh(a) - weigh(b));
}

function compareComponents(a: string[], b: string[]): number {
  const length = Math.min(a.length, b.length);

  for (let i = 0; i < length; i++) {
    const ai = toBigInt(a[i]);
    const bi = toBigInt(b[i]);

    let diff: number;
    if (ai !== null && bi !== null) {
      diff = compareBigInts(ai, bi);
    } else if (ai === null && bi === null) {
      diff = compareSpecial(a[i], b[i]);
    } else if (ai !== null) {
      diff = compareSpecial("#", b[i]);
    } else {
      diff = compareSpecial(a[i], "#");
    }

    if (diff !== 0) return diff;
  }

  if (a.length > b.length) {
    if (isInt(a[b.length])) return 1;
    return compareComponents(a.slice(b.length), ["#"]);
  }

  if (a.length < b.length) {
    if (isInt(b[a.length])) return -1;
    return compareComponents(["#"], b.slice(a.length));
  }

  return 0;
}

const INT64_MIN = -(BigInt(2) ** BigInt(63));
const INT64_MAX = BigInt(2) ** BigInt(63) - BigInt(1);

// Go's strconv.Atoi, which fails on numbers that don't fit in an int64.
function isInt(str: string): boolean {
  const value = toBigInt(str);
  return value !== null && value >= INT64_MIN && value <= INT64_MAX;
}
