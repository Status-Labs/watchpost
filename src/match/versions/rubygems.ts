// Ported from google/osv-scalibr semantic/version-rubygems.go (Apache-2.0) at commit 733765f.

import { compareBigInts, compareStrings, isAsciiDigit, toBigInt } from "./utilities";
import { notSameScheme, type Version } from "./version";

export class RubyGemsVersion implements Version {
  constructor(private readonly segments: string[]) {}

  compare(other: Version): number {
    if (!(other instanceof RubyGemsVersion)) throw notSameScheme();

    const a = this.segments;
    const b = other.segments;
    const length = Math.max(a.length, b.length);

    for (let i = 0; i < length; i++) {
      const as = a[i] ?? "0";
      const bs = b[i] ?? "0";
      const ai = toBigInt(as);
      const bi = toBigInt(bs);

      if (ai !== null && bi !== null) {
        const diff = compareBigInts(ai, bi);
        if (diff !== 0) return diff;
      } else if (ai === null && bi === null) {
        const diff = compareStrings(as, bs);
        if (diff !== 0) return diff;
      } else {
        // A number is higher than a prerelease label: 1.0 > 1.0.a.
        return ai !== null ? 1 : -1;
      }
    }

    return 0;
  }
}

export function parseRubyGemsVersion(str: string): RubyGemsVersion {
  return new RubyGemsVersion(canonicalSegments(canonicalize(str).split(".")));
}

// Puts a "." wherever digits and non-digits meet, so "1.0a1" becomes "1.0.a.1".
function canonicalize(str: string): string {
  let result = "";
  let checkPrevious = false;
  let previousWasDigit = true;

  for (const char of str) {
    if (char === ".") {
      checkPrevious = false;
      result += ".";
      continue;
    }

    const isDigit = isAsciiDigit(char);
    if (checkPrevious && previousWasDigit !== isDigit) result += ".";
    result += char;

    previousWasDigit = isDigit;
    checkPrevious = true;
  }

  return result;
}

// Everything from the first non-numeric segment on is the prerelease part.
// Trailing zeros are dropped from both parts.
function canonicalSegments(segments: string[]): string[] {
  const numbers: string[] = [];
  const build: string[] = [];

  for (const segment of segments) {
    if (build.length > 0 || toBigInt(segment) === null) {
      build.push(segment);
    } else {
      numbers.push(segment);
    }
  }

  return [...removeTrailingZeros(numbers), ...removeTrailingZeros(build)];
}

function removeTrailingZeros(segments: string[]): string[] {
  let end = segments.length;
  while (end > 0 && segments[end - 1] === "0") end--;
  return segments.slice(0, end);
}
