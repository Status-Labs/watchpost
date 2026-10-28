// Ported from google/osv-scalibr semantic/version-maven.go (Apache-2.0) at commit 733765f.

import { compareBigInts, compareStrings, goToLower, isAsciiDigit, toBigInt } from "./utilities";
import { notSameScheme, type Version } from "./version";

type Token = {
  prefix: string;
  value: string;
  isNull: boolean;
};

// See https://maven.apache.org/pom.html#version-order-specification
export class MavenVersion implements Version {
  constructor(private readonly tokens: Token[]) {}

  compare(other: Version): number {
    if (!(other instanceof MavenVersion)) throw notSameScheme();

    if (this.equals(other)) return 0;
    return this.lessThan(other) ? -1 : 1;
  }

  private equals(other: MavenVersion): boolean {
    return (
      this.tokens.length === other.tokens.length &&
      this.tokens.every((token, i) => tokensEqual(token, other.tokens[i]))
    );
  }

  private lessThan(other: MavenVersion): boolean {
    const length = Math.max(this.tokens.length, other.tokens.length);

    for (let i = 0; i < length; i++) {
      // The shorter version is padded with "null" tokens whose prefix matches
      // the other version's token.
      const left = this.tokens[i] ?? nullToken(other.tokens[i]);
      const right = other.tokens[i] ?? nullToken(this.tokens[i]);

      if (tokensEqual(left, right)) continue;
      return tokenLessThan(left, right);
    }

    return false;
  }
}

export function parseMavenVersion(str: string): MavenVersion {
  const tokens: Token[] = [];

  // Split on "." and "-", keeping the separators as each token's prefix.
  const rawTokens = str.split(/([-.])/);

  for (let i = 0; i < rawTokens.length; i += 2) {
    const pieces = splitAtTransitions(rawTokens[i]);

    pieces.forEach((piece, j) => {
      // A transition between digits and letters counts as a hyphen.
      const prefix = j > 0 ? "-" : i === 0 ? "" : rawTokens[i - 1];

      // The spec doesn't say so, but all qualifiers are case-insensitive.
      let value = goToLower(piece);

      if (value === "") value = "0";
      if (value === "cr") value = "rc";
      // "release" isn't in the spec, but Maven treats it like "ga" and "final".
      if (value === "ga" || value === "final" || value === "release") value = "";

      // "a", "b" and "m" are short for "alpha", "beta" and "milestone" when a
      // number follows directly.
      if (j < pieces.length - 1) {
        if (value === "a") value = "alpha";
        if (value === "b") value = "beta";
        if (value === "m") value = "milestone";
      }

      const number = toBigInt(value);
      if (number !== null) value = number.toString();

      tokens.push({ prefix, value, isNull: false });
    });
  }

  // Trim trailing "null" values, then repeat from each hyphen back to the start.
  let i = tokens.length - 1;
  while (i > 0) {
    if (shouldTrim(tokens[i])) {
      tokens.splice(i, 1);
      i--;
      continue;
    }

    while (i >= 0 && tokens[i].prefix !== "-") i--;
    i--;
  }

  return new MavenVersion(tokens);
}

// Splits wherever a digit meets a non-digit. Maven treats any non-digit as a letter.
//
// The Go code finds these points with byte offsets and splits one byte after the
// start of a non-digit followed by a digit. For a multi-byte character that cuts
// it in two, and Go's ToLower then turns each broken byte into U+FFFD. We do the
// same so non-ASCII versions compare the way they do in Go.
function splitAtTransitions(token: string): string[] {
  const chars = Array.from(token);
  const pieces: string[] = [];
  let current = "";

  for (let k = 0; k < chars.length; k++) {
    const char = chars[k];
    const next = chars[k + 1];
    const atTransition = next !== undefined && isAsciiDigit(char) !== isAsciiDigit(next);

    if (atTransition && !isAsciiDigit(char) && char.codePointAt(0)! > 0x7f) {
      pieces.push(current + "�");
      current = "�".repeat(utf8Length(char) - 1);
      continue;
    }

    current += char;
    if (atTransition) {
      pieces.push(current);
      current = "";
    }
  }

  pieces.push(current);
  return pieces;
}

function utf8Length(char: string): number {
  const codePoint = char.codePointAt(0)!;
  if (codePoint < 0x80) return 1;
  if (codePoint < 0x800) return 2;
  if (codePoint < 0x10000) return 3;
  return 4;
}

function shouldTrim(token: Token): boolean {
  return token.value === "0" || token.value === "" || token.value === "final" || token.value === "ga";
}

function tokensEqual(a: Token, b: Token): boolean {
  return a.prefix === b.prefix && a.value === b.value;
}

function nullToken(token: Token): Token {
  // "sp" is the only qualifier that sorts after an empty value, so padding
  // against it uses "" instead of "0".
  if (token.prefix === ".") return { prefix: ".", value: token.value === "sp" ? "" : "0", isNull: true };
  if (token.prefix === "-") return { prefix: "-", value: "", isNull: true };

  // Unreachable: only the first token lacks a prefix, and it's never padded.
  throw new Error(`invalid version: unknown prefix '${token.prefix}' (value '${token.value}')`);
}

const KEYWORD_ORDER = ["alpha", "beta", "milestone", "rc", "snapshot", "", "sp"];

function keywordOrder(keyword: string): number {
  const index = KEYWORD_ORDER.indexOf(keyword);
  return index === -1 ? KEYWORD_ORDER.length : index;
}

function tokenLessThan(a: Token, b: Token): boolean {
  // ".qualifier" < "-qualifier" < "-number" < ".number"
  if (a.prefix !== b.prefix) return qualifierOrder(a) < qualifierOrder(b);

  const av = toBigInt(a.value);
  const bv = toBigInt(b.value);
  if (av !== null && bv !== null) return compareBigInts(av, bv) < 0;

  // Numbers sort after qualifiers, unless they're padding. This follows Maven's
  // implementation rather than the spec:
  // https://github.com/apache/maven/blob/965aaa53da5c2d814e94a41d37142d0d6830375d/maven-artifact/src/main/java/org/apache/maven/artifact/versioning/ComparableVersion.java#L443
  if (av !== null && !a.isNull) return false;
  if (bv !== null && !b.isNull) return true;

  // Known qualifiers come first in a fixed order, then unknown ones alphabetically.
  const left = keywordOrder(a.value);
  const right = keywordOrder(b.value);
  if (left === KEYWORD_ORDER.length && right === KEYWORD_ORDER.length) {
    return compareStrings(a.value, b.value) < 0;
  }
  return left < right;
}

function qualifierOrder(token: Token): number {
  const isNumber = toBigInt(token.value) !== null;
  if (token.prefix === "-") return isNumber ? 2 : 1;
  if (token.prefix === ".") return isNumber ? 3 : 0;

  // Unreachable: tokens at the same index both lack a prefix or both have one.
  throw new Error(`invalid version: unknown prefix '${token.prefix}'`);
}
