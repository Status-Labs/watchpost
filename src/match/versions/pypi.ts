// Ported from google/osv-scalibr semantic/version-pypi.go (Apache-2.0) at commit 733765f.

import { compareBigInts, compareStrings, goToLower, isAsciiDigit, toBigInt } from "./utilities";
import { compareComponents, notSameScheme, type Version } from "./version";

// From https://peps.python.org/pep-0440/#appendix-b-parsing-version-strings-with-regular-expressions,
// with Go's ASCII-only \s spelled out and only the groups we read capturing.
const VERSION =
  /^[\t\n\f\r ]*v?(?:(?:([0-9]+)!)?([0-9]+(?:\.[0-9]+)*)(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?([0-9]+)?)?(?:(?:-([0-9]+))|(?:[-_.]?(post|rev|r)[-_.]?([0-9]+)?))?(?:[-_.]?(dev)[-_.]?([0-9]+)?)?)(?:\+([a-z0-9]+(?:[-_.][a-z0-9]+)*))?[\t\n\f\r ]*$/;
// Capture groups in VERSION.
const EPOCH = 1;
const RELEASE = 2;
const PRE_L = 3;
const PRE_N = 4;
const POST_N1 = 5;
const POST_L = 6;
const POST_N2 = 7;
const DEV_L = 8;
const DEV_N = 9;
const LOCAL = 10;

const LEGACY_PARTS = /\d+|[a-z]+|\.|-/g;

type Segment = { letter: string; number: bigint | null };

const NO_SEGMENT: Segment = { letter: "", number: null };

type Parts = {
  epoch: bigint;
  release: bigint[];
  pre: Segment;
  post: Segment;
  dev: Segment;
  local: string[];
  // Set for versions that don't follow PEP 440, which sort before all others.
  legacy: string[];
};

// See https://peps.python.org/pep-0440/
export class PyPIVersion implements Version {
  constructor(private readonly parts: Parts) {}

  compare(other: Version): number {
    if (!(other instanceof PyPIVersion)) throw notSameScheme();

    const v = this.parts;
    const w = other.parts;
    return (
      compareLegacy(v.legacy, w.legacy) ||
      compareBigInts(v.epoch, w.epoch) ||
      compareComponents(v.release, w.release) ||
      comparePre(v, w) ||
      comparePost(v.post, w.post) ||
      compareDev(v.dev, w.dev) ||
      compareLocal(v.local, w.local)
    );
  }
}

export function parsePyPIVersion(str: string): PyPIVersion | null {
  str = goToLower(str);

  const match = VERSION.exec(str);
  if (!match) return new PyPIVersion(parseLegacy(str));

  const group = (index: number) => match[index] ?? "";

  let epoch = BigInt(0);
  if (group(EPOCH) !== "") {
    const parsed = toBigInt(group(EPOCH));
    if (parsed === null) return null;
    epoch = parsed;
  }

  const release: bigint[] = [];
  for (const part of group(RELEASE).split(".")) {
    const parsed = toBigInt(part);
    if (parsed === null) return null;
    release.push(parsed);
  }

  const pre = parseSegment(group(PRE_L), group(PRE_N));
  const post = parseSegment(group(POST_L), group(POST_N1) || group(POST_N2));
  const dev = parseSegment(group(DEV_L), group(DEV_N));
  if (!pre || !post || !dev) return null;

  // An absent local part becomes [""], as in Go, which sorts before any real one.
  const local = group(LOCAL).split(/[._-]/).map(goToLower);

  return new PyPIVersion({ epoch, release, pre, post, dev, local, legacy: [] });
}

function parseSegment(letter: string, number: string): Segment | null {
  if (letter === "" && number === "") return NO_SEGMENT;

  // A number without a letter is the implicit post release syntax, as in 1.0-1.
  // A letter without a number has an implicit 0.
  const parsed = toBigInt(number === "" ? "0" : number);
  if (parsed === null) return null;

  return { letter: letter === "" ? "post" : normalizeLetter(goToLower(letter)), number: parsed };
}

function normalizeLetter(letter: string): string {
  switch (letter) {
    case "alpha":
      return "a";
    case "beta":
      return "b";
    case "c":
    case "pre":
    case "preview":
      return "rc";
    case "rev":
    case "r":
      return "post";
    default:
      return letter;
  }
}

function parseLegacy(str: string): Parts {
  const parts: string[] = [];

  for (const match of [...(str.match(LEGACY_PARTS) ?? []), "final"]) {
    if (match === ".") continue;

    const part = normalizeLegacyPart(match);

    if (part.startsWith("*")) {
      if (compareStrings(part, "*final") < 0) {
        while (parts.at(-1) === "*final-") parts.pop();
      }
      while (parts.at(-1) === "00000000") parts.pop();
    }

    parts.push(part);
  }

  return {
    epoch: BigInt(-1),
    release: [],
    pre: NO_SEGMENT,
    post: NO_SEGMENT,
    dev: NO_SEGMENT,
    local: [],
    legacy: parts,
  };
}

function normalizeLegacyPart(part: string): string {
  switch (part) {
    case "pre":
    case "preview":
    case "rc":
      part = "c";
      break;
    case "-":
      part = "final-";
      break;
    case "dev":
      part = "@";
      break;
  }

  // Numbers are zero-padded so they compare correctly as strings.
  if (isAsciiDigit(part[0])) return part.padStart(8, "0");
  return "*" + part;
}

function compareLegacy(a: string[], b: string[]): number {
  if (a.length === 0 && b.length === 0) return 0;
  if (a.length === 0) return 1;
  if (b.length === 0) return -1;
  return compareStrings(a.join(""), b.join(""));
}

// A dev release of a final version, like 1.0.dev0, sorts before its prereleases.
function isDevOnly(v: Parts): boolean {
  return v.pre.number === null && v.post.number === null && v.dev.number !== null;
}

function comparePre(v: Parts, w: Parts): number {
  const vDevOnly = isDevOnly(v);
  const wDevOnly = isDevOnly(w);
  if (vDevOnly && wDevOnly) return 0;
  if (vDevOnly) return -1;
  if (wDevOnly) return 1;

  // A version without a prerelease sorts after one with.
  if (v.pre.number === null && w.pre.number === null) return 0;
  if (v.pre.number === null) return 1;
  if (w.pre.number === null) return -1;

  // The letters are "a", "b" and "rc", so the first character orders them.
  const a = v.pre.letter.charCodeAt(0);
  const b = w.pre.letter.charCodeAt(0);
  if (a !== b) return a > b ? 1 : -1;

  return compareBigInts(v.pre.number, w.pre.number);
}

// A version without a post release sorts before one with.
function comparePost(v: Segment, w: Segment): number {
  if (v.number === null && w.number === null) return 0;
  if (v.number === null) return -1;
  if (w.number === null) return 1;
  return compareBigInts(v.number, w.number);
}

// A version without a dev release sorts after one with.
function compareDev(v: Segment, w: Segment): number {
  if (v.number === null && w.number === null) return 0;
  if (v.number === null) return 1;
  if (w.number === null) return -1;
  return compareBigInts(v.number, w.number);
}

function compareLocal(a: string[], b: string[]): number {
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
      // Numeric segments are higher than alphanumeric ones.
      diff = ai !== null ? 1 : -1;
    }

    if (diff !== 0) return diff;
  }

  // With equal leading segments, more segments is higher.
  return Math.sign(a.length - b.length);
}
