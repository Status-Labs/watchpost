// Ported from google/osv-scalibr semantic/utilities.go (Apache-2.0) at commit 733765f.

// What Go's big.Int SetString(str, 10) accepts: an optional sign, then ASCII digits.
const BIG_INT = /^[+-]?[0-9]+$/;
const ASCII = /^[\x00-\x7f]*$/;

export function toBigInt(str: string): bigint | null {
  return BIG_INT.test(str) ? BigInt(str) : null;
}

export function compareBigInts(a: bigint, b: bigint): number {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

export function isAsciiDigit(char: string): boolean {
  return char >= "0" && char <= "9" && char.length === 1;
}

// Go's strings.Compare orders by UTF-8 bytes, which is code point order. JS
// compares UTF-16 code units, which disagrees once surrogate pairs are involved.
export function compareStrings(a: string, b: string): number {
  if (a === b) return 0;

  const length = Math.min(a.length, b.length);
  for (let i = 0; i < length; i++) {
    if (a.charCodeAt(i) !== b.charCodeAt(i)) {
      return a.codePointAt(i)! < b.codePointAt(i)! ? -1 : 1;
    }
  }

  return a.length < b.length ? -1 : 1;
}

// Go's strings.ToLower maps each code point on its own. JS applies context rules
// (final sigma) and expands "İ" to two code points, so map one at a time.
export function goToLower(str: string): string {
  if (ASCII.test(str)) return str.toLowerCase();

  let lower = "";
  for (const char of str) {
    lower += String.fromCodePoint(char.toLowerCase().codePointAt(0)!);
  }
  return lower;
}
