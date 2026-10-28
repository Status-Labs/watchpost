import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parseVersion } from "./index";

// Mirrors osv-scalibr's semantic/compare_test.go: every fixture line is checked
// in both directions.
const FIXTURES: [ecosystem: string, file: string][] = [
  ["npm", "semver-versions.txt"],
  ["crates.io", "semver-versions.txt"],
  ["Go", "semver-versions.txt"],
  ["Hex", "semver-versions.txt"],
  ["SwiftURL", "semver-versions.txt"],
  ["GitHub Actions", "semver-versions.txt"],
  ["RubyGems", "rubygems-versions.txt"],
  ["RubyGems", "rubygems-versions-generated.txt"],
  ["NuGet", "nuget-versions.txt"],
  ["Packagist", "packagist-versions.txt"],
  ["Packagist", "packagist-versions-generated.txt"],
  ["Maven", "maven-versions.txt"],
  ["Maven", "maven-versions-generated.txt"],
  ["PyPI", "pypi-versions.txt"],
  ["PyPI", "pypi-versions-generated.txt"],
  ["CRAN", "cran-versions.txt"],
  ["CRAN", "cran-versions-generated.txt"],
  ["Hackage", "hackage-versions.txt"],
  ["Pub", "pub-versions.txt"],
];

const EXPECTED: Record<string, number> = { "<": -1, "=": 0, ">": 1 };

function readFixture(file: string): string[] {
  return readFileSync(`fixtures/versions/${file}`, "utf8")
    .split("\n")
    .filter((line) => line !== "" && !line.startsWith("# ") && !line.startsWith("// "));
}

function compare(ecosystem: string, a: string, b: string): number {
  const left = parseVersion(ecosystem, a);
  const right = parseVersion(ecosystem, b);
  if (!left) throw new Error(`failed to parse ${a} as ${ecosystem}`);
  if (!right) throw new Error(`failed to parse ${b} as ${ecosystem}`);
  return left.compare(right);
}

describe("parseVersion fixtures", () => {
  it.each(FIXTURES)("%s: %s", (ecosystem, file) => {
    const lines = readFixture(file);
    const failures: string[] = [];

    for (const line of lines) {
      const pieces = line.split(" ");
      if (pieces.length !== 3) throw new Error(`incorrect number of pieces in fixture "${line}"`);

      const [a, operator, b] = pieces;
      const expected = EXPECTED[operator];
      if (expected === undefined) throw new Error(`unknown comparator ${operator}`);

      if (compare(ecosystem, a, b) !== expected || compare(ecosystem, b, a) !== -expected) {
        failures.push(line);
      }
    }

    expect(lines.length).toBeGreaterThan(0);
    expect(failures).toEqual([]);
  });
});

describe("parseVersion", () => {
  it("returns null for unsupported ecosystems", () => {
    expect(parseVersion("Debian", "1.2.3")).toBeNull();
    expect(parseVersion("Alpine:v3.20", "1.2.3")).toBeNull();
    expect(parseVersion("constructor", "1.2.3")).toBeNull();
    expect(parseVersion("", "1.2.3")).toBeNull();
  });

  it("strips the ecosystem suffix", () => {
    expect(compare("npm:whatever", "1.2.3", "1.10.0")).toBe(-1);
  });

  it("returns null for versions the scheme rejects", () => {
    expect(parseVersion("CRAN", "1.2.a")).toBeNull();
    expect(parseVersion("Hackage", "1.2-beta")).toBeNull();
  });

  it("compares numbers too big for a double", () => {
    expect(compare("npm", "1.0.90071992547409930", "1.0.90071992547409931")).toBe(-1);
    expect(compare("PyPI", "1.0.post90071992547409931", "1.0.post90071992547409930")).toBe(1);
  });

  it("refuses to compare versions from different schemes", () => {
    const npm = parseVersion("npm", "1.0.0")!;
    const pypi = parseVersion("PyPI", "1.0.0")!;
    expect(() => npm.compare(pypi)).toThrow();
  });
});
