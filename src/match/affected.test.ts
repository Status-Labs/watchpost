import { describe, expect, it } from "vitest";
import { affects } from "./affected";

const record = (affected: unknown[]) => ({ id: "GHSA-test", affected });
const npm = (ranges: unknown[], extra: object = {}) => record([{ package: { ecosystem: "npm", name: "lodash" }, ranges, ...extra }]);
const semver = (...events: object[]) => ({ type: "SEMVER", events });

describe("affects", () => {
  it("evaluates introduced and fixed", () => {
    const r = npm([semver({ introduced: "0" }, { fixed: "4.17.21" })]);
    expect(affects(r, "npm", "lodash", "4.17.15")).toBe("affected");
    expect(affects(r, "npm", "lodash", "4.17.21")).toBe("not-affected");
    expect(affects(r, "npm", "lodash", "5.0.0")).toBe("not-affected");
  });

  it("handles several ranges in one event list, in any order", () => {
    const r = npm([semver({ fixed: "1.2.0" }, { introduced: "2.0.0" }, { introduced: "1.0.0" }, { fixed: "2.1.0" })]);
    expect(affects(r, "npm", "lodash", "0.9.0")).toBe("not-affected");
    expect(affects(r, "npm", "lodash", "1.1.0")).toBe("affected");
    expect(affects(r, "npm", "lodash", "1.5.0")).toBe("not-affected");
    expect(affects(r, "npm", "lodash", "2.0.5")).toBe("affected");
    expect(affects(r, "npm", "lodash", "2.1.0")).toBe("not-affected");
  });

  it("treats last_affected as inclusive", () => {
    const r = npm([semver({ introduced: "1.0.0" }, { last_affected: "1.4.0" })]);
    expect(affects(r, "npm", "lodash", "1.4.0")).toBe("affected");
    expect(affects(r, "npm", "lodash", "1.4.1")).toBe("not-affected");
  });

  it("matches explicit version lists", () => {
    const r = record([{ package: { ecosystem: "PyPI", name: "Django" }, versions: ["3.2", "3.2.1"] }]);
    expect(affects(r, "PyPI", "django", "3.2.1")).toBe("affected");
    // The same PyPI version written differently.
    expect(affects(r, "PyPI", "django", "3.2.0")).toBe("affected");
    expect(affects(r, "PyPI", "django", "3.2.2")).toBe("not-affected");
  });

  it("affects every version for a malicious package report", () => {
    const r = npm([semver({ introduced: "0" })]);
    expect(affects(r, "npm", "lodash", "0.0.1")).toBe("affected");
  });

  it("ignores other packages, ecosystems and GIT ranges", () => {
    const r = npm([semver({ introduced: "0" })]);
    expect(affects(r, "npm", "underscore", "1.0.0")).toBe("not-affected");
    expect(affects(r, "PyPI", "lodash", "1.0.0")).toBe("not-affected");
    expect(affects(npm([{ type: "GIT", events: [{ introduced: "0" }] }]), "npm", "lodash", "1.0.0")).toBe("not-affected");
  });

  it("normalizes PyPI names and ecosystem suffixes", () => {
    const r = record([{ package: { ecosystem: "PyPI:extra", name: "Zope_Interface" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "5.0" }] }] }]);
    expect(affects(r, "PyPI", "zope.interface", "4.7.1")).toBe("affected");
  });

  it("uses each ecosystem's own ordering", () => {
    const r = record([{ package: { ecosystem: "Maven", name: "org.apache.logging.log4j:log4j-core" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "2.0-beta9" }, { fixed: "2.15.0" }] }] }]);
    expect(affects(r, "Maven", "org.apache.logging.log4j:log4j-core", "2.14.1")).toBe("affected");
    expect(affects(r, "Maven", "org.apache.logging.log4j:log4j-core", "2.0-alpha1")).toBe("not-affected");
  });

  it("reports unknown when the version can't be read", () => {
    const r = record([{ package: { ecosystem: "CRAN", name: "x" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "2.0" }] }] }]);
    expect(affects(r, "CRAN", "x", "1.a")).toBe("unknown");
  });

  it("survives malformed records", () => {
    expect(affects(null, "npm", "lodash", "1.0.0")).toBe("not-affected");
    expect(affects({ affected: "nope" }, "npm", "lodash", "1.0.0")).toBe("not-affected");
    expect(affects(npm([{ type: "SEMVER", events: "nope" }]), "npm", "lodash", "1.0.0")).toBe("not-affected");
  });
});
