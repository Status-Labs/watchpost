import { describe, expect, it } from "vitest";
import { CATEGORY_IDS, categoryPattern, matchesCategory } from "./categories";

describe("categories", () => {
  it("matches package names by whole segment", () => {
    expect(matchesCategory("databases", { name: "pg" })).toBe(true);
    expect(matchesCategory("databases", { name: "github.com/jackc/pgx/v5" })).toBe(true);
    expect(matchesCategory("databases", { name: "org.postgresql:postgresql" })).toBe(true);
    expect(matchesCategory("databases", { name: "pgadmin-ui" })).toBe(false);
    expect(matchesCategory("infrastructure", { name: "k8s.io/kubernetes" })).toBe(true);
    expect(matchesCategory("web", { name: "@nestjs/core" })).toBe(true);
  });

  it("matches KEV vendor and product text", () => {
    expect(matchesCategory("os", { name: "Microsoft Windows" })).toBe(true);
    expect(matchesCategory("network", { name: "Fortinet FortiOS" })).toBe(true);
    expect(matchesCategory("browsers", { name: "Google Chromium V8" })).toBe(true);
    expect(matchesCategory("databases", { name: "Oracle Database Server" })).toBe(true);
  });

  it("puts whole ecosystems in a category", () => {
    expect(matchesCategory("infrastructure", { ecosystem: "GitHub Actions", name: "some/action" })).toBe(true);
  });

  it("builds patterns that only contain safe regex syntax", () => {
    for (const id of CATEGORY_IDS) expect(() => new RegExp(categoryPattern(id), "i")).not.toThrow();
  });
});
