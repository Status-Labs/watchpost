import { describe, expect, it } from "vitest";
import { LIST_DEFAULTS, describeFilter, filterQuery, parseFilters } from "./filters";

describe("parseFilters", () => {
  it("opens the list on critical CVEs and advisories, newest first", () => {
    expect(parseFilters({}, LIST_DEFAULTS)).toEqual({
      filter: {
        ecosystems: undefined,
        categories: undefined,
        packages: undefined,
        query: undefined,
        severities: ["critical"],
        kind: "advisories",
      },
      sort: "newest",
      page: 1,
    });
  });

  it("has no severity default for the feed", () => {
    expect(parseFilters({}).filter.severities).toBeUndefined();
  });

  it("shows every severity in the exploited view, since CISA publishes no scores", () => {
    expect(parseFilters({ type: "exploited" }, LIST_DEFAULTS).filter.severities).toBeUndefined();
    expect(parseFilters({ type: "exploited", severity: "high" }, LIST_DEFAULTS).filter.severities).toEqual(["high"]);
  });

  it("reads severity lists and 'all', and falls back on bad values", () => {
    expect(parseFilters({ severity: "critical,high" }, LIST_DEFAULTS).filter.severities).toEqual(["critical", "high"]);
    expect(parseFilters({ severity: "all" }, LIST_DEFAULTS).filter.severities).toBeUndefined();
    expect(parseFilters({ severity: "bogus" }, LIST_DEFAULTS).filter.severities).toEqual(["critical"]);
  });

  it("reads lists of languages, categories and packages, dropping unknown values", () => {
    const { filter } = parseFilters({ ecosystem: "npm,Nope,PyPI", category: "databases,bogus", package: "pg, redis ,pg" });
    expect(filter.ecosystems).toEqual(["npm", "PyPI"]);
    expect(filter.categories).toEqual(["databases"]);
    expect(filter.packages).toEqual(["pg", "redis"]);
  });

  it("drops invalid values instead of failing", () => {
    const parsed = parseFilters({ ecosystem: "Nope", sort: "random", type: "x", page: "999999", q: "x".repeat(500) });
    expect(parsed.filter.ecosystems).toBeUndefined();
    expect(parsed.filter.query).toBeUndefined();
    expect(parsed.sort).toBe("newest");
    expect(parsed.filter.kind).toBe("advisories");
    expect(parsed.page).toBe(1);
  });
});

describe("filterQuery", () => {
  it("leaves defaults out, so shared links stay short", () => {
    const { filter } = parseFilters({}, LIST_DEFAULTS);
    expect(filterQuery({ filter }, LIST_DEFAULTS)).toBe("");
    const exploited = parseFilters({ type: "exploited" }, LIST_DEFAULTS).filter;
    expect(filterQuery({ filter: exploited }, LIST_DEFAULTS)).toBe("?type=exploited");
  });

  it("round-trips a view through the URL", () => {
    const params = { ecosystem: "npm,PyPI", category: "web", q: "lodash", severity: "critical,high", sort: "severity", page: "2" };
    const { filter, sort, page } = parseFilters(params, LIST_DEFAULTS);
    const query = filterQuery({ filter, sort, page }, LIST_DEFAULTS);
    expect(query).toBe("?ecosystem=npm,PyPI&category=web&q=lodash&severity=critical,high&sort=severity&page=2");
    expect(parseFilters(Object.fromEntries(new URLSearchParams(query)), LIST_DEFAULTS)).toEqual({ filter, sort, page });
  });

  it("spells out severity when the defaults differ", () => {
    const { filter } = parseFilters({}, LIST_DEFAULTS);
    expect(filterQuery({ filter })).toBe("?severity=critical");
    const all = parseFilters({}).filter;
    expect(filterQuery({ filter: all }, LIST_DEFAULTS)).toBe("?severity=all");
  });
});

describe("describeFilter", () => {
  it("names a view for feed titles", () => {
    const { filter } = parseFilters({ type: "exploited", category: "databases", ecosystem: "PyPI" });
    expect(describeFilter(filter)).toBe("Known exploited · Python · Databases");
    expect(describeFilter(parseFilters({ package: "a,b,c" }).filter)).toBe("3 packages");
  });
});
