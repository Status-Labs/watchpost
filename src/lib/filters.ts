import { z } from "zod";
import { SEVERITIES, type Severity } from "@/db/schema";
import { SYNCED_ECOSYSTEMS } from "@/osv/sync";
import { CATEGORIES, isCategory, type CategoryId } from "./categories";
import { LANGUAGES } from "./ecosystems";
import { toQueryString } from "./query-string";
import { KINDS, MAX_PAGE, MAX_QUERY_LENGTH, SORTS, type Kind, type Sort, type VulnFilter } from "./vulns";

const single = (value: unknown) => (Array.isArray(value) ? value[0] : value);
const blankToUndefined = (value: unknown) => {
  const v = single(value);
  return typeof v === "string" && v.trim() !== "" ? v.trim() : undefined;
};

// Without JavaScript, checkboxes submit a name once per value; read them as one list.
const joined = (value: unknown) => (Array.isArray(value) ? value.join(",") : value);

const ALL = "all";
export const MAX_PACKAGES = 20;

// A comma-separated list, keeping only the values that pass `keep`.
const list = <T extends string>(keep: (value: string) => value is T, max: number) =>
  z.preprocess(
    (value) => {
      const items = blankToUndefined(joined(value))
        ?.split(",")
        .map((s) => s.trim())
        .filter(keep);
      return items?.length ? [...new Set(items)].slice(0, max) : undefined;
    },
    z.array(z.string()).optional().catch(undefined),
  ) as z.ZodType<T[] | undefined>;

const isEcosystem = (value: string): value is string => SYNCED_ECOSYSTEMS.has(value);
const isPackageName = (value: string): value is string => value.length <= 214 && /^[^\u0000-\u001f\u007f\s]+$/.test(value);
const isSeverity = (value: string): value is Severity => (SEVERITIES as readonly string[]).includes(value);

// What a URL without a given parameter means. The list page opens on critical
// advisories; the RSS feed has no severity default.
export type FilterDefaults = { severities?: Severity[] };
export const LIST_DEFAULTS: FilterDefaults = { severities: ["critical"] };

// CISA publishes no severity scores, so a severity default would hide most of
// the exploited list.
function severityDefault(kind: Kind | undefined, defaults: FilterDefaults): Severity[] | undefined {
  return kind === "exploited" ? undefined : defaults.severities;
}

// Query string filters shared by the CVE list page, the RSS builder and the
// public RSS feed. Invalid values are dropped rather than rejected, so a bad
// link still works.
const filterSchema = z.object({
  ecosystem: list(isEcosystem, SYNCED_ECOSYSTEMS.size),
  category: list((value): value is CategoryId => isCategory(value), 20),
  package: list(isPackageName, MAX_PACKAGES),
  q: z.preprocess(
    blankToUndefined,
    z.string().max(MAX_QUERY_LENGTH).regex(/^[^\u0000-\u001f\u007f]+$/).optional().catch(undefined),
  ),
  // Comma-separated, like "critical,high", or "all". Unknown values are ignored.
  severity: z.preprocess(
    (value) => {
      const text = blankToUndefined(joined(value));
      if (text === ALL) return ALL;
      const severities = text?.split(",").filter(isSeverity);
      return severities?.length ? severities : undefined;
    },
    z.union([z.literal(ALL), z.array(z.enum(SEVERITIES))]).optional().catch(undefined),
  ),
  // Malicious-package reports are hidden by default; they would bury real advisories.
  type: z.preprocess(single, z.enum(Object.keys(KINDS) as [Kind, ...Kind[]]).catch("advisories")),
  sort: z.preprocess(single, z.enum(Object.keys(SORTS) as [Sort, ...Sort[]]).catch("newest")),
  page: z.preprocess(single, z.coerce.number().int().min(1).max(MAX_PAGE).catch(1)),
});

export type ParsedFilters = { filter: VulnFilter; sort: Sort; page: number };

export function parseFilters(params: Record<string, unknown>, defaults: FilterDefaults = {}): ParsedFilters {
  const parsed = filterSchema.parse({
    ecosystem: params.ecosystem,
    category: params.category,
    package: params.package,
    q: params.q,
    severity: params.severity,
    type: params.type ?? "advisories",
    sort: params.sort ?? "newest",
    page: params.page ?? 1,
  });
  return {
    filter: {
      ecosystems: parsed.ecosystem,
      categories: parsed.category,
      packages: parsed.package,
      query: parsed.q,
      severities: parsed.severity === ALL ? undefined : (parsed.severity ?? severityDefault(parsed.type, defaults)),
      kind: parsed.type,
    },
    sort: parsed.sort,
    page: parsed.page,
  };
}

// The query parameters for a view, with values equal to the defaults left out.
export function filterParams(
  { filter, sort = "newest", page }: { filter: VulnFilter; sort?: Sort; page?: number },
  defaults: FilterDefaults = {},
): URLSearchParams {
  const query = new URLSearchParams();
  if (filter.kind && filter.kind !== "advisories") query.set("type", filter.kind);
  if (filter.ecosystems?.length) query.set("ecosystem", filter.ecosystems.join(","));
  if (filter.categories?.length) query.set("category", filter.categories.join(","));
  if (filter.packages?.length) query.set("package", filter.packages.join(","));
  if (filter.query) query.set("q", filter.query);
  const severity = severityParam(filter.severities);
  if (severity !== severityParam(severityDefault(filter.kind, defaults))) query.set("severity", severity);
  if (sort !== "newest") query.set("sort", sort);
  if (page && page > 1) query.set("page", String(page));
  return query;
}

// Builds the shortest query string for a view.
export function filterQuery(view: { filter: VulnFilter; sort?: Sort; page?: number }, defaults: FilterDefaults = {}): string {
  return toQueryString(filterParams(view, defaults));
}

export function severityParam(severities: Severity[] | undefined): string {
  return severities?.length ? severities.join(",") : ALL;
}


const KIND_TITLES: Record<Kind, string | undefined> = {
  advisories: undefined,
  exploited: "Known exploited",
  packages: "Package advisories",
  malware: "Malicious packages",
  all: undefined,
};

// A short title for a view, like "Known exploited · Databases · Python".
export function describeFilter(filter: VulnFilter): string {
  // Two names fit in a title; more become a count.
  const names = (values: string[] | undefined, noun: string, label: (value: string) => string = (v) => v) =>
    values?.length ? (values.length > 2 ? `${values.length} ${noun}` : values.map(label).join(", ")) : undefined;
  return [
    filter.kind ? KIND_TITLES[filter.kind] : undefined,
    filter.severities?.length ? filter.severities.map((s) => s[0].toUpperCase() + s.slice(1)).join(", ") : undefined,
    names(filter.ecosystems, "languages", (e) => LANGUAGES.find((l) => l.ecosystem === e)?.label.replace(/ \(.*\)$/, "") ?? e),
    names(filter.categories, "categories", (c) => (isCategory(c) ? CATEGORIES[c].label : c)),
    names(filter.packages, "packages"),
    filter.query ? `“${filter.query}”` : undefined,
  ]
    .filter(Boolean)
    .join(" · ");
}
