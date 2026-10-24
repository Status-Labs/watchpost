import type { Metadata } from "next";
import Link from "next/link";
import { Suspense } from "react";
import { FilterTransition, PendingResults } from "@/components/filter-transition";
import { VulnList, VulnListSkeleton } from "@/components/vuln-list";
import { CATEGORIES } from "@/lib/categories";
import { LANGUAGES } from "@/lib/ecosystems";
import { LIST_DEFAULTS, filterQuery, parseFilters, severityParam } from "@/lib/filters";
import { listVulnsCached } from "@/lib/cached";
import { KINDS, MAX_PAGE, PAGE_SIZE, SORTS, type VulnFilter } from "@/lib/vulns";
import { VulnFilters, type FilterOptions } from "./vuln-filters";

export const metadata: Metadata = {
  title: "Vulnerabilities",
  description: "The latest CVEs, open source package advisories and known exploited vulnerabilities.",
  alternates: { canonical: "/vulns" },
};

const SEVERITY_OPTIONS: [string, string][] = [
  ["critical", "Critical"],
  ["critical,high", "Critical and high"],
  ["high", "High"],
  ["medium", "Medium"],
  ["low", "Low"],
  ["all", "All severities"],
];

const OPTIONS: FilterOptions = {
  kinds: Object.entries(KINDS),
  languages: LANGUAGES.map((l) => [l.ecosystem, l.label]),
  categories: Object.entries(CATEGORIES).map(([id, c]) => [id, c.label]),
  severities: SEVERITY_OPTIONS,
  sorts: Object.entries(SORTS),
};

export default function VulnsPage({ searchParams }: PageProps<"/vulns">) {
  return (
    <div className="mx-auto w-full max-w-5xl px-4 py-10">
      <h1 className="text-3xl font-semibold tracking-tight">Vulnerabilities</h1>
      <p className="mt-2 text-sm text-muted">
        Open source package advisories from OSV and known exploited vulnerabilities from CISA, updated every 15 minutes.
        Shows critical by default.
      </p>
      <Suspense
        fallback={
          <div className="mt-6">
            <VulnListSkeleton />
          </div>
        }
      >
        <FilteredVulns searchParams={searchParams} />
      </Suspense>
    </div>
  );
}

// The form's values for a view, with the list's defaults filled in.
function formValues(filter: VulnFilter, sort?: string) {
  return {
    q: filter.query ?? "",
    type: filter.kind ?? "advisories",
    ecosystem: filter.ecosystems?.join(",") ?? "",
    category: filter.categories?.join(",") ?? "",
    severity: severityParam(filter.severities),
    sort: sort ?? "newest",
  };
}

async function FilteredVulns({ searchParams }: Pick<PageProps<"/vulns">, "searchParams">) {
  const { filter, sort, page } = parseFilters(await searchParams, LIST_DEFAULTS);
  const pageLink = (target: number) => `/vulns${filterQuery({ filter, sort, page: target }, LIST_DEFAULTS)}`;
  // Fetch one extra row to know whether a next page exists.
  const rows = await listVulnsCached(filter, { page, limit: PAGE_SIZE + 1, sort });
  const vulns = rows.slice(0, PAGE_SIZE);
  const hasNext = rows.length > PAGE_SIZE && page < MAX_PAGE;

  return (
    <FilterTransition>
      <VulnFilters values={formValues(filter, sort)} options={OPTIONS} />

      <PendingResults className="mt-6">
        <VulnList vulns={vulns} />
        {vulns.length === 0 && filter.kind === "exploited" && filter.severities?.length ? (
          <p className="mt-3 text-sm text-muted">
            CISA doesn&apos;t publish severity scores. Choose &quot;All severities&quot; to see every exploited CVE.
          </p>
        ) : null}
      </PendingResults>

      <nav className="mt-6 flex items-center justify-between gap-3" aria-label="Pagination">
        {page > 1 ? (
          <Link href={pageLink(page - 1)} className="label min-h-11 content-center border border-foreground px-4">
            ← Newer
          </Link>
        ) : (
          <span />
        )}
        <Link href={`/rss${filterQuery({ filter })}`} className="label min-h-11 content-center text-muted hover:text-foreground">
          RSS for this view
        </Link>
        {hasNext ? (
          <Link href={pageLink(page + 1)} className="label min-h-11 content-center border border-foreground px-4">
            Older →
          </Link>
        ) : (
          <span />
        )}
      </nav>
    </FilterTransition>
  );
}
