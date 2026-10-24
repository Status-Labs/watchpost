import type { Metadata } from "next";
import { Suspense } from "react";
import { FilterTransition, PendingResults } from "@/components/filter-transition";
import { VulnList, VulnListSkeleton } from "@/components/vuln-list";
import { SEVERITIES } from "@/db/schema";
import { CATEGORIES } from "@/lib/categories";
import { LANGUAGES } from "@/lib/ecosystems";
import { describeFilter, parseFilters } from "@/lib/filters";
import { listVulnsCached } from "@/lib/cached";
import { siteUrl } from "@/lib/site";
import { KINDS } from "@/lib/vulns";
import { FeedBuilder, type BuilderOptions } from "./feed-builder";

export const metadata: Metadata = {
  title: "RSS feeds",
  description: "Build an RSS feed of new CVEs for the languages, categories and packages you use.",
  alternates: { canonical: "/rss" },
};

const PREVIEW_SIZE = 10;

const OPTIONS: BuilderOptions = {
  kinds: Object.entries(KINDS),
  severities: SEVERITIES.map((s) => [s, s[0].toUpperCase() + s.slice(1)]),
  languages: LANGUAGES.map((l) => [l.ecosystem, l.label]),
  categories: Object.entries(CATEGORIES).map(([id, c]) => [id, c.label]),
};

export default function RssPage({ searchParams }: PageProps<"/rss">) {
  return (
    <div className="mx-auto w-full max-w-5xl px-4 py-10">
      <h1 className="text-3xl font-semibold tracking-tight">RSS feeds</h1>
      <p className="mt-2 max-w-2xl text-sm text-muted">
        Pick what you want to follow and copy the feed URL into your reader, Slack or Discord. Feeds are public and need
        no sign-up: we never learn who subscribes.
      </p>
      <Suspense
        fallback={
          <div className="mt-6">
            <VulnListSkeleton rows={PREVIEW_SIZE} />
          </div>
        }
      >
        <Builder searchParams={searchParams} />
      </Suspense>
    </div>
  );
}

async function Builder({ searchParams }: Pick<PageProps<"/rss">, "searchParams">) {
  // The feed's own defaults: no severity default, unlike the list page.
  const { filter } = parseFilters(await searchParams);
  const vulns = await listVulnsCached(filter, { limit: PREVIEW_SIZE });
  const values = {
    type: filter.kind ?? "advisories",
    severity: filter.severities?.join(",") ?? "",
    ecosystem: filter.ecosystems?.join(",") ?? "",
    category: filter.categories?.join(",") ?? "",
    package: filter.packages?.join(", ") ?? "",
    q: filter.query ?? "",
  };

  return (
    <FilterTransition>
      <FeedBuilder values={values} feedBase={siteUrl("/feed.xml")} options={OPTIONS}>
        <PendingResults>
          <p className="mb-2 text-xs text-muted">{describeFilter(filter) || "All new CVEs and advisories"}</p>
          <VulnList vulns={vulns} />
        </PendingResults>
      </FeedBuilder>
    </FilterTransition>
  );
}
