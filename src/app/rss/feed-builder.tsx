"use client";

import Link from "next/link";
import type { ReactNode } from "react";
import { CopyButton } from "@/components/copy-button";
import { useFilterForm, type FilterValues } from "@/components/filter-transition";
import { toQueryString } from "@/lib/query-string";

type Option = [value: string, label: string];

export type BuilderOptions = {
  kinds: Option[];
  severities: Option[];
  languages: Option[];
  categories: Option[];
};

// The feed has no severity default, and hides malicious packages unless asked.
const defaults = (): FilterValues => ({ type: "advisories" });

const normalize = (values: FilterValues): FilterValues => ({
  ...values,
  package: values.package
    .split(/[\s,]+/)
    .filter(Boolean)
    .join(","),
});

// Pick filters, get a feed URL. The preview below updates as filters change.
export function FeedBuilder({
  values,
  feedBase,
  options,
  children,
}: {
  values: FilterValues;
  feedBase: string;
  options: BuilderOptions;
  children: ReactNode;
}) {
  const { state, update } = useFilterForm("/rss", values, defaults, normalize);
  const query = toQueryString(normalize(state), defaults());
  const feedUrl = `${feedBase}${query}`;
  // The list page opens on critical; spell out "all" so it shows the same view.
  const listQuery = toQueryString({ ...normalize(state), severity: state.severity || "all" }, defaults());

  const toggle = (name: string, value: string, order: Option[]) =>
    update((current) => {
      const selected = new Set(current[name].split(",").filter(Boolean));
      if (selected.has(value)) selected.delete(value);
      else selected.add(value);
      return { [name]: order.map(([v]) => v).filter((v) => selected.has(v)).join(",") };
    });

  return (
    <div className="mt-6 flex flex-col gap-8">
      <section aria-labelledby="feed-url-heading" className="flex flex-col gap-3 border border-border bg-surface p-4">
        <h2 id="feed-url-heading" className="label text-muted">
          Your feed URL
        </h2>
        <div className="flex items-start gap-3">
          <input
            readOnly
            value={feedUrl}
            aria-labelledby="feed-url-heading"
            onFocus={(e) => e.currentTarget.select()}
            className="min-h-11 min-w-0 flex-1 border border-border-strong bg-background px-3 font-mono text-xs"
          />
          <CopyButton text={feedUrl} label="Copy URL" />
        </div>
        <ul className="flex flex-col gap-1 text-xs text-muted">
          <li>Feed readers: paste the URL into Feedly, NetNewsWire, Inoreader or any RSS reader.</li>
          <li>
            Slack: <code className="break-all font-mono">/feed subscribe {feedUrl}</code>
          </li>
          <li>Discord: add it with an RSS bot such as MonitoRSS.</li>
        </ul>
        <p className="text-xs text-muted">
          Anyone who sees this URL can see the filters in it. Stick to languages and categories, or public packages you
          don&apos;t mind sharing.
        </p>
      </section>

      <div className="grid grid-cols-1 gap-8 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
        <form method="get" action="/rss" onSubmit={(e) => e.preventDefault()} className="flex flex-col gap-6">
          <Group legend="Include">
            {options.kinds.map(([value, label]) => (
              <Choice
                key={value}
                type="radio"
                name="type"
                label={label}
                checked={state.type === value}
                onChange={() => update({ type: value })}
              />
            ))}
          </Group>

          <Group legend="Severity" hint="None selected means every severity. CISA's exploited entries have no score.">
            {options.severities.map(([value, label]) => (
              <Choice
                key={value}
                type="checkbox"
                name="severity"
                label={label}
                checked={state.severity.split(",").includes(value)}
                onChange={() => toggle("severity", value, options.severities)}
              />
            ))}
          </Group>

          <Group legend="Languages" hint="None selected means every language." columns>
            {options.languages.map(([value, label]) => (
              <Choice
                key={value}
                type="checkbox"
                name="ecosystem"
                label={label}
                checked={state.ecosystem.split(",").includes(value)}
                onChange={() => toggle("ecosystem", value, options.languages)}
              />
            ))}
          </Group>

          <Group legend="Categories" hint="Matched by package and product names, so a best guess." columns>
            {options.categories.map(([value, label]) => (
              <Choice
                key={value}
                type="checkbox"
                name="category"
                label={label}
                checked={state.category.split(",").includes(value)}
                onChange={() => toggle("category", value, options.categories)}
              />
            ))}
          </Group>

          <label className="flex flex-col gap-1">
            <span className="label text-muted">Packages</span>
            <input
              name="package"
              value={state.package}
              onChange={(e) => update({ package: e.target.value }, { debounce: true })}
              placeholder="Exact names, like lodash, django"
              className="min-h-11 border border-border-strong bg-surface px-3 font-mono text-sm"
            />
            <span className="text-xs text-muted">Up to 20, separated by commas.</span>
          </label>

          <label className="flex flex-col gap-1">
            <span className="label text-muted">Keyword</span>
            <input
              type="search"
              name="q"
              value={state.q}
              onChange={(e) => update({ q: e.target.value }, { debounce: true })}
              placeholder="Like log4j or wordpress"
              maxLength={100}
              className="min-h-11 border border-border-strong bg-surface px-3 font-mono text-sm"
            />
          </label>

          <noscript>
            <button type="submit" className="label min-h-11 bg-foreground px-5 text-background">
              Update
            </button>
          </noscript>
        </form>

        <section aria-labelledby="preview-heading" className="flex min-w-0 flex-col gap-2">
          <div className="flex items-end justify-between gap-4">
            <h2 id="preview-heading" className="text-sm font-semibold">
              Latest in this feed
            </h2>
            <Link href={`/vulns${listQuery}`} className="label min-h-11 content-center text-muted hover:text-foreground sm:min-h-0">
              View as list →
            </Link>
          </div>
          {children}
        </section>
      </div>
    </div>
  );
}

function Group({
  legend,
  hint,
  columns = false,
  children,
}: {
  legend: string;
  hint?: string;
  columns?: boolean;
  children: ReactNode;
}) {
  return (
    <fieldset className="flex flex-col gap-1">
      <legend className="label mb-1 text-muted">{legend}</legend>
      <div className={columns ? "grid grid-cols-1 sm:grid-cols-2" : "flex flex-col"}>{children}</div>
      {hint && <p className="text-xs text-muted">{hint}</p>}
    </fieldset>
  );
}

function Choice({
  type,
  name,
  label,
  checked,
  onChange,
}: {
  type: "radio" | "checkbox";
  name: string;
  label: string;
  checked: boolean;
  onChange: () => void;
}) {
  return (
    <label className="flex min-h-11 cursor-pointer items-center gap-3 text-sm sm:min-h-9">
      <input type={type} name={name} checked={checked} onChange={onChange} className="size-4 accent-[var(--color-brand)]" />
      {label}
    </label>
  );
}
