"use client";

import { useFilterForm, type FilterValues } from "@/components/filter-transition";

export type Option = [value: string, label: string];

export type FilterOptions = {
  kinds: Option[];
  languages: Option[];
  categories: Option[];
  severities: Option[];
  sorts: Option[];
};

// The list's defaults. CISA publishes no severity scores, so the exploited
// view shows every severity unless asked otherwise.
export function listDefaults(values: FilterValues): FilterValues {
  return { type: "advisories", sort: "newest", severity: values.type === "exploited" ? "all" : "critical" };
}

const field = "min-h-11 w-full border border-border-strong bg-surface px-3 text-sm";

// Filters apply as they change: selects right away, the search box once typing
// pauses. Without JavaScript it's a plain GET form with an Apply button.
export function VulnFilters({ values, options }: { values: FilterValues; options: FilterOptions }) {
  const { state, update } = useFilterForm("/vulns", values, listDefaults);

  // Entering or leaving the exploited view resets severity to that view's default.
  const changeType = (type: string) =>
    update((current) => ({
      type,
      severity: type === "exploited" || current.type === "exploited" ? listDefaults({ type }).severity : current.severity,
    }));

  return (
    <form method="get" action="/vulns" onSubmit={(e) => {
        e.preventDefault();
        update({});
      }} className="mt-6 flex flex-col gap-3">
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-[1fr_auto]">
        <label className="flex flex-col gap-1">
          <span className="label text-muted">Search</span>
          <input
            type="search"
            name="q"
            value={state.q}
            onChange={(e) => update({ q: e.target.value }, { debounce: true })}
            placeholder="CVE ID, package or keyword"
            maxLength={100}
            className={`${field} font-mono`}
          />
        </label>
        <Select label="Show" name="type" value={state.type} options={options.kinds} onChange={changeType} />
      </div>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Select
          label="Language"
          name="ecosystem"
          value={state.ecosystem}
          options={withCurrent([["", "All languages"], ...options.languages], state.ecosystem, "languages")}
          onChange={(ecosystem) => update({ ecosystem })}
        />
        <Select
          label="Category"
          name="category"
          value={state.category}
          options={withCurrent([["", "All categories"], ...options.categories], state.category, "categories")}
          onChange={(category) => update({ category })}
        />
        <Select
          label="Severity"
          name="severity"
          value={state.severity}
          options={withCurrent(options.severities, state.severity, "severities")}
          onChange={(severity) => update({ severity })}
        />
        <Select label="Sort" name="sort" value={state.sort} options={options.sorts} onChange={(sort) => update({ sort })} />
      </div>
      <noscript>
        <button type="submit" className="label min-h-11 bg-foreground px-5 text-background">
          Apply
        </button>
      </noscript>
    </form>
  );
}

// A link from the RSS builder can combine several values the select doesn't list.
function withCurrent(options: Option[], value: string, noun: string): Option[] {
  if (options.some(([v]) => v === value)) return options;
  const count = value.split(",").length;
  return [[value, count > 1 ? `${count} ${noun}` : value], ...options];
}

function Select({
  label,
  name,
  value,
  options,
  onChange,
}: {
  label: string;
  name: string;
  value: string;
  options: Option[];
  onChange: (value: string) => void;
}) {
  return (
    <label className="flex min-w-0 flex-col gap-1">
      <span className="label text-muted">{label}</span>
      <select name={name} value={value} onChange={(e) => onChange(e.target.value)} className={field}>
        {options.map(([v, text]) => (
          <option key={v} value={v}>
            {text}
          </option>
        ))}
      </select>
    </label>
  );
}
