"use client";

import { useRouter } from "next/navigation";
import { createContext, use, useEffect, useRef, useState, useTransition, type ReactNode } from "react";
import { toQueryString } from "@/lib/query-string";

// Filters update the URL as they change, and the server renders the matching
// results. While that happens the current results stay on screen, dimmed.
type FilterNavigation = { navigate: (href: string) => void; isPending: boolean };

const FilterContext = createContext<FilterNavigation>({ navigate: () => {}, isPending: false });

export function FilterTransition({ children }: { children: ReactNode }) {
  const router = useRouter();
  const [isPending, startTransition] = useTransition();
  const navigate = (href: string) => startTransition(() => router.replace(href, { scroll: false }));
  return <FilterContext value={{ navigate, isPending }}>{children}</FilterContext>;
}

export function useFilterNavigation(): FilterNavigation {
  return use(FilterContext);
}

export function PendingResults({ children, className = "" }: { children: ReactNode; className?: string }) {
  const { isPending } = useFilterNavigation();
  return (
    <div aria-busy={isPending} className={`transition-opacity ${isPending ? "opacity-50" : ""} ${className}`}>
      <p role="status" className="sr-only">
        {isPending ? "Updating results" : ""}
      </p>
      {children}
    </div>
  );
}

export type FilterValues = Record<string, string>;

// Form state for a set of filters. Selects and checkboxes navigate right away;
// text fields wait until typing pauses. When the URL changes some other way
// (back and forward buttons), the form follows it.
export function useFilterForm(
  basePath: string,
  values: FilterValues,
  defaultsFor: (values: FilterValues) => FilterValues,
  // Tidies values for the URL, like "pg, redis" to "pg,redis".
  normalize: (values: FilterValues) => FilterValues = (v) => v,
) {
  const { navigate } = useFilterNavigation();
  const incoming = toQueryString(normalize(values), defaultsFor(values));
  const [state, setState] = useState(values);
  const [seen, setSeen] = useState(incoming);
  const [sent, setSent] = useState(incoming);
  if (incoming !== seen) {
    setSeen(incoming);
    if (incoming !== sent) {
      setState(values);
      setSent(incoming);
    }
  }

  const timer = useRef<ReturnType<typeof setTimeout>>(undefined);
  useEffect(() => () => clearTimeout(timer.current), []);
  // The newest values, so changes made before a re-render build on each other.
  const latest = useRef(state);
  useEffect(() => {
    latest.current = state;
  }, [state]);

  function update(changes: FilterValues | ((current: FilterValues) => FilterValues), { debounce = false } = {}) {
    const next = { ...latest.current, ...(typeof changes === "function" ? changes(latest.current) : changes) };
    latest.current = next;
    setState(next);
    clearTimeout(timer.current);
    const go = () => {
      const query = toQueryString(normalize(next), defaultsFor(next));
      setSent(query);
      navigate(`${basePath}${query}`);
    };
    if (debounce) timer.current = setTimeout(go, 350);
    else go();
  }

  return { state, update };
}
