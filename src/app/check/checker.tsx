"use client";

import { useState, type DragEvent } from "react";
import { SeverityBadge } from "@/components/severity";
import type { Severity } from "@/db/schema";
import { LOCKFILE_FORMATS, dedupePackages, formatForFile, sniffFormat, type ParsedPackage } from "@/lib/lockfiles";

// Everything here runs in the browser: files are parsed locally, and only the
// package names and versions are sent to /api/check.

const BATCH = 5_000;
const MAX_FILE_BYTES = 20_000_000;

type Source = { label: string; packages: ParsedPackage[] };
type Result = {
  id: string;
  aliases: string[];
  severity: Severity | null;
  ecosystem: string;
  package: string;
  version: string;
  fixed_versions: string[];
  summary: string | null;
  url: string;
};
type Outcome = { checked: number; results: Result[]; skipped: number };

export function Checker() {
  const [sources, setSources] = useState<Source[]>([]);
  const [pasted, setPasted] = useState("");
  const [problem, setProblem] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<Outcome | null>(null);
  const [busy, setBusy] = useState(false);
  const [dragging, setDragging] = useState(false);

  const packages = dedupePackages(sources.flatMap((s) => s.packages));

  function add(label: string, list: ParsedPackage[]) {
    setOutcome(null);
    if (list.length === 0) {
      setProblem(`No packages with exact versions found in ${label}.`);
      return;
    }
    setProblem(null);
    setSources((current) => [...current, { label, packages: list }]);
  }

  async function addFiles(files: FileList | File[]) {
    for (const file of Array.from(files)) {
      const format = formatForFile(file.name);
      if (!format) {
        setProblem(
          file.name === "package.json"
            ? "package.json only has version ranges. Drop package-lock.json, pnpm-lock.yaml or yarn.lock instead."
            : `${file.name} isn't a supported lockfile.`,
        );
        continue;
      }
      if (file.size > MAX_FILE_BYTES) {
        setProblem(`${file.name} is too large.`);
        continue;
      }
      try {
        add(file.name, format.parse(await file.text()));
      } catch {
        setProblem(`Couldn't read ${file.name}. Is it a valid ${format.label}?`);
      }
    }
  }

  function addPasted() {
    const format = sniffFormat(pasted);
    try {
      add(format.id === "list" ? "pasted list" : `pasted ${format.label}`, format.parse(pasted));
      setPasted("");
    } catch {
      setProblem(`Couldn't read the pasted text as ${format.label}.`);
    }
  }

  async function check() {
    setBusy(true);
    setProblem(null);
    try {
      const merged: Outcome = { checked: 0, results: [], skipped: 0 };
      for (let i = 0; i < packages.length; i += BATCH) {
        const res = await fetch("/api/check", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ packages: packages.slice(i, i + BATCH) }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error ?? "The check failed.");
        merged.checked += data.checked;
        merged.results.push(...data.results);
        merged.skipped += data.rejected.length;
      }
      setOutcome(merged);
    } catch (error) {
      setProblem(error instanceof Error ? error.message : "The check failed. Try again.");
    } finally {
      setBusy(false);
    }
  }

  function onDrop(event: DragEvent) {
    event.preventDefault();
    setDragging(false);
    void addFiles(event.dataTransfer.files);
  }

  return (
    <div className="flex flex-col gap-6">
      <label
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        className={`flex min-h-36 cursor-pointer flex-col items-center justify-center gap-2 border-2 border-dashed p-6 text-center ${
          dragging ? "border-foreground bg-surface" : "border-border-strong"
        }`}
      >
        <span className="text-sm font-semibold">Drop lockfiles here, or choose files</span>
        <span className="text-xs text-muted">
          {LOCKFILE_FORMATS.filter((f) => f.id !== "list").map((f) => f.label).join(", ")}
        </span>
        <input type="file" multiple className="sr-only" onChange={(e) => e.target.files && addFiles(e.target.files)} />
      </label>

      <div className="flex flex-col gap-2">
        <label htmlFor="paste" className="label text-muted">
          Or paste a lockfile, pip freeze output, or a list like &ldquo;npm lodash 4.17.21&rdquo;
        </label>
        <textarea
          id="paste"
          value={pasted}
          onChange={(e) => setPasted(e.target.value)}
          rows={5}
          spellCheck={false}
          className="border border-border-strong bg-surface p-3 font-mono text-xs"
        />
        <button
          type="button"
          onClick={addPasted}
          disabled={!pasted.trim()}
          className="label min-h-11 self-start border border-foreground px-4 disabled:opacity-50"
        >
          Add
        </button>
      </div>

      {problem && (
        <p role="alert" className="border border-severity-critical px-4 py-3 text-sm">
          {problem}
        </p>
      )}

      {sources.length > 0 && (
        <div className="flex flex-col gap-3 border border-border bg-surface p-4">
          <ul className="flex flex-col gap-1 text-sm">
            {sources.map((s, i) => (
              <li key={i} className="flex items-center justify-between gap-3">
                <span className="min-w-0 truncate">
                  <span className="font-mono text-xs">{s.label}</span>{" "}
                  <span className="text-muted">· {s.packages.length} packages</span>
                </span>
                <button
                  type="button"
                  onClick={() => {
                    setOutcome(null);
                    setSources((current) => current.filter((_, j) => j !== i));
                  }}
                  className="label min-h-11 shrink-0 text-muted hover:text-foreground"
                  aria-label={`Remove ${s.label}`}
                >
                  Remove
                </button>
              </li>
            ))}
          </ul>
          <button
            type="button"
            onClick={check}
            disabled={busy}
            className="label min-h-11 bg-foreground px-5 text-background disabled:opacity-60"
          >
            {busy ? "Checking…" : `Check ${packages.length} ${packages.length === 1 ? "package" : "packages"}`}
          </button>
        </div>
      )}

      {outcome && <Results outcome={outcome} />}
    </div>
  );
}

function Results({ outcome }: { outcome: Outcome }) {
  const { checked, results, skipped } = outcome;
  const packages = `${checked} ${checked === 1 ? "package" : "packages"}`;
  return (
    <section aria-live="polite" className="flex flex-col gap-3">
      <h2 className="text-lg font-semibold">
        {results.length
          ? `${results.length} known ${results.length === 1 ? "vulnerability" : "vulnerabilities"} in ${packages}`
          : `No known vulnerabilities in ${packages}`}
      </h2>
      {skipped > 0 && (
        <p className="text-xs text-muted">Skipped {skipped} entries that didn&apos;t look like public package names and versions.</p>
      )}
      {results.length > 0 && (
        <ul className="divide-y divide-border border border-border bg-surface">
          {results.map((r) => (
            <li key={`${r.id}/${r.ecosystem}/${r.package}/${r.version}`} className="flex flex-col gap-1.5 px-4 py-3">
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                <SeverityBadge severity={r.severity} />
                <span className="break-all font-mono text-sm">
                  {r.ecosystem}/{r.package}@{r.version}
                </span>
              </div>
              {/* Advisory text is upstream data, rendered as plain text. */}
              {r.summary && <p className="text-sm text-muted">{r.summary}</p>}
              <div className="flex flex-wrap gap-x-4 gap-y-1 font-mono text-xs">
                <a href={r.url} className="underline">
                  {r.id}
                </a>
                {r.aliases.map((a) => (
                  <span key={a} className="text-muted">
                    {a}
                  </span>
                ))}
                <span>{r.fixed_versions.length ? `Fixed in ${r.fixed_versions.join(", ")}` : "No fix listed"}</span>
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
