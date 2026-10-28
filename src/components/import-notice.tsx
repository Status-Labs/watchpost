"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { LANGUAGES } from "@/lib/ecosystems";

type Status = {
  history?: "complete" | "importing";
  importing?: { ecosystem: string; done: number; total: number; records: number } | null;
};

const POLL_MS = 3_000;

// Local app only: while the first run downloads OSV's history, say so, and
// refresh the page when it's done. Hosted builds compile this to nothing.
export function ImportNotice() {
  const router = useRouter();
  const [status, setStatus] = useState<Status | null>(null);

  useEffect(() => {
    if (!process.env.NEXT_PUBLIC_LOCAL_BUILD) return;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let wasImporting = false;
    const poll = async () => {
      try {
        const next: Status = await (await fetch("/api/status", { cache: "no-store" })).json();
        setStatus(next);
        if (next.history !== "complete") {
          wasImporting = true;
          timer = setTimeout(poll, POLL_MS);
        } else if (wasImporting) {
          router.refresh();
        }
      } catch {
        timer = setTimeout(poll, POLL_MS);
      }
    };
    poll();
    return () => clearTimeout(timer);
  }, [router]);

  if (!status || status.history === "complete") return null;
  const progress = status.importing;
  const language = progress && (LANGUAGES.find((l) => l.ecosystem === progress.ecosystem)?.label ?? progress.ecosystem);

  return (
    <div role="status" className="border-b border-border bg-surface">
      <p className="mx-auto w-full max-w-5xl px-4 py-2 text-sm text-muted">
        <span className="text-foreground">Downloading vulnerability history.</span>{" "}
        {progress
          ? `${language}: ${progress.records.toLocaleString("en-US")} advisories (${progress.done + 1} of ${progress.total}). `
          : "Starting. "}
        Checks are complete once this finishes, in a few minutes.
      </p>
    </div>
  );
}
