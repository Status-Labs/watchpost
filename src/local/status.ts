import type { Db } from "@/db";
import { importArchives, type ArchiveProgress } from "./archive";

// The first-run import outlives any one request, so it runs as a job in the
// server process. The import route starts it and reports on it; the home page
// shows its progress.

type ImportJob = {
  running: boolean;
  progress: ArchiveProgress | null;
  // Set when a run ends, until the next status call reports it.
  finished: { imported: number; skipped: number } | { error: string } | null;
};

const globalForJob = globalThis as unknown as { watchpostImport?: ImportJob };

function job(): ImportJob {
  globalForJob.watchpostImport ??= { running: false, progress: null, finished: null };
  return globalForJob.watchpostImport;
}

export function importProgress(): ArchiveProgress | null {
  return job().running ? job().progress : null;
}

// Returns the outcome of a run that ended since the last call (once), or
// "running". Otherwise starts a run if `start` is set, or returns null.
export function pollImport(db: Db, { start }: { start: boolean }): ImportJob["finished"] | "running" {
  const current = job();
  if (current.finished) {
    const finished = current.finished;
    current.finished = null;
    return finished;
  }
  if (current.running) return "running";
  if (!start) return null;

  current.running = true;
  importArchives({ db, onProgress: (progress) => (current.progress = progress) })
    .then((result) => (current.finished = result))
    .catch((error) => (current.finished = { error: String(error).slice(0, 500) }))
    .finally(() => {
      current.running = false;
      current.progress = null;
    });
  return "running";
}
