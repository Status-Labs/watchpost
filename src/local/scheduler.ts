import { siteUrl } from "@/lib/site";

// Local mode has no Vercel Cron, so the app calls its own cron routes on a
// timer while it runs. Going through the routes (rather than calling the sync
// functions directly) lets them refresh cached pages, which only works inside
// a request.

const OSV_EVERY_MS = 15 * 60_000;
const KEV_EVERY_MS = 60 * 60_000;
// Also vacuums the database (PGlite has no autovacuum).
const CLEANUP_EVERY_MS = 24 * 60 * 60_000;
const STARTUP_DELAY_MS = 1_000;
const STARTUP_ATTEMPTS = 60;
// One OSV run handles up to 500 changes; a machine that slept for days catches
// up in a few runs.
const MAX_CATCH_UP_RUNS = 40;
const IMPORT_POLL_MS = 5_000;

const globalForScheduler = globalThis as unknown as { watchpostScheduler?: boolean };

export function startScheduler() {
  // Dev reloads re-run instrumentation; keep one scheduler per process.
  if (globalForScheduler.watchpostScheduler) return;
  globalForScheduler.watchpostScheduler = true;

  setTimeout(async () => {
    await waitForServer();
    await run("/api/cron/sync-kev");
    await syncOsv();
    setInterval(syncOsv, OSV_EVERY_MS).unref();
    setInterval(() => run("/api/cron/sync-kev"), KEV_EVERY_MS).unref();
    setInterval(() => run("/api/cron/cleanup"), CLEANUP_EVERY_MS).unref();
  }, STARTUP_DELAY_MS).unref();
}

// The server starts listening after instrumentation finishes.
async function waitForServer() {
  for (let i = 0; i < STARTUP_ATTEMPTS; i++) {
    try {
      if ((await fetch(siteUrl("/api/status"), { cache: "no-store" })).ok) return;
    } catch {
      // Not listening yet.
    }
    await new Promise((resolve) => setTimeout(resolve, STARTUP_DELAY_MS));
  }
}

// Starts the first-run import and waits for it. A no-op once the full history is in.
async function importHistory() {
  while (true) {
    const result = await run("/api/cron/import-osv");
    if (!result || !result.running) return;
    await new Promise((resolve) => setTimeout(resolve, IMPORT_POLL_MS));
  }
}

let syncing = false;

// A failed import is retried on the next tick. A tick that comes while the
// last one is still running (a long first import) is skipped.
async function syncOsv() {
  if (syncing) return;
  syncing = true;
  try {
    await importHistory();
    for (let i = 0; i < MAX_CATCH_UP_RUNS; i++) {
      const result = await run("/api/cron/sync-osv");
      if (!result || !(Number(result.remaining) > 0)) return;
    }
  } finally {
    syncing = false;
  }
}

async function run(path: string): Promise<Record<string, unknown> | null> {
  try {
    const res = await fetch(siteUrl(path), {
      headers: { authorization: `Bearer ${process.env.CRON_SECRET}` },
      cache: "no-store",
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${(await res.text()).slice(0, 300)}`);
    return (await res.json()) as Record<string, unknown>;
  } catch (error) {
    // The next tick tries again.
    console.error(`${path} failed: ${String(error)}`);
    return null;
  }
}
