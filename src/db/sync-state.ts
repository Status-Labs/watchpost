import { eq } from "drizzle-orm";
import type { Db } from "./index";
import { syncState } from "./schema";

export async function loadSyncState(db: Db, source: string) {
  const [state] = await db.select().from(syncState).where(eq(syncState.source, source));
  return state ?? null;
}

// Records a run. A successful run (no error) also updates last_success_at,
// which is what the staleness alert watches.
export async function saveSyncState(
  db: Db,
  { source, cursor, now, error }: { source: string; cursor: string; now: Date; error: string | null },
) {
  const success = error === null ? { lastSuccessAt: now } : {};
  await db
    .insert(syncState)
    .values({ source, cursor, lastRunAt: now, lastError: error, ...success })
    .onConflictDoUpdate({
      target: syncState.source,
      set: { cursor, lastRunAt: now, lastError: error, ...success },
    });
}
