import { revalidateTag } from "next/cache";
import { connection } from "next/server";
import { getDb } from "@/db";
import { VULNS_TAG } from "@/lib/cached";
import { isAuthorizedCron } from "@/lib/auth";
import { importComplete } from "@/local/archive";
import { isLocalMode } from "@/local/mode";
import { importProgress, pollImport } from "@/local/status";

// Local mode only: downloads OSV's full history on the first run. The import
// runs in the background; call again to check on it.
export async function GET(request: Request) {
  // Decided per request; without this the build would prerender the 404.
  await connection();
  if (!isLocalMode()) return new Response(null, { status: 404 });
  if (!isAuthorizedCron(request)) {
    return Response.json({ error: "unauthorized" }, { status: 401 });
  }

  const db = getDb();
  // Collect a finished run's outcome before deciding there's nothing to do.
  const outcome = pollImport(db, { start: !(await importComplete(db)) });
  if (outcome === null) return Response.json({ done: true });
  if (outcome === "running") return Response.json({ running: true, progress: importProgress() }, { status: 202 });
  if ("error" in outcome) return Response.json(outcome, { status: 500 });
  // Cached pages refresh on their next visit.
  revalidateTag(VULNS_TAG, "max");
  console.log("osv import", outcome);
  return Response.json({ done: true, ...outcome });
}
