import { sql } from "drizzle-orm";
import { runCleanup } from "@/auth/cleanup";
import { getDb } from "@/db";
import { isAuthorizedCron } from "@/lib/auth";
import { isLocalMode } from "@/local/mode";

export const maxDuration = 120;

export async function GET(request: Request) {
  if (!isAuthorizedCron(request)) {
    return Response.json({ error: "unauthorized" }, { status: 401 });
  }
  const db = getDb();
  const result = await runCleanup(db);
  // Hosted Postgres vacuums itself; PGlite has no autovacuum.
  if (isLocalMode()) await db.execute(sql`vacuum analyze`);
  console.log("cleanup", result);
  return Response.json(result);
}
