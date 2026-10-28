import { connection } from "next/server";
import { getDb } from "@/db";
import { syncState } from "@/db/schema";
import { importComplete } from "@/local/archive";
import { isLocalMode } from "@/local/mode";
import { importProgress } from "@/local/status";

// Public sync health: when each source last synced. The local CLI also uses it
// to tell a running Watchpost apart from another app on the same port.
export async function GET() {
  await connection();
  const db = getDb();
  const rows = await db.select().from(syncState);
  const lastSync = (source: string) => rows.find((r) => r.source === source)?.lastSuccessAt?.toISOString() ?? null;
  const local = isLocalMode();

  return Response.json(
    {
      // A fixed identifier, not the configurable site name.
      app: "watchpost",
      local,
      osv: lastSync("osv"),
      kev: lastSync("kev"),
      ...(local ? { history: (await importComplete(db)) ? "complete" : "importing", importing: importProgress() } : {}),
    },
    { headers: { "Cache-Control": "no-store" } },
  );
}
