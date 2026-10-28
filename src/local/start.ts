import path from "node:path";
import type { PgliteDatabase } from "drizzle-orm/pglite";
import { migrate } from "drizzle-orm/pglite/migrator";
import { getDb } from "@/db";
import { startScheduler } from "./scheduler";

// Runs once when the local app starts, before it serves requests.
export async function startLocal() {
  if (!process.env.CRON_SECRET) throw new Error("CRON_SECRET is not set");
  await migrate(getDb() as unknown as PgliteDatabase, { migrationsFolder: path.join(process.cwd(), "drizzle") });
  startScheduler();
}
