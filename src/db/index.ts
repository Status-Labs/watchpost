import path from "node:path";
import { PGlite } from "@electric-sql/pglite";
import { attachDatabasePool } from "@vercel/functions";
import type { SQL } from "drizzle-orm";
import { drizzle as drizzlePg } from "drizzle-orm/node-postgres";
import type { PgDatabase, PgQueryResultHKT } from "drizzle-orm/pg-core";
import { drizzle as drizzlePglite } from "drizzle-orm/pglite";
import { Pool } from "pg";
import { dataDir, isLocalMode } from "@/local/mode";
import * as schema from "./schema";

// Hosted deploys use Postgres (Neon); local mode uses PGlite. Both run the same
// schema and queries.
export type Db = PgDatabase<PgQueryResultHKT, typeof schema>;

const globalForDb = globalThis as unknown as { pool?: Pool; pglite?: PGlite };

function createPool(): Pool {
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) throw new Error("DATABASE_URL is not set");
  const pool = new Pool({ connectionString, max: 5 });
  // Lets Vercel close idle connections before a function instance is suspended.
  attachDatabasePool(pool);
  return pool;
}

export function createDb(pool: Pool): Db {
  return drizzlePg(pool, { schema });
}

// An in-memory PGlite when no folder is given, for tests.
export function createPgliteDb(client: PGlite): Db {
  return drizzlePglite(client, { schema });
}

let db: Db | undefined;

// Created lazily so builds and imports never open a connection.
export function getDb(): Db {
  if (!db) {
    if (isLocalMode()) {
      globalForDb.pglite ??= new PGlite(path.join(dataDir(), "db"));
      db = createPgliteDb(globalForDb.pglite);
    } else {
      globalForDb.pool ??= createPool();
      db = createDb(globalForDb.pool);
    }
  }
  return db;
}

// Rows of a raw query. Both drivers return { rows }.
export async function queryRows<T>(db: Db, query: SQL): Promise<T[]> {
  const result = (await db.execute(query)) as unknown as { rows: T[] };
  return result.rows;
}
