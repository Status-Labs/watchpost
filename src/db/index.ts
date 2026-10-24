import { attachDatabasePool } from "@vercel/functions";
import { drizzle, type NodePgDatabase } from "drizzle-orm/node-postgres";
import { Pool } from "pg";
import * as schema from "./schema";

export type Db = NodePgDatabase<typeof schema>;

const globalForDb = globalThis as unknown as { pool?: Pool };

function createPool(): Pool {
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) throw new Error("DATABASE_URL is not set");
  const pool = new Pool({ connectionString, max: 5 });
  // Lets Vercel close idle connections before a function instance is suspended.
  attachDatabasePool(pool);
  return pool;
}

export function createDb(pool: Pool): Db {
  return drizzle(pool, { schema });
}

let db: Db | undefined;

// Created lazily so builds and imports never open a connection.
export function getDb(): Db {
  if (!db) {
    globalForDb.pool ??= createPool();
    db = createDb(globalForDb.pool);
  }
  return db;
}
