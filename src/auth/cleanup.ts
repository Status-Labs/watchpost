import { and, eq, isNotNull, lt, notExists, or, sql } from "drizzle-orm";
import type { Db } from "@/db";
import { authCodes, oauthClients, tokens, workspaces } from "@/db/schema";

const DAY_MS = 24 * 60 * 60_000;
export const IDLE_WORKSPACE_DAYS = 90;
// Used refresh tokens are kept a while so reusing one still revokes its grant.
const ROTATED_REFRESH_KEEP_DAYS = 7;
// Sign-ins that never finished leave clients and empty workspaces behind.
const ABANDONED_AFTER_DAYS = 1;

export type CleanupResult = {
  idleWorkspaces: number;
  unreachableWorkspaces: number;
  codes: number;
  tokens: number;
  clients: number;
};

// Runs daily. Deleting a workspace cascades to its stacks, matches and tokens.
export async function runCleanup(db: Db, now = new Date()): Promise<CleanupResult> {
  const daysAgo = (days: number) => new Date(now.getTime() - days * DAY_MS);

  const idle = await db
    .delete(workspaces)
    .where(lt(workspaces.lastActiveAt, daysAgo(IDLE_WORKSPACE_DAYS)))
    .returning({ id: workspaces.id });

  const codes = await db.delete(authCodes).where(lt(authCodes.expiresAt, now)).returning({ hash: authCodes.codeHash });

  const expired = await db
    .delete(tokens)
    .where(
      or(
        lt(tokens.expiresAt, now),
        and(isNotNull(tokens.rotatedAt), lt(tokens.rotatedAt, daysAgo(ROTATED_REFRESH_KEEP_DAYS))),
      ),
    )
    .returning({ hash: tokens.hash });

  // No token or code left means nobody can ever reach the workspace again.
  const unreachable = await db
    .delete(workspaces)
    .where(
      and(
        lt(workspaces.createdAt, daysAgo(ABANDONED_AFTER_DAYS)),
        notExists(db.select({ one: sql`1` }).from(tokens).where(eq(tokens.workspaceId, workspaces.id))),
        notExists(db.select({ one: sql`1` }).from(authCodes).where(eq(authCodes.workspaceId, workspaces.id))),
      ),
    )
    .returning({ id: workspaces.id });

  const clients = await db
    .delete(oauthClients)
    .where(
      and(
        lt(oauthClients.createdAt, daysAgo(ABANDONED_AFTER_DAYS)),
        notExists(db.select({ one: sql`1` }).from(tokens).where(eq(tokens.clientId, oauthClients.id))),
        notExists(db.select({ one: sql`1` }).from(authCodes).where(eq(authCodes.clientId, oauthClients.id))),
      ),
    )
    .returning({ id: oauthClients.id });

  return {
    idleWorkspaces: idle.length,
    unreachableWorkspaces: unreachable.length,
    codes: codes.length,
    tokens: expired.length,
    clients: clients.length,
  };
}
