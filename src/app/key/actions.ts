"use server";

import { createWorkspaceWithKey } from "@/auth/oauth";
import { getDb } from "@/db";

// Server actions only accept same-origin POSTs, so other sites can't create
// workspaces in a visitor's browser. The key is returned once and never stored.
export async function createKey(): Promise<{ key: string }> {
  return { key: await createWorkspaceWithKey(getDb()) };
}
