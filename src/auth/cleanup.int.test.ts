import { randomBytes } from "node:crypto";
import { eq, sql } from "drizzle-orm";
import { Pool } from "pg";
import { afterAll, beforeEach, describe, expect, inject, it } from "vitest";
import { createDb } from "@/db";
import { oauthClients, stacks, tokens, workspaces } from "@/db/schema";
import { runCleanup } from "./cleanup";
import { approve, createWorkspaceWithKey, exchangeToken, registerClient, validateAuthorize, verifyBearer } from "./oauth";
import { pkceChallenge } from "./tokens";

const pool = new Pool({ connectionString: inject("databaseUrl") });
const db = createDb(pool);
const DAY = 24 * 60 * 60_000;

beforeEach(async () => {
  await db.execute(sql`truncate ${workspaces}, ${oauthClients} cascade`);
});

afterAll(async () => {
  await pool.end();
});

describe("runCleanup", () => {
  it("deletes workspaces idle for 90 days, with everything in them", async () => {
    const idleKey = await createWorkspaceWithKey(db);
    const activeKey = await createWorkspaceWithKey(db);
    const idle = (await verifyBearer(db, idleKey))!;
    await db.insert(stacks).values({ workspaceId: idle.workspaceId, name: "laptop" });
    await db.update(workspaces).set({ lastActiveAt: new Date(Date.now() - 91 * DAY) }).where(eq(workspaces.id, idle.workspaceId));

    const result = await runCleanup(db);
    expect(result.idleWorkspaces).toBe(1);
    expect(await verifyBearer(db, idleKey)).toBeNull();
    expect(await verifyBearer(db, activeKey)).not.toBeNull();
    expect(await db.$count(stacks)).toBe(0);
  });

  it("clears abandoned sign-ins and expired tokens, but keeps working grants", async () => {
    // A finished sign-in.
    const client = await registerClient(db, { redirect_uris: ["http://127.0.0.1:1/cb"] });
    const verifier = randomBytes(32).toString("base64url");
    const request = {
      response_type: "code",
      client_id: client.client_id,
      redirect_uri: "http://127.0.0.1:1/cb",
      code_challenge: pkceChallenge(verifier),
      code_challenge_method: "S256",
    };
    const code = new URL(await approve(db, await validateAuthorize(db, request))).searchParams.get("code")!;
    const issued = await exchangeToken(db, { grant_type: "authorization_code", client_id: client.client_id, code, code_verifier: verifier, redirect_uri: "http://127.0.0.1:1/cb" });

    // An abandoned one: registered and approved, code never exchanged.
    const abandoned = await registerClient(db, { redirect_uris: ["http://127.0.0.1:2/cb"] });
    await approve(db, await validateAuthorize(db, { ...request, client_id: abandoned.client_id, redirect_uri: "http://127.0.0.1:2/cb" }));

    // Two days later the abandoned code has expired; the access token too.
    const later = new Date(Date.now() + 2 * DAY);
    const result = await runCleanup(db, later);
    expect(result).toMatchObject({ codes: 1, clients: 1, unreachableWorkspaces: 1 });
    expect(result.tokens).toBeGreaterThanOrEqual(1);

    // The finished sign-in can still refresh.
    expect(await db.$count(oauthClients)).toBe(1);
    expect(await db.$count(tokens, eq(tokens.kind, "refresh"))).toBe(1);
    await expect(exchangeToken(db, { grant_type: "refresh_token", refresh_token: issued.refresh_token, client_id: client.client_id })).resolves.toBeTruthy();
  });
});
