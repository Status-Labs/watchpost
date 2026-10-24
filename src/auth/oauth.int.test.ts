import { randomBytes } from "node:crypto";
import { eq, sql } from "drizzle-orm";
import { Pool } from "pg";
import { afterAll, beforeEach, describe, expect, inject, it } from "vitest";
import { createDb } from "@/db";
import { authCodes, oauthClients, stacks, tokens, workspaces } from "@/db/schema";
import {
  approve,
  createWorkspaceWithKey,
  deleteWorkspace,
  exchangeToken,
  isAllowedRedirectUri,
  registerClient,
  revokeToken,
  validateAuthorize,
  verifyBearer,
} from "./oauth";
import { hashSecret, pkceChallenge } from "./tokens";

const pool = new Pool({ connectionString: inject("databaseUrl") });
const db = createDb(pool);
const REDIRECT = "http://127.0.0.1:33418/callback";

beforeEach(async () => {
  await db.execute(sql`truncate ${workspaces}, ${oauthClients} cascade`);
});

afterAll(async () => {
  await pool.end();
});

// Runs the browser half of the flow: register, open /connect, approve.
async function signIn() {
  const client = await registerClient(db, { client_name: "Test app", redirect_uris: [REDIRECT] });
  const verifier = randomBytes(32).toString("base64url");
  const validated = await validateAuthorize(db, {
    response_type: "code",
    client_id: client.client_id,
    redirect_uri: "http://127.0.0.1:50123/callback",
    code_challenge: pkceChallenge(verifier),
    code_challenge_method: "S256",
    state: "xyz",
    resource: "http://localhost:3000/api/mcp/workspace",
  });
  const redirect = new URL(await approve(db, validated));
  return { client, verifier, redirect, code: redirect.searchParams.get("code")! };
}

const codeGrant = (clientId: string, code: string, verifier: string) => ({
  grant_type: "authorization_code",
  client_id: clientId,
  code,
  code_verifier: verifier,
  redirect_uri: "http://127.0.0.1:50123/callback",
});

describe("OAuth sign-in", () => {
  it("creates a workspace and hands the app tokens that work on /api/mcp", async () => {
    const { client, verifier, redirect, code } = await signIn();
    // Loopback redirects may use any port; state and issuer come back.
    expect(redirect.port).toBe("50123");
    expect(redirect.searchParams.get("state")).toBe("xyz");
    expect(redirect.searchParams.get("iss")).toBe("http://localhost:3000");
    expect(code).toMatch(/^wpc_/);

    const issued = await exchangeToken(db, codeGrant(client.client_id, code, verifier));
    expect(issued.access_token).toMatch(/^wpa_/);
    expect(issued.refresh_token).toMatch(/^wpr_/);

    const caller = await verifyBearer(db, issued.access_token);
    expect(caller?.workspaceId).toBeTruthy();
    expect(await db.$count(workspaces)).toBe(1);
    // Only hashes are stored.
    const stored = await db.select({ hash: tokens.hash }).from(tokens);
    expect(stored.map((t) => t.hash)).toContain(hashSecret(issued.access_token));
    expect(JSON.stringify(stored)).not.toContain(issued.access_token);
  });

  it("uses each code once and requires the right PKCE verifier", async () => {
    const { client, verifier, code } = await signIn();
    await expect(exchangeToken(db, codeGrant(client.client_id, code, "x".repeat(43)))).rejects.toThrow("PKCE");
    // A failed attempt still burns the code.
    await expect(exchangeToken(db, codeGrant(client.client_id, code, verifier))).rejects.toThrow("invalid or expired");

    const second = await signIn();
    await exchangeToken(db, codeGrant(second.client.client_id, second.code, second.verifier));
    await expect(exchangeToken(db, codeGrant(second.client.client_id, second.code, second.verifier))).rejects.toThrow(
      "invalid or expired",
    );
  });

  it("rejects expired codes and codes for another client", async () => {
    const { verifier, code } = await signIn();
    const other = await registerClient(db, { redirect_uris: [REDIRECT] });
    await expect(exchangeToken(db, codeGrant(other.client_id, code, verifier))).rejects.toThrow("different client");

    const fresh = await signIn();
    await db.update(authCodes).set({ expiresAt: new Date(Date.now() - 1000) });
    await expect(exchangeToken(db, codeGrant(fresh.client.client_id, fresh.code, fresh.verifier))).rejects.toThrow("expired");
  });

  it("rotates refresh tokens, and revokes the grant when an old one is reused", async () => {
    const { client, verifier, code } = await signIn();
    const first = await exchangeToken(db, codeGrant(client.client_id, code, verifier));
    const refresh = (token: string) =>
      exchangeToken(db, { grant_type: "refresh_token", refresh_token: token, client_id: client.client_id });

    const second = await refresh(first.refresh_token);
    expect(await verifyBearer(db, first.access_token)).toBeNull();
    expect(await verifyBearer(db, second.access_token)).not.toBeNull();

    // Replaying the first refresh token looks like theft: everything from this approval stops working.
    await expect(refresh(first.refresh_token)).rejects.toThrow("already used");
    expect(await verifyBearer(db, second.access_token)).toBeNull();
    await expect(refresh(second.refresh_token)).rejects.toThrow();
  });

  it("refuses expired access tokens and tokens of the wrong kind", async () => {
    const { client, verifier, code } = await signIn();
    const issued = await exchangeToken(db, codeGrant(client.client_id, code, verifier));
    expect(await verifyBearer(db, issued.refresh_token)).toBeNull();
    await db.update(tokens).set({ expiresAt: new Date(Date.now() - 1000) }).where(eq(tokens.kind, "access"));
    expect(await verifyBearer(db, issued.access_token)).toBeNull();
    expect(await verifyBearer(db, undefined)).toBeNull();
  });

  it("revokes a grant and deletes a workspace with everything in it", async () => {
    const { client, verifier, code } = await signIn();
    const issued = await exchangeToken(db, codeGrant(client.client_id, code, verifier));
    await revokeToken(db, issued.refresh_token);
    expect(await verifyBearer(db, issued.access_token)).toBeNull();

    const key = await createWorkspaceWithKey(db);
    const caller = await verifyBearer(db, key);
    expect(caller?.kind).toBe("key");
    await db.insert(stacks).values({ workspaceId: caller!.workspaceId, name: "laptop" });
    await deleteWorkspace(db, caller!.workspaceId);
    expect(await verifyBearer(db, key)).toBeNull();
    expect(await db.$count(stacks)).toBe(0);
  });
});

describe("authorization request checks", () => {
  it("only accepts registered redirect URIs and this server as the resource", async () => {
    const client = await registerClient(db, { redirect_uris: ["https://app.example/callback"] });
    const base = {
      response_type: "code",
      client_id: client.client_id,
      redirect_uri: "https://app.example/callback",
      code_challenge: "a".repeat(43),
      code_challenge_method: "S256",
    };
    await expect(validateAuthorize(db, base)).resolves.toMatchObject({ redirectHost: "app.example" });
    await expect(validateAuthorize(db, { ...base, redirect_uri: "https://evil.example/callback" })).rejects.toThrow(
      "doesn't match",
    );
    await expect(validateAuthorize(db, { ...base, code_challenge_method: "plain" })).rejects.toThrow(
      "code_challenge_method",
    );
    await expect(validateAuthorize(db, { ...base, resource: "https://other.example/mcp" })).rejects.toThrow(
      "different server",
    );
    await expect(validateAuthorize(db, { ...base, client_id: "wpcl_unknown" })).rejects.toThrow("isn't registered");
  });

  it("registers only safe redirect URIs", async () => {
    expect(isAllowedRedirectUri("https://claude.ai/api/mcp/auth_callback")).toBe(true);
    expect(isAllowedRedirectUri("http://localhost:8080/cb")).toBe(true);
    expect(isAllowedRedirectUri("cursor://anysphere.cursor-mcp/oauth/callback")).toBe(true);
    expect(isAllowedRedirectUri("http://app.example/cb")).toBe(false);
    expect(isAllowedRedirectUri("com.example.app:/oauth/callback")).toBe(true);
    expect(isAllowedRedirectUri("javascript:alert(1)")).toBe(false);
    expect(isAllowedRedirectUri("ms-msdt:/id PCWDiagnostic")).toBe(false);
    expect(isAllowedRedirectUri("search-ms:query=x")).toBe(false);
    expect(isAllowedRedirectUri("https://user:pass@app.example/cb")).toBe(false);
    expect(isAllowedRedirectUri("https://app.example/cb#frag")).toBe(false);
    await expect(registerClient(db, { redirect_uris: ["data:text/html,hi"] })).rejects.toThrow("Redirect URIs");
    await expect(
      registerClient(db, { redirect_uris: [REDIRECT], token_endpoint_auth_method: "client_secret_basic" }),
    ).rejects.toThrow("public clients");
  });

  it("keeps hostile client names to one short line of text", async () => {
    const client = await registerClient(db, { client_name: "Claude‮\u0000 Official\n".padEnd(300, "!"), redirect_uris: [REDIRECT] });
    expect(client.client_name).toMatch(/^Claude Official/);
    expect(client.client_name.length).toBeLessThanOrEqual(60);
  });
});
