import { and, eq, gt, inArray, isNull, lt, or } from "drizzle-orm";
import { z } from "zod";
import type { Db } from "@/db";
import { authCodes, oauthClients, tokens, workspaces } from "@/db/schema";
import { oneLine } from "@/lib/sanitize";
import { siteUrl } from "@/lib/site";
import { TOKEN_PREFIXES, hashSecret, newId, newSecret, pkceChallenge } from "./tokens";

// A small OAuth 2.1 authorization server for the MCP endpoint, following the
// MCP authorization spec: public clients, PKCE (S256) required, Dynamic Client
// Registration, and tokens bound to the MCP server as their resource.
//
// There are no accounts. Approving a connection creates a new, empty workspace,
// so a malicious client that gets a user to approve it only gets an empty workspace.

export const ACCESS_TOKEN_TTL_S = 60 * 60;
export const REFRESH_TOKEN_TTL_S = 90 * 24 * 60 * 60;
const CODE_TTL_MS = 5 * 60_000;
const ACTIVITY_GRANULARITY_MS = 24 * 60 * 60_000;

export const SCOPE = "stack";

export function mcpResourceUrl(): string {
  return siteUrl("/api/mcp/workspace");
}

export function issuerUrl(): string {
  return siteUrl("/").replace(/\/$/, "");
}

export class OAuthError extends Error {
  constructor(
    readonly code: "invalid_request" | "invalid_client" | "invalid_grant" | "unsupported_grant_type" | "invalid_redirect_uri" | "invalid_client_metadata",
    readonly description: string,
  ) {
    super(description);
  }
}

// --- Client registration (RFC 7591) ---

const MAX_REDIRECT_URIS = 5;
const MAX_URI_LENGTH = 500;
// App schemes: reverse-DNS ones (RFC 8252, like com.example.app:) plus a few
// MCP apps that use short schemes. Anything else could hand the browser to an
// OS protocol handler (ms-msdt:, search-ms:, ...).
const KNOWN_APP_SCHEMES = new Set(["cursor:", "vscode:", "vscode-insiders:", "windsurf:", "zed:"]);
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

// https anywhere, http only on loopback (native apps, RFC 8252), or an app
// scheme. No fragments or embedded credentials.
export function isAllowedRedirectUri(value: string): boolean {
  if (value.length > MAX_URI_LENGTH) return false;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  if (url.hash || url.username || url.password) return false;
  if (url.protocol === "https:") return true;
  if (url.protocol === "http:") return LOOPBACK_HOSTS.has(url.hostname);
  return KNOWN_APP_SCHEMES.has(url.protocol) || /^[a-z][a-z0-9+-]*(\.[a-z0-9+-]+)+:$/.test(url.protocol);
}

const registrationSchema = z.object({
  redirect_uris: z.array(z.string()).min(1).max(MAX_REDIRECT_URIS),
  // Long names are cut down, not refused.
  client_name: z.string().max(2_000).optional(),
  token_endpoint_auth_method: z.string().optional(),
  grant_types: z.array(z.string()).optional(),
  response_types: z.array(z.string()).optional(),
});

export async function registerClient(db: Db, body: unknown) {
  const parsed = registrationSchema.safeParse(body);
  if (!parsed.success) {
    throw new OAuthError("invalid_client_metadata", "Invalid metadata: redirect_uris (1 to 5 URIs) is required.");
  }
  const meta = parsed.data;
  if (!meta.redirect_uris.every(isAllowedRedirectUri)) {
    throw new OAuthError("invalid_redirect_uri", "Redirect URIs must be https, http on localhost, or an app scheme.");
  }
  if (meta.token_endpoint_auth_method && meta.token_endpoint_auth_method !== "none") {
    throw new OAuthError("invalid_client_metadata", "Only public clients are supported (token_endpoint_auth_method: none).");
  }
  const id = newId("wpcl_");
  // The name is shown on the approval page as untrusted text.
  const name = cleanName(meta.client_name) || "An MCP app";
  await db.insert(oauthClients).values({ id, name, redirectUris: meta.redirect_uris });
  return {
    client_id: id,
    client_id_issued_at: Math.floor(Date.now() / 1000),
    client_name: name,
    redirect_uris: meta.redirect_uris,
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
  };
}

function cleanName(value: string | undefined): string {
  return oneLine(value ?? "").slice(0, 60);
}

// --- Authorization request (the /connect page) ---

export const authorizeSchema = z.object({
  response_type: z.literal("code"),
  client_id: z.string().min(1).max(100),
  redirect_uri: z.string().min(1).max(MAX_URI_LENGTH),
  code_challenge: z.string().regex(/^[A-Za-z0-9_-]{43,128}$/),
  code_challenge_method: z.literal("S256"),
  state: z.string().max(1000).optional(),
  scope: z.string().max(200).optional(),
  resource: z.string().max(MAX_URI_LENGTH).optional(),
});
export type AuthorizeRequest = z.infer<typeof authorizeSchema>;

export type ValidatedAuthorize = {
  request: AuthorizeRequest;
  client: { id: string; name: string };
  redirectHost: string;
};

// Errors before the redirect URI is trusted are shown on our page, never sent
// to the redirect URI (an attacker could otherwise use us as an open redirect).
export async function validateAuthorize(db: Db, params: Record<string, unknown>): Promise<ValidatedAuthorize> {
  const single = Object.fromEntries(
    Object.entries(params).map(([key, value]) => [key, Array.isArray(value) ? value[0] : value]),
  );
  const parsed = authorizeSchema.safeParse(single);
  if (!parsed.success) {
    const field = parsed.error.issues[0]?.path[0];
    throw new OAuthError("invalid_request", `The sign-in request is missing or has an invalid ${String(field ?? "field")}.`);
  }
  const request = parsed.data;
  const [client] = await db.select().from(oauthClients).where(eq(oauthClients.id, request.client_id));
  if (!client) throw new OAuthError("invalid_client", "This app isn't registered. Try connecting again from the app.");
  if (!redirectMatches(client.redirectUris, request.redirect_uri)) {
    throw new OAuthError("invalid_redirect_uri", "The app's callback address doesn't match its registration.");
  }
  if (request.resource && stripSlash(request.resource) !== stripSlash(mcpResourceUrl())) {
    throw new OAuthError("invalid_request", "This sign-in is for a different server.");
  }
  const redirect = new URL(request.redirect_uri);
  return {
    request,
    client: { id: client.id, name: client.name },
    redirectHost:
      redirect.protocol === "https:" || redirect.protocol === "http:" ? redirect.host : `${redirect.protocol}//${redirect.host}`,
  };
}

// Exact match, except loopback redirects may use any port (RFC 8252 7.3).
export function redirectMatches(registered: string[], requested: string): boolean {
  if (registered.includes(requested)) return true;
  let req: URL;
  try {
    req = new URL(requested);
  } catch {
    return false;
  }
  if (req.protocol !== "http:" || !LOOPBACK_HOSTS.has(req.hostname)) return false;
  return registered.some((uri) => {
    const reg = new URL(uri);
    return reg.protocol === "http:" && reg.hostname === req.hostname && reg.pathname === req.pathname && reg.search === req.search;
  });
}

function stripSlash(value: string): string {
  return value.replace(/\/+$/, "");
}

// Approval: creates a fresh workspace and a one-time code for the app.
export async function approve(db: Db, { request, client }: ValidatedAuthorize): Promise<string> {
  const code = newSecret(TOKEN_PREFIXES.code);
  await db.transaction(async (tx) => {
    const [workspace] = await tx.insert(workspaces).values({}).returning({ id: workspaces.id });
    await tx.insert(authCodes).values({
      codeHash: hashSecret(code),
      clientId: client.id,
      workspaceId: workspace.id,
      redirectUri: request.redirect_uri,
      codeChallenge: request.code_challenge,
      expiresAt: new Date(Date.now() + CODE_TTL_MS),
    });
  });
  const url = new URL(request.redirect_uri);
  url.searchParams.set("code", code);
  if (request.state !== undefined) url.searchParams.set("state", request.state);
  url.searchParams.set("iss", issuerUrl());
  return url.toString();
}

// --- Token endpoint ---

export type TokenResponse = {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  refresh_token: string;
  scope: string;
};

const codeGrantSchema = z.object({
  grant_type: z.literal("authorization_code"),
  code: z.string().min(1).max(200),
  redirect_uri: z.string().min(1).max(MAX_URI_LENGTH),
  client_id: z.string().min(1).max(100),
  code_verifier: z.string().regex(/^[A-Za-z0-9._~-]{43,128}$/),
  resource: z.string().max(MAX_URI_LENGTH).optional(),
});

const refreshGrantSchema = z.object({
  grant_type: z.literal("refresh_token"),
  refresh_token: z.string().min(1).max(200),
  client_id: z.string().min(1).max(100),
  resource: z.string().max(MAX_URI_LENGTH).optional(),
});

export async function exchangeToken(db: Db, params: Record<string, string>): Promise<TokenResponse> {
  if (params.grant_type === "authorization_code") return exchangeCode(db, params);
  if (params.grant_type === "refresh_token") return refresh(db, params);
  throw new OAuthError("unsupported_grant_type", "Use authorization_code or refresh_token.");
}

async function exchangeCode(db: Db, params: Record<string, string>): Promise<TokenResponse> {
  const parsed = codeGrantSchema.safeParse(params);
  if (!parsed.success) throw new OAuthError("invalid_request", "Missing or invalid code, redirect_uri, client_id or code_verifier.");
  const { code, redirect_uri, client_id, code_verifier } = parsed.data;
  checkResource(parsed.data.resource);

  // Deleting on read makes a code single-use even under concurrent requests.
  const [row] = await db.delete(authCodes).where(eq(authCodes.codeHash, hashSecret(code))).returning();
  if (!row || row.expiresAt.getTime() < Date.now()) throw new OAuthError("invalid_grant", "The code is invalid or expired.");
  if (row.clientId !== client_id || row.redirectUri !== redirect_uri) {
    throw new OAuthError("invalid_grant", "The code was issued to a different client or redirect URI.");
  }
  if (pkceChallenge(code_verifier) !== row.codeChallenge) throw new OAuthError("invalid_grant", "PKCE verification failed.");

  return issueTokens(db, { workspaceId: row.workspaceId, clientId: client_id, grantId: crypto.randomUUID() });
}

async function refresh(db: Db, params: Record<string, string>): Promise<TokenResponse> {
  const parsed = refreshGrantSchema.safeParse(params);
  if (!parsed.success) throw new OAuthError("invalid_request", "Missing or invalid refresh_token or client_id.");
  checkResource(parsed.data.resource);
  const hash = hashSecret(parsed.data.refresh_token);

  // Rotate, retire the old access tokens and issue new ones in one transaction,
  // so a failure part way can't leave the app without a working refresh token.
  const issued = await db.transaction(async (tx) => {
    // Only one concurrent request can win this update.
    const [rotated] = await tx
      .update(tokens)
      .set({ rotatedAt: new Date() })
      .where(and(eq(tokens.hash, hash), eq(tokens.kind, "refresh"), isNull(tokens.rotatedAt)))
      .returning();
    if (!rotated) return null;
    if (rotated.clientId !== parsed.data.client_id || !rotated.grantId) {
      throw new OAuthError("invalid_grant", "The refresh token was issued to a different client.");
    }
    if (rotated.expiresAt && rotated.expiresAt.getTime() < Date.now()) {
      throw new OAuthError("invalid_grant", "The refresh token has expired.");
    }
    await tx.delete(tokens).where(and(eq(tokens.grantId, rotated.grantId), eq(tokens.kind, "access")));
    return issueTokens(tx, { workspaceId: rotated.workspaceId, clientId: rotated.clientId, grantId: rotated.grantId });
  });
  if (issued) return issued;

  // A used refresh token presented again means it may have been stolen:
  // revoke everything issued from that approval.
  const [reused] = await db.select().from(tokens).where(and(eq(tokens.hash, hash), eq(tokens.kind, "refresh")));
  if (reused?.grantId) await db.delete(tokens).where(eq(tokens.grantId, reused.grantId));
  throw new OAuthError("invalid_grant", "The refresh token is invalid or was already used.");
}

function checkResource(resource: string | undefined) {
  if (resource && stripSlash(resource) !== stripSlash(mcpResourceUrl())) {
    throw new OAuthError("invalid_grant", "Tokens can only be issued for this server's MCP endpoint.");
  }
}

async function issueTokens(
  db: Pick<Db, "insert">,
  { workspaceId, clientId, grantId }: { workspaceId: string; clientId: string; grantId: string },
): Promise<TokenResponse> {
  const access = newSecret(TOKEN_PREFIXES.access);
  const refreshToken = newSecret(TOKEN_PREFIXES.refresh);
  const now = Date.now();
  await db.insert(tokens).values([
    { hash: hashSecret(access), kind: "access", workspaceId, clientId, grantId, expiresAt: new Date(now + ACCESS_TOKEN_TTL_S * 1000) },
    { hash: hashSecret(refreshToken), kind: "refresh", workspaceId, clientId, grantId, expiresAt: new Date(now + REFRESH_TOKEN_TTL_S * 1000) },
  ]);
  return { access_token: access, token_type: "Bearer", expires_in: ACCESS_TOKEN_TTL_S, refresh_token: refreshToken, scope: SCOPE };
}

// --- Revocation (RFC 7009) ---

// Revoking either token of a grant ends the whole grant. Unknown tokens are
// not an error, per the RFC.
export async function revokeToken(db: Db, token: string) {
  const [row] = await db.select().from(tokens).where(eq(tokens.hash, hashSecret(token)));
  if (!row) return;
  if (row.grantId) await db.delete(tokens).where(eq(tokens.grantId, row.grantId));
  else await db.delete(tokens).where(eq(tokens.hash, row.hash));
}

// --- Static keys ("Get a key", for apps without OAuth) ---

export async function createWorkspaceWithKey(db: Db): Promise<string> {
  const key = newSecret(TOKEN_PREFIXES.key);
  await db.transaction(async (tx) => {
    const [workspace] = await tx.insert(workspaces).values({}).returning({ id: workspaces.id });
    await tx.insert(tokens).values({ hash: hashSecret(key), kind: "key", workspaceId: workspace.id });
  });
  return key;
}

// --- Verifying bearer tokens on /api/mcp/workspace ---

export type Caller = { workspaceId: string; clientId: string; kind: "access" | "key"; expiresAt: Date | null };

export async function verifyBearer(db: Db, token: string | undefined): Promise<Caller | null> {
  if (!token || token.length > 200) return null;
  if (!token.startsWith(TOKEN_PREFIXES.access) && !token.startsWith(TOKEN_PREFIXES.key)) return null;
  const now = new Date();
  const [row] = await db
    .select()
    .from(tokens)
    .where(
      and(
        eq(tokens.hash, hashSecret(token)),
        inArray(tokens.kind, ["access", "key"]),
        or(isNull(tokens.expiresAt), gt(tokens.expiresAt, now)),
      ),
    );
  if (!row) return null;
  await touchWorkspace(db, row.workspaceId, now);
  return {
    workspaceId: row.workspaceId,
    clientId: row.clientId ?? "static-key",
    kind: row.kind === "key" ? "key" : "access",
    expiresAt: row.expiresAt,
  };
}

// Activity keeps a workspace from being deleted after 90 idle days. Written at
// most once a day, so it reveals little about when a workspace is used.
export async function touchWorkspace(db: Db, workspaceId: string, now = new Date()) {
  await db
    .update(workspaces)
    .set({ lastActiveAt: now })
    .where(and(eq(workspaces.id, workspaceId), lt(workspaces.lastActiveAt, new Date(now.getTime() - ACTIVITY_GRANULARITY_MS))));
}

export async function deleteWorkspace(db: Db, workspaceId: string) {
  await db.delete(workspaces).where(eq(workspaces.id, workspaceId));
}
