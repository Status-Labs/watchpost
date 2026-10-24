import { OAuthError } from "./oauth";

// Shared helpers for the OAuth endpoints. These are public, unauthenticated
// endpoints that MCP apps (sometimes browser-based) call, so they allow CORS
// without credentials.
export const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, MCP-Protocol-Version",
};

const NO_STORE = { "Cache-Control": "no-store", Pragma: "no-cache" };
const MAX_BODY = 10_000;

export function preflight() {
  return new Response(null, { status: 204, headers: CORS_HEADERS });
}

export function jsonResponse(data: unknown, status = 200) {
  return Response.json(data, { status, headers: { ...CORS_HEADERS, ...NO_STORE } });
}

export function oauthErrorResponse(error: unknown) {
  if (error instanceof OAuthError) {
    const status = error.code === "invalid_client" ? 401 : 400;
    return jsonResponse({ error: error.code, error_description: error.description }, status);
  }
  throw error;
}

// Request bodies are small; anything larger is refused before parsing.
export async function readBody(request: Request): Promise<string> {
  if (Number(request.headers.get("content-length") ?? 0) > MAX_BODY) {
    throw new OAuthError("invalid_request", "Request body too large.");
  }
  const text = await request.text();
  if (text.length > MAX_BODY) throw new OAuthError("invalid_request", "Request body too large.");
  return text;
}

export async function readForm(request: Request): Promise<Record<string, string>> {
  const text = await readBody(request);
  const type = request.headers.get("content-type") ?? "";
  if (type.includes("application/json")) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text || "{}");
    } catch {
      throw new OAuthError("invalid_request", "The body isn't valid JSON.");
    }
    if (!parsed || typeof parsed !== "object") return {};
    return Object.fromEntries(Object.entries(parsed).filter(([, v]) => typeof v === "string")) as Record<string, string>;
  }
  return Object.fromEntries(new URLSearchParams(text));
}
