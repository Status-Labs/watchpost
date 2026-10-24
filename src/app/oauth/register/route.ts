import { registerClient } from "@/auth/oauth";
import { jsonResponse, oauthErrorResponse, preflight, readBody } from "@/auth/http";
import { OAuthError } from "@/auth/oauth";
import { getDb } from "@/db";

// Dynamic Client Registration (RFC 7591) for MCP apps. Public clients only.
export async function POST(request: Request) {
  try {
    let body: unknown;
    try {
      body = JSON.parse(await readBody(request));
    } catch (error) {
      if (error instanceof OAuthError) throw error;
      throw new OAuthError("invalid_client_metadata", "The body must be JSON.");
    }
    return jsonResponse(await registerClient(getDb(), body), 201);
  } catch (error) {
    return oauthErrorResponse(error);
  }
}

export const OPTIONS = preflight;
