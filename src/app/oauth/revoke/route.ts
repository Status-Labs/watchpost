import { revokeToken } from "@/auth/oauth";
import { CORS_HEADERS, oauthErrorResponse, preflight, readForm } from "@/auth/http";
import { getDb } from "@/db";

// Token revocation (RFC 7009). Always 200, even for unknown tokens.
export async function POST(request: Request) {
  try {
    const { token } = await readForm(request);
    if (token && token.length <= 200) await revokeToken(getDb(), token);
    return new Response(null, { status: 200, headers: CORS_HEADERS });
  } catch (error) {
    return oauthErrorResponse(error);
  }
}

export const OPTIONS = preflight;
