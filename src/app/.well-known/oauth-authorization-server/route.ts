import { SCOPE, issuerUrl } from "@/auth/oauth";
import { CORS_HEADERS, preflight } from "@/auth/http";
import { siteUrl } from "@/lib/site";

// OAuth authorization server metadata (RFC 8414), which MCP apps read to find
// the sign-in, token and registration endpoints.
export function GET() {
  return Response.json(
    {
      issuer: issuerUrl(),
      authorization_endpoint: siteUrl("/connect"),
      token_endpoint: siteUrl("/oauth/token"),
      registration_endpoint: siteUrl("/oauth/register"),
      revocation_endpoint: siteUrl("/oauth/revoke"),
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none"],
      revocation_endpoint_auth_methods_supported: ["none"],
      scopes_supported: [SCOPE],
      authorization_response_iss_parameter_supported: true,
      // Client ID Metadata Documents would mean fetching a URL the client
      // chooses; we don't make requests to user-supplied URLs.
      client_id_metadata_document_supported: false,
    },
    { headers: CORS_HEADERS },
  );
}

export const OPTIONS = preflight;
