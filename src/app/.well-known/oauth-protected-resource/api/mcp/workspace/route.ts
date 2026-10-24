import { SCOPE, issuerUrl, mcpResourceUrl } from "@/auth/oauth";
import { CORS_HEADERS, preflight } from "@/auth/http";
import { SITE_NAME, siteUrl } from "@/lib/site";

// Protected resource metadata (RFC 9728) for /api/mcp: tells MCP apps which
// authorization server issues tokens for it.
export function GET() {
  return Response.json(
    {
      resource: mcpResourceUrl(),
      authorization_servers: [issuerUrl()],
      scopes_supported: [SCOPE],
      bearer_methods_supported: ["header"],
      resource_name: SITE_NAME,
      resource_documentation: siteUrl("/docs#mcp"),
    },
    { headers: CORS_HEADERS },
  );
}

export const OPTIONS = preflight;
