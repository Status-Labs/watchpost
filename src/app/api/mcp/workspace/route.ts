import { createMcpHandler, withMcpAuth } from "mcp-handler";
import { SCOPE, mcpResourceUrl, verifyBearer } from "@/auth/oauth";
import { getDb } from "@/db";
import { SITE_NAME, siteUrl } from "@/lib/site";
import { mcpEndpoint } from "@/mcp/http";
import { WORKSPACE_INSTRUCTIONS, registerWorkspaceTools } from "@/mcp/tools";

export const maxDuration = 120;

const mcp = createMcpHandler(registerWorkspaceTools, {
  serverInfo: { name: `${SITE_NAME.toLowerCase()}-workspace`, version: "0.1.0" },
  instructions: WORKSPACE_INSTRUCTIONS,
});

// Optional, for people who want stacks kept between sessions. Bearer tokens
// only (never cookies). An unauthenticated request gets a 401 pointing at our
// OAuth metadata, which is what starts the sign-in flow in MCP apps.
const authed = withMcpAuth(
  mcp,
  async (_req, token) => {
    const caller = await verifyBearer(getDb(), token);
    if (!caller) return undefined;
    return {
      token: token!,
      clientId: caller.clientId,
      scopes: [SCOPE],
      expiresAt: caller.expiresAt ? Math.floor(caller.expiresAt.getTime() / 1000) : undefined,
      resource: new URL(mcpResourceUrl()),
      extra: { workspaceId: caller.workspaceId },
    };
  },
  {
    required: true,
    resourceMetadataPath: "/.well-known/oauth-protected-resource/api/mcp/workspace",
    resourceUrl: siteUrl("/").replace(/\/$/, ""),
  },
);

const handler = mcpEndpoint(authed);

export { handler as GET, handler as POST, handler as DELETE };
