import { createMcpHandler } from "mcp-handler";
import { SITE_NAME } from "@/lib/site";
import { mcpEndpoint } from "@/mcp/http";
import { LOOKUP_INSTRUCTIONS, registerLookupTools } from "@/mcp/tools";

export const maxDuration = 60;

// The default MCP endpoint: no sign-in and nothing stored. check_packages
// checks a package list and forgets it. For stacks kept between sessions, see
// /api/mcp/workspace.
const mcp = createMcpHandler(registerLookupTools, {
  serverInfo: { name: SITE_NAME.toLowerCase(), version: "0.1.0" },
  instructions: LOOKUP_INSTRUCTIONS,
});

const handler = mcpEndpoint(mcp);

export { handler as GET, handler as POST, handler as DELETE };
