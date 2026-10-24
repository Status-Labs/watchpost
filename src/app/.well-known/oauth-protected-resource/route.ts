// Some MCP apps look for the metadata at the root path instead of the
// resource-specific one; serve the same document there.
export { GET, OPTIONS } from "./api/mcp/workspace/route";
