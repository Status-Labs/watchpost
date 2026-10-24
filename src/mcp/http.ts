import { siteUrl } from "@/lib/site";

// Wraps an MCP handler: rejects browser requests from other origins and marks
// every response private.
//
// MCP apps don't send an Origin header; browsers do. Rejecting other origins
// stops a web page from calling tools in a visitor's browser, and DNS-rebinding
// attacks against local copies.
export function mcpEndpoint(handler: (request: Request) => Promise<Response>) {
  return async (request: Request): Promise<Response> => {
    const origin = request.headers.get("origin");
    if (origin && origin !== new URL(siteUrl("/")).origin) {
      return Response.json({ error: "forbidden_origin" }, { status: 403 });
    }
    const response = await handler(request);
    const headers = new Headers(response.headers);
    headers.set("Cache-Control", "private, no-store");
    headers.set("X-Robots-Tag", "noindex");
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
  };
}
