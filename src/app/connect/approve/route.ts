import { OAuthError, approve, validateAuthorize } from "@/auth/oauth";
import { readForm } from "@/auth/http";
import { getDb } from "@/db";
import { siteUrl } from "@/lib/site";

// The approval form posts here. Same-origin only, so another site can't
// create workspaces or approve connections in a visitor's browser.
export async function POST(request: Request) {
  if (!isSameOrigin(request)) return new Response("Forbidden\n", { status: 403 });

  try {
    const form = await readForm(request);
    const validated = await validateAuthorize(getDb(), form);
    if (form.decision !== "approve") {
      const url = new URL(validated.request.redirect_uri);
      url.searchParams.set("error", "access_denied");
      if (validated.request.state !== undefined) url.searchParams.set("state", validated.request.state);
      return redirect(url.toString());
    }
    return redirect(await approve(getDb(), validated));
  } catch (error) {
    if (error instanceof OAuthError) return new Response(`${error.description}\n`, { status: 400 });
    throw error;
  }
}

function isSameOrigin(request: Request): boolean {
  // Every current browser sends Sec-Fetch-Site. Origin is the fallback; with
  // our no-referrer policy, browsers send "null" there for form posts.
  const site = request.headers.get("sec-fetch-site");
  if (site) return site === "same-origin";
  return request.headers.get("origin") === new URL(siteUrl("/")).origin;
}

function redirect(location: string) {
  return new Response(null, { status: 303, headers: { Location: location, "Cache-Control": "no-store" } });
}
