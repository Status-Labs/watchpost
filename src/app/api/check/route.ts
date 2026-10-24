import type { NextRequest } from "next/server";
import { z } from "zod";
import { getDb } from "@/db";
import { checkPackages, formatText, type CheckResult } from "@/stacks/check";
import { MAX_ITEMS, stackItemInput, validateItems, type RejectedItem } from "@/stacks/validate";

export const maxDuration = 60;

// Stateless check: send package names and versions, get back the known
// vulnerabilities that affect them. Nothing is stored or logged, and no key is
// needed. ?format=text returns a plain summary for cron jobs and terminals.
const MAX_BODY = 1_000_000;
const NO_STORE = { "Cache-Control": "no-store", "X-Robots-Tag": "noindex" };

const bodySchema = z.object({ packages: z.array(stackItemInput).min(1).max(MAX_ITEMS) });

export async function POST(request: NextRequest) {
  const text = request.nextUrl.searchParams.get("format") === "text";
  if (Number(request.headers.get("content-length") ?? 0) > MAX_BODY) return fail(413, "Request body too large.", text);
  const raw = await request.text();
  if (raw.length > MAX_BODY) return fail(413, "Request body too large.", text);

  let body: z.infer<typeof bodySchema>;
  try {
    body = bodySchema.parse(JSON.parse(raw));
  } catch {
    return fail(400, `Send JSON like {"packages": [{"ecosystem": "npm", "name": "lodash", "version": "4.17.21"}]}, up to ${MAX_ITEMS} packages.`, text);
  }

  const { items, rejected } = validateItems(body.packages);
  if (items.length === 0) return fail(400, "No valid packages to check.", text, rejected);

  let results: CheckResult[];
  try {
    results = await checkPackages(getDb(), items);
  } catch {
    return fail(502, "The vulnerability lookup is unavailable. Try again in a few minutes.", text);
  }

  if (text) return new Response(formatText(items.length, results, rejected), { headers: { "Content-Type": "text/plain; charset=utf-8", ...NO_STORE } });
  return Response.json(
    { checked: items.length, vulnerable_packages: new Set(results.map((r) => `${r.ecosystem}/${r.package}@${r.version}`)).size, results, rejected },
    { headers: NO_STORE },
  );
}

function fail(status: number, message: string, text: boolean, rejected: RejectedItem[] = []) {
  if (text) return new Response(`${message}\n`, { status, headers: { "Content-Type": "text/plain; charset=utf-8", ...NO_STORE } });
  return Response.json({ error: message, rejected }, { status, headers: NO_STORE });
}
