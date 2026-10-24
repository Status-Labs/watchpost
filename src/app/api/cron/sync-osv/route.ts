import { revalidateTag } from "next/cache";
import { getDb } from "@/db";
import { VULNS_TAG } from "@/lib/cached";
import { isAuthorizedCron } from "@/lib/auth";
import { runOsvSync } from "@/osv/sync";

export const maxDuration = 300;

export async function GET(request: Request) {
  if (!isAuthorizedCron(request)) {
    return Response.json({ error: "unauthorized" }, { status: 401 });
  }

  const result = await runOsvSync({ db: getDb() });
  // Cached pages refresh on their next visit, serving the old copy meanwhile.
  if (result.upserted > 0) revalidateTag(VULNS_TAG, "max");
  console.log("osv sync", result);
  return Response.json(result);
}
