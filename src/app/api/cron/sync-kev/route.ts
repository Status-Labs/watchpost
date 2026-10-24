import { revalidateTag } from "next/cache";
import { getDb } from "@/db";
import { VULNS_TAG } from "@/lib/cached";
import { isAuthorizedCron } from "@/lib/auth";
import { runKevSync } from "@/kev/sync";

export const maxDuration = 120;

export async function GET(request: Request) {
  if (!isAuthorizedCron(request)) {
    return Response.json({ error: "unauthorized" }, { status: 401 });
  }

  const result = await runKevSync({ db: getDb() });
  if (result.changed) revalidateTag(VULNS_TAG, "max");
  console.log("kev sync", result);
  return Response.json(result);
}
