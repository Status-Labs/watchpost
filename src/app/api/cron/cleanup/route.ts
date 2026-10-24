import { runCleanup } from "@/auth/cleanup";
import { getDb } from "@/db";
import { isAuthorizedCron } from "@/lib/auth";

export const maxDuration = 120;

export async function GET(request: Request) {
  if (!isAuthorizedCron(request)) {
    return Response.json({ error: "unauthorized" }, { status: 401 });
  }
  const result = await runCleanup(getDb());
  console.log("cleanup", result);
  return Response.json(result);
}
