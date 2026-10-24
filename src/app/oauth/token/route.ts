import { exchangeToken } from "@/auth/oauth";
import { jsonResponse, oauthErrorResponse, preflight, readForm } from "@/auth/http";
import { getDb } from "@/db";

export async function POST(request: Request) {
  try {
    return jsonResponse(await exchangeToken(getDb(), await readForm(request)));
  } catch (error) {
    return oauthErrorResponse(error);
  }
}

export const OPTIONS = preflight;
