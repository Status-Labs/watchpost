import { createHash, timingSafeEqual } from "node:crypto";

// Compares secrets in constant time. Hashing first makes the lengths equal.
export function secretsMatch(given: string, expected: string): boolean {
  const a = createHash("sha256").update(given).digest();
  const b = createHash("sha256").update(expected).digest();
  return timingSafeEqual(a, b);
}

const MIN_SECRET_LENGTH = 32;
const EXAMPLE_SECRET = "dev-cron-secret";

// Vercel Cron sends `Authorization: Bearer <CRON_SECRET>`.
export function isAuthorizedCron(request: Request): boolean {
  const secret = process.env.CRON_SECRET;
  if (!secret) return false;
  // A short or copied-from-.env.example secret in production is as good as none.
  if (process.env.NODE_ENV === "production" && (secret.length < MIN_SECRET_LENGTH || secret === EXAMPLE_SECRET)) {
    console.error("CRON_SECRET is too weak; generate one with `openssl rand -base64 32`. Refusing cron requests.");
    return false;
  }
  const header = request.headers.get("authorization") ?? "";
  return secretsMatch(header, `Bearer ${secret}`);
}
