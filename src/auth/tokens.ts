import { createHash, randomBytes } from "node:crypto";

// Every secret has a type prefix so secret scanners (and people) can tell what
// leaked: wpa_ access token, wpr_ refresh token, wpk_ static key.
// Authorization codes (wpc_) are short-lived but follow the same rules.
export const TOKEN_PREFIXES = {
  access: "wpa_",
  refresh: "wpr_",
  key: "wpk_",
  code: "wpc_",
} as const;

// 256 bits of randomness, base64url.
export function newSecret(prefix: string): string {
  return `${prefix}${randomBytes(32).toString("base64url")}`;
}

// Secrets are random, so a fast hash is enough; only hashes are stored.
export function hashSecret(secret: string): string {
  return createHash("sha256").update(secret).digest("hex");
}

// Public identifiers (not secrets), like OAuth client IDs.
export function newId(prefix: string): string {
  return `${prefix}${randomBytes(16).toString("base64url")}`;
}

// PKCE S256: base64url(sha256(verifier)).
export function pkceChallenge(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}
