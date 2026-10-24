import { isVulnId } from "./sanitize";

// Next.js has already decoded route params. Anything that isn't shaped like an
// advisory ID (including NUL bytes, which Postgres rejects) is treated as not found.
export function parseVulnId(id: string): string | null {
  return isVulnId(id) ? id : null;
}

export const PUBLIC_CACHE_HEADERS = {
  // Public data, refreshed every 15 minutes by the sync. The CDN serves cached
  // copies, so most requests never reach the server or the database.
  "Cache-Control": "public, s-maxage=900, stale-while-revalidate=3600",
};
