// Deployment settings come from env vars, so anyone can self-host under their own name.
export const SITE_NAME = process.env.SITE_NAME ?? "Watchpost";

export const SITE_DESCRIPTION =
  "Public CVE and vulnerability data, with alerts for the packages in your stack.";

export function siteUrl(path = ""): string {
  const base =
    process.env.SITE_URL ??
    (process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : "http://localhost:3000");
  return new URL(path, base.endsWith("/") ? base : `${base}/`).toString();
}

export function vulnPath(id: string): string {
  return `/vulns/${encodeURIComponent(id)}`;
}

export const OSV_ATTRIBUTION =
  "Vulnerability data from OSV.dev, licensed under CC BY 4.0.";

export const SOURCE_URL = process.env.SOURCE_URL ?? "https://github.com/Status-Labs/watchpost";

export const KEV_CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog";
