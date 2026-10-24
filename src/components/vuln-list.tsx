import Link from "next/link";
import { vulnPath } from "@/lib/site";
import type { VulnSummary } from "@/lib/vulns";
import { ExploitedBadge, RansomwareBadge } from "./exploited";
import { SeverityBadge } from "./severity";

const MAX_PACKAGES_SHOWN = 3;

export function VulnList({ vulns }: { vulns: VulnSummary[] }) {
  if (vulns.length === 0) {
    return (
      <div className="border border-border bg-surface px-4 py-10 text-center text-sm text-muted">
        No vulnerabilities match.
      </div>
    );
  }

  return (
    <ul className="divide-y divide-border border border-border bg-surface">
      {vulns.map((vuln) => (
        <li key={vuln.id}>
          <Link
            href={vulnPath(vuln.id)}
            className="flex flex-col gap-1.5 px-4 py-3 hover:bg-background sm:flex-row sm:items-start sm:gap-4"
          >
            <div className="flex items-center justify-between gap-3 sm:w-28 sm:shrink-0 sm:pt-0.5">
              {/* CISA entries without a package advisory have no severity score. */}
              {vuln.product ? <ExploitedBadge /> : <SeverityBadge severity={vuln.severity} />}
              <Published date={vuln.published} className="sm:hidden" />
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="truncate font-mono text-sm">{vuln.id}</span>
                {vuln.exploited && !vuln.product && <ExploitedBadge />}
                {vuln.ransomware && <RansomwareBadge />}
              </div>
              <div className="line-clamp-2 text-sm text-muted">{vuln.summary ?? "No summary"}</div>
              {vuln.product ? (
                <div className="mt-1 truncate font-mono text-xs text-muted">
                  {vuln.product.vendor} / {vuln.product.product}
                </div>
              ) : (
                <PackageList packages={vuln.packages} />
              )}
            </div>
            <Published date={vuln.published} className="hidden sm:block sm:pt-0.5" />
          </Link>
        </li>
      ))}
    </ul>
  );
}

function PackageList({ packages }: { packages: VulnSummary["packages"] }) {
  if (packages.length === 0) return null;
  const shown = packages.slice(0, MAX_PACKAGES_SHOWN);
  const hidden = packages.length - shown.length;
  return (
    <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1 font-mono text-xs text-muted">
      {shown.map((p) => (
        <span key={`${p.ecosystem}/${p.name}`} className="max-w-full truncate">
          {p.ecosystem}/{p.name}
        </span>
      ))}
      {hidden > 0 && <span>+{hidden} more</span>}
    </div>
  );
}

function Published({ date, className = "" }: { date: Date | null; className?: string }) {
  if (!date) return null;
  return (
    <time dateTime={date.toISOString()} className={`shrink-0 font-mono text-xs text-muted ${className}`}>
      {date.toISOString().slice(0, 10)}
    </time>
  );
}

export function VulnListSkeleton({ rows = 8 }: { rows?: number }) {
  return (
    <ul className="divide-y divide-border border border-border bg-surface" aria-busy="true">
      {Array.from({ length: rows }, (_, i) => (
        <li key={i} className="px-4 py-3">
          <div className="h-4 w-1/3 bg-border" />
          <div className="mt-2 h-3 w-2/3 bg-border" />
        </li>
      ))}
    </ul>
  );
}
