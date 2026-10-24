import type { Metadata } from "next";
import Link from "next/link";
import { notFound, permanentRedirect } from "next/navigation";
import { Suspense } from "react";
import { ExploitedBadge, RansomwareBadge } from "@/components/exploited";
import { SeverityBadge } from "@/components/severity";
import { affectedPackages } from "@/lib/affected";
import { KEV_CATALOG_URL, vulnPath } from "@/lib/site";
import { lookupVuln as loadVuln } from "@/lib/cached";
import type { KevEntry, VulnDetail } from "@/lib/vulns";

// loadVuln is cached (see lib/cached.ts), so after a CVE page's first visit it
// becomes a static page. Anything that isn't an advisory ID is a 404 without
// touching the database.

// Cache Components only turns visited pages into static pages when this returns
// at least one param. The placeholder fails the advisory-ID check, so the build
// renders it as a 404 without touching the database; real CVE pages become
// static after their first visit.
export function generateStaticParams() {
  return [{ id: "__shell__" }];
}

export async function generateMetadata({ params }: PageProps<"/vulns/[id]">): Promise<Metadata> {
  const { id } = await params;
  const { id: validId, vuln, aliasMatches, exploit } = await loadVuln(id);
  if (exploit) {
    return {
      title: `${exploit.cveId}: ${exploit.name}`,
      description: `${exploit.vendor} ${exploit.product}: listed in CISA's Known Exploited Vulnerabilities catalog.`,
      alternates: { canonical: vulnPath(exploit.cveId), types: { "text/markdown": `${vulnPath(exploit.cveId)}.md` } },
    };
  }
  // Never echo an unknown URL into the title: it would let anyone make a
  // convincing page on our domain ("Security notice: your account...").
  if (!vuln) return { title: validId && aliasMatches.length ? validId : "Not found" };
  return {
    title: vuln.summary ? `${vuln.id}: ${vuln.summary}` : vuln.id,
    description: vuln.summary ?? `Details for ${vuln.id}.`,
    alternates: {
      canonical: vulnPath(vuln.id),
      types: { "text/markdown": `${vulnPath(vuln.id)}.md` },
    },
  };
}

export default function VulnPage({ params }: PageProps<"/vulns/[id]">) {
  return (
    <div className="mx-auto w-full max-w-5xl px-4 py-10">
      <Link href="/vulns" className="label min-h-11 content-center text-muted hover:text-foreground">
        ← All vulnerabilities
      </Link>
      <Suspense fallback={<div className="mt-6 h-40 border border-border bg-surface" aria-busy="true" />}>
        <VulnContent params={params} />
      </Suspense>
    </div>
  );
}

async function VulnContent({ params }: Pick<PageProps<"/vulns/[id]">, "params">) {
  const { id: validId, vuln, aliasMatches, exploit } = await loadVuln((await params).id);

  if (exploit) return <KevDetails entry={exploit} />;
  if (!vuln) {
    if (aliasMatches.length === 1) permanentRedirect(vulnPath(aliasMatches[0]));
    if (validId && aliasMatches.length > 1) return <AliasMatches alias={validId} ids={aliasMatches} />;
    notFound();
  }
  return <VulnDetails vuln={vuln} />;
}

function VulnDetails({ vuln }: { vuln: VulnDetail }) {
  const affected = affectedPackages(vuln.record);

  return (
    <article className="mt-4 flex flex-col gap-8">
      <header className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-3">
          <SeverityBadge severity={vuln.severity} />
          {vuln.cvssScore !== null && <span className="label text-muted">CVSS {vuln.cvssScore}</span>}
          {vuln.exploits.length > 0 && <ExploitedBadge />}
          {vuln.exploits.some((e) => e.ransomware) && <RansomwareBadge />}
          {vuln.withdrawn && <span className="label border border-foreground px-2">Withdrawn</span>}
        </div>
        <h1 className="break-words font-mono text-2xl font-semibold sm:text-3xl">{vuln.id}</h1>
        {vuln.summary && <p className="text-lg">{vuln.summary}</p>}
      </header>

      <dl className="grid grid-cols-1 gap-px border border-border bg-border text-sm sm:grid-cols-3">
        <Fact label="Published" value={vuln.published?.toISOString().slice(0, 10) ?? "Unknown"} />
        <Fact label="Modified" value={vuln.modified.toISOString().slice(0, 10)} />
        <Fact label="Aliases" value={vuln.aliases.length ? vuln.aliases.join(", ") : "None"} />
      </dl>

      {vuln.exploits.map((entry) => (
        <ExploitNotice key={entry.cveId} entry={entry} />
      ))}

      {affected.length > 0 && (
        <section aria-labelledby="affected-heading">
          <h2 id="affected-heading" className="mb-2 text-sm font-semibold">
            Affected packages
          </h2>
          <ul className="divide-y divide-border border border-border bg-surface">
            {affected.map((pkg, i) => (
              <li key={`${pkg.ecosystem}/${pkg.name}/${i}`} className="flex flex-col gap-1 px-4 py-3">
                <span className="break-all font-mono text-sm">
                  {pkg.ecosystem}/{pkg.name}
                </span>
                <span className="font-mono text-xs text-muted">
                  {pkg.ranges.length ? pkg.ranges.join("; ") : `${pkg.versionCount} listed versions`}
                </span>
              </li>
            ))}
          </ul>
        </section>
      )}

      {vuln.details && (
        <section aria-labelledby="details-heading">
          <h2 id="details-heading" className="mb-2 text-sm font-semibold">
            Details
          </h2>
          {/* Upstream text is untrusted: rendered as plain text, never as HTML. */}
          <div className="overflow-x-auto whitespace-pre-wrap break-words border border-border bg-surface p-4 text-sm leading-relaxed">
            {vuln.details}
          </div>
        </section>
      )}

      <footer className="flex flex-wrap gap-4">
        <a
          href={`https://osv.dev/vulnerability/${encodeURIComponent(vuln.id)}`}
          className="label min-h-11 content-center border border-foreground px-4"
        >
          View on OSV.dev
        </a>
        <a href={`${vulnPath(vuln.id)}.md`} className="label min-h-11 content-center text-muted hover:text-foreground">
          Markdown
        </a>
        <a
          href={`/api/vulns/${encodeURIComponent(vuln.id)}`}
          className="label min-h-11 content-center text-muted hover:text-foreground"
        >
          JSON
        </a>
      </footer>
    </article>
  );
}

function Fact({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex flex-col gap-1 bg-surface px-4 py-3">
      <dt className="label text-muted">{label}</dt>
      <dd className="break-words font-mono">{value}</dd>
    </div>
  );
}

function AliasMatches({ alias, ids }: { alias: string; ids: string[] }) {
  return (
    <section className="mt-4 flex flex-col gap-4">
      <h1 className="break-words font-mono text-2xl font-semibold">{alias}</h1>
      <p className="text-sm text-muted">This ID appears in several advisories:</p>
      <ul className="divide-y divide-border border border-border bg-surface">
        {ids.map((id) => (
          <li key={id}>
            <Link href={vulnPath(id)} className="block px-4 py-3 font-mono text-sm hover:bg-background">
              {id}
            </Link>
          </li>
        ))}
      </ul>
    </section>
  );
}

const day = (date: Date) => date.toISOString().slice(0, 10);

// CISA's entry for an advisory's CVE: attackers are using it, so it comes first.
function ExploitNotice({ entry }: { entry: KevEntry }) {
  return (
    <section aria-label="Known exploited" className="flex flex-col gap-2 border-2 border-foreground bg-surface p-4">
      <p className="text-sm font-semibold">
        CISA lists {entry.cveId} as exploited in the wild (added {day(entry.dateAdded)}
        {entry.ransomware ? ", used in ransomware campaigns" : ""}).
      </p>
      <p className="text-sm text-muted">{entry.requiredAction}</p>
    </section>
  );
}

// A CVE that CISA lists as exploited, with no package advisory: usually an
// operating system, device or commercial product.
function KevDetails({ entry }: { entry: KevEntry }) {
  return (
    <article className="mt-4 flex flex-col gap-8">
      <header className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-3">
          <ExploitedBadge />
          {entry.ransomware && <RansomwareBadge />}
        </div>
        <h1 className="break-words font-mono text-2xl font-semibold sm:text-3xl">{entry.cveId}</h1>
        <p className="text-lg">{entry.name}</p>
      </header>

      <dl className="grid grid-cols-1 gap-px border border-border bg-border text-sm sm:grid-cols-3">
        <Fact label="Product" value={`${entry.vendor} ${entry.product}`} />
        <Fact label="Added to KEV" value={day(entry.dateAdded)} />
        <Fact label="Federal due date" value={entry.dueDate ? day(entry.dueDate) : "None"} />
      </dl>

      <section aria-labelledby="description-heading">
        <h2 id="description-heading" className="mb-2 text-sm font-semibold">
          Description
        </h2>
        <p className="whitespace-pre-wrap break-words border border-border bg-surface p-4 text-sm leading-relaxed">
          {entry.description}
        </p>
      </section>

      <section aria-labelledby="action-heading">
        <h2 id="action-heading" className="mb-2 text-sm font-semibold">
          Required action
        </h2>
        <p className="whitespace-pre-wrap break-words border border-border bg-surface p-4 text-sm leading-relaxed">
          {entry.requiredAction}
        </p>
      </section>

      <footer className="flex flex-wrap gap-4">
        <a href={KEV_CATALOG_URL} className="label min-h-11 content-center border border-foreground px-4">
          CISA KEV catalog
        </a>
        <a
          href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(entry.cveId)}`}
          className="label min-h-11 content-center text-muted hover:text-foreground"
        >
          NVD
        </a>
        <a href={`${vulnPath(entry.cveId)}.md`} className="label min-h-11 content-center text-muted hover:text-foreground">
          Markdown
        </a>
        <a
          href={`/api/vulns/${encodeURIComponent(entry.cveId)}`}
          className="label min-h-11 content-center text-muted hover:text-foreground"
        >
          JSON
        </a>
      </footer>
    </article>
  );
}
