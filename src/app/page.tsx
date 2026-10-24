import Link from "next/link";
import { connection } from "next/server";
import { Suspense } from "react";
import { PromptTabs } from "@/components/prompt-tabs";
import { SeverityBadge } from "@/components/severity";
import { VulnList, VulnListSkeleton } from "@/components/vuln-list";
import type { Severity } from "@/db/schema";
import { agentGuides } from "@/lib/snippets";
import { SOURCE_URL } from "@/lib/site";
import { homeOverview } from "@/lib/cached";
import type { RecentCounts } from "@/lib/vulns";

const PRIORITY_COUNT = 10;
const LATEST_COUNT = 15;

export default function Home() {
  return (
    <div className="mx-auto w-full max-w-5xl px-4">
      <Hero />
      <HowItWorks />
      <Suspense fallback={<OverviewSkeleton />}>
        <Overview />
      </Suspense>
      <ClosingCta />
    </div>
  );
}

async function Overview() {
  // Rendered per request (no database at build time); the queries come from the shared cache.
  await connection();
  const { windowDays, counts, critical, recent } = await homeOverview({ priority: PRIORITY_COUNT, latest: LATEST_COUNT });

  return (
    <>
      <Section title={`New advisories · last ${windowDays} days`}>
        <SeverityCounts counts={counts} />
      </Section>
      <Section title="Critical and high" link={{ href: "/vulns?severity=critical,high&sort=severity", label: "View all" }}>
        <VulnList vulns={critical} />
      </Section>
      <Section title="Latest advisories" link={{ href: "/vulns", label: "View all" }}>
        <VulnList vulns={recent} />
      </Section>
    </>
  );
}

function Section({
  title,
  link,
  children,
}: {
  title: string;
  link?: { href: string; label: string };
  children: React.ReactNode;
}) {
  return (
    <section className="mt-8">
      <div className="mb-2 flex items-end justify-between gap-4">
        <h2 className="text-sm font-semibold">{title}</h2>
        {link && (
          <Link href={link.href} className="label min-h-11 content-center text-muted hover:text-foreground sm:min-h-0">
            {link.label} →
          </Link>
        )}
      </div>
      {children}
    </section>
  );
}

const COUNTED: (Severity | "unknown")[] = ["critical", "high", "medium", "low", "unknown"];

function SeverityCounts({ counts }: { counts: RecentCounts }) {
  const tile = "flex h-full flex-col gap-1 bg-surface px-4 py-3";
  return (
    <ul className="grid grid-cols-2 gap-px border border-border bg-border sm:grid-cols-4 lg:grid-cols-7">
      {COUNTED.map((severity) => {
        const content = (
          <>
            <SeverityBadge severity={severity === "unknown" ? null : severity} />
            <span className="font-mono text-2xl">{counts[severity]}</span>
          </>
        );
        return (
          <li key={severity}>
            {severity === "unknown" ? (
              <div className={tile}>{content}</div>
            ) : (
              <Link href={`/vulns?severity=${severity}`} className={`${tile} hover:bg-background`}>
                {content}
              </Link>
            )}
          </li>
        );
      })}
      <li>
        <Link href="/vulns?type=exploited" className={`${tile} hover:bg-background`}>
          <span className="label inline-flex items-center gap-1.5">
            <span aria-hidden="true">▲</span>
            Exploited
          </span>
          <span className="font-mono text-2xl">{counts.exploited}</span>
        </Link>
      </li>
      <li>
        <Link href="/vulns?type=malware" className={`${tile} hover:bg-background`}>
          <span className="label inline-flex items-center gap-1.5 text-muted">
            <span className="size-2 border border-foreground" aria-hidden="true" />
            Malicious pkgs
          </span>
          <span className="font-mono text-2xl">{counts.malware}</span>
        </Link>
      </li>
    </ul>
  );
}

function Hero() {
  return (
    <section className="flex flex-col items-start gap-5 border-b border-border py-10 sm:py-12">
      <h1 className="max-w-3xl text-4xl font-semibold leading-[1.05] tracking-tight sm:text-5xl">
        Know when a CVE{" "}
        <span className="inline-block size-[0.7em] translate-y-[0.05em] rounded-full bg-brand" aria-hidden="true" />{" "}
        hits your stack.
      </h1>
      <p className="label text-muted">Public vulnerability data. Private checks. Nothing stored. No sign-up.</p>
      <div className="flex flex-wrap gap-3">
        <Link href="/check" className="label inline-flex min-h-11 items-center rounded-full bg-brand px-5 text-black">
          Check your dependencies
        </Link>
        <Link
          href="/vulns"
          className="label inline-flex min-h-11 items-center rounded-full bg-muted px-5 text-background"
        >
          Browse CVEs
        </Link>
      </div>
      <SetupPrompt />
    </section>
  );
}

// Small but obvious: a tab per AI app, with the full prompt behind "Show".
function SetupPrompt() {
  return (
    <div className="w-full max-w-2xl">
      <h2 className="label mb-2 text-muted">Set up your AI assistant</h2>
      <PromptTabs guides={agentGuides()} />
    </div>
  );
}

const STEPS = [
  {
    title: "Check your stack",
    body: "Drop a lockfile here, or let your AI assistant check over MCP. Package names and versions only, and nothing is stored.",
    soon: false,
    block: "bg-foreground text-background",
    shape: <span className="block size-7 rounded-full bg-brand" />,
  },
  {
    title: "We watch OSV and CISA",
    body: "New advisories for npm, PyPI, Go, crates.io, Maven and more every 15 minutes, plus CISA's list of CVEs attackers are exploiting.",
    soon: false,
    block: "bg-brand text-black",
    shape: <span className="block size-7 bg-black" />,
  },
  {
    title: "Run it on a schedule",
    body: "A cron job or coding agent on your machine checks every week and reports what affects you, with the versions that fix it.",
    soon: false,
    block: "bg-muted text-background",
    shape: <span className="block size-0 border-x-[14px] border-b-[24px] border-x-transparent border-b-background" />,
  },
];

function HowItWorks() {
  return (
    <section aria-labelledby="how-heading" className="mt-8">
      <div className="mb-2 flex items-end justify-between gap-4">
        <h2 id="how-heading" className="text-sm font-semibold">
          How it works
        </h2>
        <Link href="/docs" className="label min-h-11 content-center text-muted hover:text-foreground sm:min-h-0">
          Read the docs →
        </Link>
      </div>
      <ol className="grid gap-3 md:grid-cols-3">
        {STEPS.map((step) => (
          <li key={step.title} className={`flex flex-col gap-4 rounded-bento p-6 ${step.block}`}>
            <div className="flex items-start justify-between">
              <span aria-hidden="true">{step.shape}</span>
              {step.soon && <span className="label opacity-80">Coming soon</span>}
            </div>
            <div className="flex flex-col gap-1.5">
              <h3 className="text-lg font-semibold">{step.title}</h3>
              <p className="text-sm opacity-90">{step.body}</p>
            </div>
          </li>
        ))}
      </ol>
    </section>
  );
}

function ClosingCta() {
  return (
    <section className="mt-12 flex flex-col items-start gap-3 border-t border-border py-10 sm:flex-row sm:items-center sm:justify-between">
      <div>
        <h2 className="text-xl font-semibold tracking-tight">Open source, MIT licensed.</h2>
        <p className="mt-1 text-sm text-muted">Read the code, run your own copy, or help build it.</p>
      </div>
      <a href={SOURCE_URL} className="label inline-flex min-h-11 items-center rounded-full bg-brand px-5 text-black">
        View on GitHub
      </a>
    </section>
  );
}

function OverviewSkeleton() {
  return (
    <div aria-busy="true">
      <div className="mt-8 h-[74px] border border-border bg-surface" />
      <div className="mt-8">
        <VulnListSkeleton rows={PRIORITY_COUNT} />
      </div>
    </div>
  );
}
