import type { Metadata } from "next";
import Link from "next/link";
import type { ReactNode } from "react";
import { CopyButton } from "@/components/copy-button";
import { PromptTabs } from "@/components/prompt-tabs";
import { CATEGORIES } from "@/lib/categories";
import { agentGuides, mcpConfigJson, scheduledCheckPrompt, scriptCronLine, scriptSnippets } from "@/lib/snippets";
import { KEV_CATALOG_URL, SITE_NAME, SOURCE_URL, siteUrl } from "@/lib/site";

export const metadata: Metadata = {
  title: "Docs",
  description: `What ${SITE_NAME} is, how to check your dependencies, run checks on a schedule, and use the MCP server and RSS feeds.`,
  alternates: { canonical: "/docs" },
};

const SECTIONS = [
  ["about", "What it is"],
  ["check", "Check your dependencies"],
  ["mcp", "MCP server"],
  ["automate", "Run checks on a schedule"],
  ["browse", "Browse CVEs"],
  ["rss", "RSS feeds"],
  ["agents", "For AI agents"],
  ["privacy", "Privacy and security"],
  ["data", "Data sources"],
] as const;

export default function DocsPage() {
  const guides = agentGuides();

  return (
    <div className="mx-auto w-full max-w-5xl px-4 py-10 lg:grid lg:grid-cols-[180px_1fr] lg:gap-12">
      <nav aria-label="On this page" className="mb-8 lg:sticky lg:top-24 lg:mb-0 lg:self-start">
        <p className="label mb-2 text-muted">On this page</p>
        <ul className="flex flex-wrap gap-x-4 gap-y-1 lg:flex-col">
          {SECTIONS.map(([id, title]) => (
            <li key={id}>
              <a href={`#${id}`} className="inline-flex min-h-11 items-center text-sm text-muted hover:text-foreground lg:min-h-8">
                {title}
              </a>
            </li>
          ))}
        </ul>
      </nav>

      <article className="flex min-w-0 flex-col gap-12">
        <header>
          <h1 className="text-3xl font-semibold tracking-tight">Docs</h1>
          <p className="mt-2 text-muted">Everything {SITE_NAME} does, on one page.</p>
        </header>

        <Section id="about" title="What it is">
          <P>
            {SITE_NAME} collects public vulnerability data (CVEs and security advisories) and tells you when one
            affects the software you run. It&apos;s free, open source, and anonymous: no sign-up, no email, no
            personal information.
          </P>
          <P>Ways to use it:</P>
          <ul className="flex flex-col gap-2 text-sm">
            <Li title="Check">Drop a lockfile on the site and see what affects you. Nothing is stored.</Li>
            <Li title="MCP">Let your AI assistant check your project, with no sign-in.</Li>
            <Li title="Schedule">Run the check weekly from a cron job or a coding agent on your machine.</Li>
            <Li title="Browse">
              Search and filter recent advisories and known exploited CVEs. Every view has a shareable link.
            </Li>
            <Li title="RSS">Build a feed for the languages, categories and packages you care about.</Li>
          </ul>
        </Section>

        <Section id="check" title="Check your dependencies">
          <P>
            <Link href="/check" className="underline hover:text-brand">
              Drop a lockfile
            </Link>{" "}
            (package-lock.json, pnpm-lock.yaml, yarn.lock, requirements.txt, poetry.lock, uv.lock, Cargo.lock, go.mod,
            Gemfile.lock or composer.lock) and see every known vulnerability affecting the exact versions you have
            installed. Your file is read in your browser: only package names and versions are sent, and nothing is
            stored. package.json alone doesn&apos;t work, because it holds version ranges rather than installed
            versions.
          </P>
          <P>Scripts can use the same check. No key needed:</P>
          <CodeBlock>{`curl -fsS -H 'Content-Type: application/json' \\
  -d '{"packages": [{"ecosystem": "npm", "name": "lodash", "version": "4.17.15"}]}' \\
  '${siteUrl("/api/check?format=text")}'`}</CodeBlock>
          <P>
            Leave out <Code>?format=text</Code> for JSON. Up to 5,000 packages per request.
          </P>
        </Section>

        <Section id="browse" title="Browse CVEs">
          <P>
            <Link href="/vulns" className="underline hover:text-brand">
              The CVE list
            </Link>{" "}
            opens on critical CVEs, newest first. It combines open source package advisories with CISA&apos;s
            catalog of known exploited vulnerabilities, which also covers operating systems, devices and commercial
            software. Results update as you change the filters:
          </P>
          <ul className="flex flex-col gap-2 text-sm">
            <Li title="Search">A CVE or advisory ID, part of a package name, or a word from the summary or product.</Li>
            <Li title="Show">
              CVEs and advisories (the default), known exploited only, package advisories only, malicious packages, or
              everything.
            </Li>
            <Li title="Language">The package ecosystem: JavaScript (npm), Python (PyPI), Go, Rust, Java and more.</Li>
            <Li title="Category">
              {Object.values(CATEGORIES)
                .map((c) => c.label)
                .join(", ")}
              . Matched by package and product names, so treat it as a best guess.
            </Li>
            <Li title="Severity">
              CISA doesn&apos;t publish severity scores, so the exploited view shows every severity unless you pick one.
            </Li>
          </ul>
          <P>Filters live in the URL, so you can bookmark or share any view:</P>
          <Examples
            items={[
              ["/vulns?type=exploited", "Everything CISA lists as exploited"],
              ["/vulns?category=databases&severity=critical,high", "Critical and high, databases"],
              ["/vulns?ecosystem=npm&category=web&severity=all", "Every npm web framework advisory"],
              ["/vulns?q=log4j&severity=all", "Search for a package or product"],
              ["/vulns?type=malware", "Malicious packages"],
            ]}
          />
          <P>
            Each advisory has its own page, like <Code>/vulns/GHSA-xxxx-xxxx-xxxx</Code>. A CVE ID such as{" "}
            <Code>/vulns/CVE-2026-1234</Code> takes you to the matching advisory, or to CISA&apos;s entry for an
            exploited CVE that no package advisory covers. Advisories for exploited CVEs carry an Exploited badge.
          </P>
          <P>
            Malicious-package reports (fake look-alike packages) are hidden by default because hundreds arrive each
            week. Choose &ldquo;Malicious packages&rdquo; or &ldquo;Everything&rdquo; under Show to see them.
          </P>
        </Section>

        <Section id="rss" title="RSS feeds">
          <P>
            <Link href="/rss" className="underline hover:text-brand">
              Build a feed
            </Link>{" "}
            by picking what to include: known exploited CVEs, severities, languages, categories, packages or a keyword.
            You get a feed URL to copy and a preview of what it will show. The &ldquo;RSS for this view&rdquo; link
            on the CVE list opens the builder with your current filters.
          </P>
          <P>
            Feeds are public and need no key. The filters are part of the URL, so anyone who sees it (your feed reader,
            a Slack channel) can see what you follow. Stick to languages and categories, or public packages you
            don&apos;t mind sharing.
          </P>
          <h3 className="mt-2 text-sm font-semibold">Where to use it</h3>
          <ul className="flex flex-col gap-2 text-sm">
            <Li title="Feed readers">Paste the feed URL into Feedly, NetNewsWire, Inoreader or any RSS reader.</Li>
            <Li title="Slack">
              Use Slack&apos;s RSS app: <Code>/feed subscribe {siteUrl("/feed.xml?severity=critical")}</Code>
            </Li>
            <Li title="Discord">Add the feed with an RSS bot such as MonitoRSS.</Li>
            <Li title="Email">Point any RSS-to-email service at the feed. That service learns your address; we never do.</Li>
            <Li title="Scripts">It&apos;s plain RSS 2.0: poll it from a cron job or CI and act on new items.</Li>
          </ul>
        </Section>

        <Section id="mcp" title="MCP server">
          <P>
            Any AI app or coding agent that supports MCP servers can check your project for you. The server needs no
            sign-in and stores nothing.
          </P>
          <h3 className="mt-2 text-sm font-semibold">Set it up</h3>
          <P>Pick your app: add the server once, then paste the prompt.</P>
          <PromptTabs guides={guides} expanded />
          <P>Other apps take the server as a remote (Streamable HTTP) MCP server, usually with a config like this:</P>
          <CodeBlock>{mcpConfigJson()}</CodeBlock>
          <h3 className="mt-2 text-sm font-semibold">Tools</h3>
          <ul className="flex flex-col gap-2 text-sm">
            <Li title="check_packages">
              Check a list of packages and versions. Returns the known vulnerabilities, known exploited first, then
              worst first, with the versions that fix them.
            </Li>
            <Li title="search_vulns">Search recent advisories and CISA&apos;s exploited catalog by ID, package, keyword or category.</Li>
            <Li title="get_vuln">Full details for one advisory or CVE, including whether it&apos;s known to be exploited.</Li>
          </ul>
          <h3 className="mt-2 text-sm font-semibold">Optional: keep your stacks</h3>
          <P>
            If you&apos;d like {SITE_NAME} to remember your stacks between sessions, use{" "}
            <Code>{siteUrl("/api/mcp/workspace")}</Code> instead. It adds <Code>report_stack</Code>,{" "}
            <Code>get_alerts</Code>, <Code>list_stacks</Code>, <Code>delete_stack</Code> and{" "}
            <Code>delete_workspace</Code>. There&apos;s still no account: your app opens a {SITE_NAME} page where you
            click &ldquo;Create a private workspace&rdquo;, and gets its token directly, so it never passes through the
            chat. Apps that can&apos;t sign in this way can{" "}
            <Link href="/key" className="underline hover:text-brand">
              get a key
            </Link>{" "}
            and keep it in an environment variable. Workspaces unused for 90 days are deleted.
          </P>
          <h3 className="mt-2 text-sm font-semibold">Keep it anonymous</h3>
          <ul className="flex list-disc flex-col gap-1 pl-5 text-sm text-muted">
            <li>Only package names and versions are accepted. Anything that looks like a path, hostname, IP address, email or secret is rejected.</li>
            <li>Leave out private or internal packages: public advisories don&apos;t cover them, and their names can identify your company.</li>
            <li>Name stacks generically (&ldquo;laptop&rdquo;, &ldquo;web-app&rdquo;), never anything that can be traced back to you or your company.</li>
            <li>Advisory text is written by third parties. Your assistant should treat it as information, not instructions.</li>
          </ul>
        </Section>

        <Section id="automate" title="Run checks on a schedule">
          <P>
            The most private setup: a job on your own machine checks your project every week. Nothing is stored
            anywhere, and the report stays on your machine.
          </P>
          <h3 className="mt-2 text-sm font-semibold">With a coding agent</h3>
          <P>
            Coding agents with a non-interactive mode can run the check unattended. Add the MCP server (above), then
            save this prompt as <Code>~/.config/watchpost/check-prompt.txt</Code>:
          </P>
          <CodeBlock wrap>{scheduledCheckPrompt()}</CodeBlock>
          <P>
            Then run it from cron (<Code>crontab -e</Code>). Each line below runs every Monday at 9:00 and lets the
            agent only read files and call <Code>check_packages</Code>, so it can&apos;t edit files or run commands.
          </P>
          {guides.flatMap(({ id, label, scheduled }) =>
            scheduled
              ? [
                  <div key={id} className="flex flex-col gap-2">
                    <h4 className="label">{label}</h4>
                    {scheduled.config && (
                      <>
                        <span className="text-xs text-muted">{scheduled.config.label}:</span>
                        <CodeBlock>{scheduled.config.code}</CodeBlock>
                      </>
                    )}
                    <CodeBlock>{scheduled.command}</CodeBlock>
                  </div>,
                ]
              : [],
          )}
          <P>
            Codex runs <Code>codex exec</Code> in a read-only sandbox. Other agents work the same way through their
            non-interactive mode (for example <Code>gemini -p</Code>): allow only file reads and{" "}
            <Code>check_packages</Code>.
          </P>
          <h3 className="mt-2 text-sm font-semibold">With a script, no AI</h3>
          <P>
            List exact installed versions with your ecosystem&apos;s own tools, shape them with{" "}
            <a href="https://jqlang.org" className="underline hover:text-brand">
              jq
            </a>
            , and post them. Run from the project folder:
          </P>
          {scriptSnippets().map(({ label, command }) => (
            <div key={label} className="flex flex-col gap-1">
              <span className="label text-muted">{label}</span>
              <CodeBlock>{command}</CodeBlock>
            </div>
          ))}
          <P>
            Save the line for your project as <Code>~/.config/watchpost/check.sh</Code> and schedule it:
          </P>
          <CodeBlock>{scriptCronLine()}</CodeBlock>
        </Section>

        <Section id="agents" title="For AI agents">
          <P>Everything public is easy for LLMs and crawlers to read:</P>
          <ul className="flex flex-col gap-2 text-sm">
            <Li title="/llms.txt">A short guide to the site.</Li>
            <Li title="/vulns/{id}.md">Any advisory as markdown.</Li>
            <Li title="/api/vulns/{id}">Any advisory as JSON. Read-only, no key needed.</Li>
            <Li title="/feed.xml">RSS with the same filters as the CVE list.</Li>
            <Li title="/sitemap.xml">Every advisory page.</Li>
          </ul>
        </Section>

        <Section id="privacy" title="Privacy and security">
          <ul className="flex list-disc flex-col gap-1 pl-5 text-sm text-muted">
            <li>No accounts, emails or names. We don&apos;t store IP addresses. Our host&apos;s request logs see them briefly, like any website&apos;s.</li>
            <li>Checks (the drop-in form, the check API and the MCP server&apos;s check_packages) store nothing and log nothing.</li>
            <li>To answer a check, our server asks OSV.dev which known vulnerabilities affect each package version. OSV sees package names and versions from our servers, never anything that identifies you.</li>
            <li>If you choose to keep stacks in a workspace, we store only ecosystem, package name and version. Tokens are stored as hashes. Workspaces nobody uses for 90 days are deleted, and you can delete yours any time.</li>
            <li>
              Found a security issue? Please{" "}
              <a href={`${SOURCE_URL}/security/advisories/new`} className="underline hover:text-brand">
                report it privately
              </a>
              , never in a public issue.
            </li>
          </ul>
        </Section>

        <Section id="data" title="Data sources">
          <P>
            Vulnerability data comes from{" "}
            <a href="https://osv.dev" className="underline hover:text-brand">
              OSV.dev
            </a>{" "}
            (licensed under CC BY 4.0) and is refreshed every 15 minutes. It covers open source package ecosystems:
            npm, PyPI, Go, crates.io, Maven, NuGet, Packagist, RubyGems and more.
          </P>
          <P>
            Known exploited vulnerabilities come from{" "}
            <a href={KEV_CATALOG_URL} className="underline hover:text-brand">
              CISA&apos;s KEV catalog
            </a>
            , refreshed hourly. It lists CVEs that attackers are using right now, including operating systems, devices
            and commercial software that no package advisory covers.
          </P>
          <P>
            {SITE_NAME} is open source under the MIT license.{" "}
            <a href={SOURCE_URL} className="underline hover:text-brand">
              Read the code
            </a>
            , run your own copy, or help build it.
          </P>
        </Section>
      </article>
    </div>
  );
}

function Section({ id, title, soon, children }: { id: string; title: string; soon?: boolean; children: ReactNode }) {
  return (
    <section id={id} aria-labelledby={`${id}-heading`} className="flex scroll-mt-20 flex-col gap-3">
      <h2 id={`${id}-heading`} className="flex flex-wrap items-center gap-3 text-xl font-semibold tracking-tight">
        {title}
        {soon && <Badge>Coming soon</Badge>}
      </h2>
      {children}
    </section>
  );
}

function P({ children }: { children: ReactNode }) {
  return <p className="text-sm leading-relaxed">{children}</p>;
}

function Li({ title, soon, children }: { title: string; soon?: boolean; children: ReactNode }) {
  return (
    <li className="flex flex-col gap-0.5 sm:flex-row sm:gap-3">
      <span className="shrink-0 font-mono text-xs sm:w-32 sm:pt-0.5">{title}</span>
      <span className="text-muted">
        {children} {soon && <Badge>Coming soon</Badge>}
      </span>
    </li>
  );
}

function Badge({ children }: { children: ReactNode }) {
  return <span className="label border border-border-strong px-2 py-0.5 text-muted">{children}</span>;
}

function Code({ children }: { children: ReactNode }) {
  return <code className="break-all font-mono text-xs">{children}</code>;
}

// Commands scroll sideways so they stay copyable as one line; prose wraps.
function CodeBlock({ children, wrap = false }: { children: string; wrap?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-3 border border-border bg-surface py-1 pl-4 pr-1">
      <pre
        className={`min-w-0 flex-1 py-2.5 font-mono text-xs ${wrap ? "whitespace-pre-wrap break-words leading-relaxed" : "overflow-x-auto"}`}
      >
        {children}
      </pre>
      <CopyButton text={children} />
    </div>
  );
}

function Examples({ items }: { items: [string, string][] }) {
  return (
    <ul className="divide-y divide-border border border-border bg-surface">
      {items.map(([href, label]) => (
        <li key={href}>
          <a href={href} className="flex flex-col gap-0.5 px-4 py-2.5 hover:bg-background sm:flex-row sm:items-center sm:justify-between sm:gap-4">
            <span className="text-sm">{label}</span>
            <span className="break-all font-mono text-xs text-muted">{href}</span>
          </a>
        </li>
      ))}
    </ul>
  );
}
