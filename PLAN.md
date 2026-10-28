# Watchpost — Plan

**Watchpost** ([watchpost.now](https://watchpost.now)) is a web app that collects public CVE data and alerts users about vulnerabilities in their tech stack. Users' AI assistant (any app that supports MCP) reports the stack over MCP, and the app matches it against new CVEs.

## Core idea

1. **Collect**: pull CVEs from public sources on a schedule.
2. **Report**: the user's AI assistant inspects a machine or project and sends its stack (packages, versions, OS, services) to our MCP server.
3. **Match**: compare stack items against CVEs.
4. **Notify**: new matches show up through MCP (`get_alerts`). No private feeds: see "Notifications".

## No sign-up: workspaces

There are no user accounts, passwords, or logins. Your data lives in an anonymous **workspace**, and nothing in it identifies you.

- **Connecting your assistant:** the MCP server uses OAuth, the sign-in flow in the MCP spec. Paste the server URL into your AI app; it opens a Watchpost page in your browser; you click "Create a private workspace". The app receives its token directly. You never see it, and it never passes through the AI chat, a URL, or a command you type.
- **Apps without OAuth support:** click "Get a key" on the site (shown once) and put it in an environment variable that your MCP config references. Never paste a key into the chat.
- A workspace holds any number of stacks (laptop, prod-api, etc.).
- Lost access? There's no recovery by design: create a new workspace and have your assistant report the stack again, which takes seconds. Any connected app can revoke its access or delete the workspace.
- Inactive workspaces are deleted automatically after 90 days. Any MCP call, dashboard visit, or feed fetch counts as activity, so abandoned data doesn't pile up.

**We collect no personal info**: no emails, names, or accounts. A workspace is just random tokens plus package lists, so a breach shouldn't be able to tie a vulnerable stack to a person or company. The one weak spot is stack labels: a label like "acme-payments-prod" would reveal the company. So labels are restricted to short slugs, and we warn both the assistant and the user: "Don't name a stack anything that can be traced back to you." That warning goes in the `report_stack` tool description, next to the label in the dashboard, and in the setup docs.

## Stack

- **Next.js (App Router) + TypeScript**
- **Neon Postgres** + **Drizzle ORM**
- **MCP server**: a Next.js route (`/api/mcp`) using `mcp-handler`
- **Cron**: Vercel Cron for syncing and matching. Crons more often than daily need the Vercel Pro plan; Hobby only allows daily.

## Data sources

| Source | Why |
|---|---|
| [OSV.dev](https://osv.dev) | Package-level vulns (npm, PyPI, Go, crates, etc.). Easy to match by name + version. |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | CVEs being exploited right now, including operating systems, devices and commercial software. Synced hourly (built Oct 2026). |

We start with CVEs in code (open source packages, which OSV covers and which we can match by name and version), plus CISA's list of CVEs being exploited right now, whatever product they affect.

**Sources: built and roadmap**
- **CISA KEV (built Oct 2026):** one ~2 MB JSON file, synced hourly by `/api/cron/sync-kev`. CISA's server ignores ETags but honors `If-Modified-Since`, so unchanged runs download nothing. The catalog is replaced wholesale, but kept if a new file looks truncated. Advisories whose CVE alias is listed get an Exploited badge; KEV entries with no advisory are listed as their own rows (vendor and product, no severity score, since CISA publishes none). `check_packages`, `get_alerts`, `search_vulns` and `get_vuln` report `known_exploited`.
- **NVD:** every CVE, including operating systems, devices and commercial software, with CVSS scores and CPE product names. It would also fill in severity for OSV advisories that have none (most Go and RustSec records). Notes from a first build: poll every 2 hours with `lastModStartDate`/`lastModEndDate` windows of at most 120 days; ~2,000 CVEs change a day; NVD takes ~45s per 2,000-record page, so use smaller pages, resumable paging and a free API key (`NVD_API_KEY`); a full history is ~300k rows and needs a storage decision; requires the notice "This product uses the NVD API but is not endorsed or certified by the NVD."

## Categories

Upstream data has no categories, so `src/lib/categories.ts` matches keywords against whole segments of package names (OSV) and vendor + product (KEV): databases, web frameworks and servers, infrastructure and DevOps, AI and ML, auth and crypto, operating systems, network and security devices, browsers, business and desktop apps. Rules apply at query time, so they can change without re-syncing. About three quarters of KEV entries match a category; the rest are a long tail of products.

## Prompt tabs

The setup prompt on the home page and docs has a tab per app: any AI app (add the URL as a connector, paste a lockfile), Claude Code (`claude mcp add`), OpenCode (`opencode.json`) and Codex (`codex mcp add`). The docs show an unattended weekly cron line for each coding agent, limited to reading files and `check_packages` (Claude Code `--tools`/`--allowedTools`/`dontAsk`; an OpenCode agent with deny-by-default permissions; Codex `exec --sandbox read-only` with only `check_packages` enabled and pre-approved). Codex also auto-approves `check_packages` because the tool is annotated `readOnlyHint`, so keep that annotation.

## Sync schedule

- **OSV: every 15 minutes, at :02, :17, :32 and :47.** OSV publishes most changes in batches on the quarter hour, so running 2 minutes after each batch is nearly as fresh as polling every 5 minutes, at a third of the runs, and lets the database sleep between them while traffic is low. Each run fetches only what changed since the last run's checkpoint.
- After each sync, re-match only the changed vulns against stored stacks. Feeds and `get_alerts` pick up new matches right away.
- Runs are idempotent and keep a `sync_state` checkpoint, so a failed or overlapping run is harmless.
- **Scope:** language package ecosystems only (npm, PyPI, Go, crates.io, Maven, NuGet, Packagist, RubyGems, Hex, Pub, GitHub Actions, Hackage, CRAN, SwiftURL). That's about 100 changed records a day. OS distros change about 25,000 records a day and come with OS package matching later.
- **History:** the first run imports the last 7 days, 500 records per run. Matching a reported stack needs full history, so `report_stack` will also query OSV's batch API (`/v1/querybatch`) for that stack's packages instead of us mirroring all of OSV.
- **Severity:** advisory severity when present (GHSA), else computed from a CVSS v3 vector. Malicious-package (`MAL-`) records count as critical. Records with only CVSS v4 or no score show as unknown for now.

## Data model (minimal)

- `workspaces`: id, created_at, last_active_at (tokens live in `tokens`, hashed)
- `stacks`: id, workspace_id, name, updated_at
- `stack_items`: id, stack_id, ecosystem, name, version, purl
- `vulns`: id (CVE/GHSA), summary, severity, published, modified, affected (json)
- `matches`: id, stack_item_id, vuln_id, first_seen_at
- `sync_state`: source, cursor, last_run_at, last_success_at, last_error
- `sync_failures`: source, ecosystem, vuln_id, attempts, last_error (records retried instead of stalling the sync)

Only hashes of tokens and keys are stored.

## Notifications

| Channel | Setup | Notes |
|---|---|---|
| **MCP** | Already set up | The assistant calls `get_alerts`, e.g. at the start of a session. |
| **Public RSS** | Build one at `/rss` | Pick known exploited, severities, languages, categories, packages or a keyword; copy the feed URL. Public data only, no key; we never learn who subscribes. The filters are in the URL, so the builder warns against listing private package names. |

**No private feeds (decided Oct 2026).** RSS has no login, so a per-workspace feed would need a secret in its URL, and a leaked URL would show which of someone's packages are vulnerable. Feed readers and Slack would hold that URL. Instead, comparisons that involve a person's stack happen through MCP, or on their own machine (see "Check without storing anything").

## Check without storing anything (built)

Ideas for people who don't want their stack stored anywhere, not even anonymously:

- **On their own machine.** Their AI assistant or a cron job reads lockfiles and compares them against public data, keeping the results local. Building blocks: a stateless check endpoint (below), or OSV's own API and `osv-scanner`, which already do this. Watchpost would add a ready-made prompt and script, and readable output. The local app (below) takes this further: checks run fully offline.
- **A drop-in form on the site.** Drop a lockfile (`package-lock.json`, `pnpm-lock.yaml`, `requirements.txt`, `go.sum`, `Cargo.lock`, ...) or paste a list. The browser parses it locally and sends only package names and versions; the page shows the results. Nothing is stored and there's no workspace. `package.json` alone holds version ranges (`^1.2.3`), not installed versions, so lockfiles give exact answers.
- **Shared piece:** `POST /api/check` takes up to a few thousand packages, asks OSV which known vulnerabilities affect them, and returns structured results without storing or logging the list. It uses the same validation as `report_stack`, and the same rate limits as the other open endpoints.

What shipped:
- `/check`: drop or paste lockfiles (npm, pnpm, yarn, pip, poetry, uv, Cargo, go.mod, Bundler, Composer, or a plain list). Parsed in the browser.
- `POST /api/check` (JSON, or `?format=text` for cron output). Advisories we don't have are fetched into memory, never written, so the database doesn't reflect what anyone checked.
- **MCP split:** `/api/mcp` is now the no-sign-in default with `check_packages`, `search_vulns` and `get_vuln`. The OAuth workspace tools moved to `/api/mcp/workspace`, which is optional.
- Docs: "Run checks on a schedule" with a prompt for unattended coding agents (a Claude Code cron example limited to file reads and `check_packages`) and no-AI `jq` + `curl` scripts for npm, Python, Go and Rust.

## MCP tools

| Tool | Purpose |
|---|---|
| `report_stack` | Upsert a named stack with its items, and return any current matches |
| `get_alerts` | CVEs matching the workspace's stacks (optionally since a date) |
| `search_vulns` | Search CVEs by package, keyword, or ID |
| `get_vuln` | Full details for one CVE, including the advisory text |
| `dashboard_link` | A one-time link to open the private dashboard in a browser |

Auth: OAuth access token (or a static key from an env var) as `Authorization: Bearer`. `search_vulns` and `get_vuln` work without one. There's deliberately no `create_workspace` tool: creating a workspace happens on the approval page, so no secret is ever generated inside the chat.

**What tools return.** Advisory text is written by whoever files the advisory, and the assistant reading it may have a shell and access to your files. So `get_alerts`, `report_stack` and `search_vulns` return only structured fields: ID, severity, ecosystem, package, affected and fixed versions, and the osv.dev URL. Free text (summary and details) only comes from `get_vuln`, truncated, with control characters and markdown links and images removed, inside a field labeled as untrusted. Tool output never includes a token or key.

## Web UI (minimal)

- `/`: landing page, recent CVE feed, setup prompt
- `/vulns/[id]`: CVE detail (also as `.md`)
- `/connect`: the OAuth approval page ("Create a private workspace" or "Connect to this workspace")
- `/login/[code]`: one-time dashboard link from `dashboard_link`. Shows a "Continue" button; the code is only exchanged on that POST, so link scanners that GET it can't use it.
- `/dashboard`: private view of stacks, matches, and feed URL
- `/vulns`: the CVE list. Filters apply as they change (no Filter button): search, show (CVEs and advisories, known exploited, package advisories, malicious packages, everything), language, category, severity, sort. All in the URL.
- `/rss`: feed builder with a live preview
- `/feed.xml`: public RSS, same filters as `/vulns`
- `/docs`: one page covering what the site is, browsing and shareable filter links, RSS feeds and where to use them, MCP setup and sign-in, AI-agent formats, privacy, and data sources

## Setup docs

The goal is to go from nothing to alerts in about a minute:

1. **Paste the setup prompt** from the home page into your AI app, or add the server yourself:
   ```sh
   claude mcp add --scope user --transport http watchpost https://watchpost.now/api/mcp
   ```
2. **Approve in the browser.** The app opens `/connect`; click "Create a private workspace". The token goes straight to the app.
3. **Report the stack.** The assistant reads lockfiles and manifests and calls `report_stack` with package names and versions only.
4. **Get alerts:** ask "Any new CVEs for my stacks?"

For apps without OAuth, the docs show how to put a key from "Get a key" in an environment variable (e.g. `${WATCHPOST_KEY}` in `.mcp.json`) at user scope, never in a committed project file and never in the chat.

The docs also cover keeping stacks current: re-run the report prompt after dependency changes. Automation (hooks or scheduled runs) can come later.

## AI and crawler friendly

Public CVE pages should be easy for search engines and LLMs to read:

- Server-rendered HTML with semantic markup and no client-only content.
- `/llms.txt`: a short guide to the site, the public pages, and the MCP server.
- A markdown version of every public page (e.g. `/vulns/CVE-2025-1234.md`).
- A public read-only JSON API for CVE lookups (`/api/vulns/[id]`).
- `sitemap.xml` covering all CVE pages, plus JSON-LD structured data.
- `robots.txt` allows search and AI crawlers on public pages and disallows `/dashboard`, `/connect`, `/key`, `/oauth/`, `/login/`, and `/api/mcp`.
- Private pages also send `noindex`, as a backstop in case a crawler ignores robots.txt.

## Security

This app stores a map of which software people run, and an assistant connected to it may have a shell on their machine. A breach or a bad tool response could hurt users, so security is part of every phase, not a later step.

**Tokens and sessions**
- No token or key ever appears in a URL, the AI chat, or a command the user types. MCP clients get tokens through OAuth (PKCE required; client registration via Dynamic Client Registration). The only secret in a URL is OAuth's authorization code: single-use, valid for 5 minutes, and useless without the app's PKCE verifier. Access tokens last an hour; refresh tokens rotate on every use, and reusing an old one revokes the whole grant.
- All tokens are 256-bit random with a type prefix (`wpa_` access, `wpr_` refresh, `wpk_` static key, `wpc_` authorization code), so secret scanners can spot leaks. Only SHA-256 hashes are stored; lookups compare in constant time.
- Dashboard sessions use a random session ID in an HttpOnly, Secure, `SameSite=Lax` cookie, stored hashed. Never a token or key.
- One-time dashboard codes expire in 60 seconds, work once, and are exchanged by POST with an `Origin` check, which also blocks signing someone into an attacker's workspace.
- Approval and "Get a key" are POSTs with CSRF protection and rate limits, so crawlers and prefetchers can't create workspaces.
- `/api/mcp` accepts only `Authorization: Bearer`, never the dashboard cookie, and rejects requests whose `Origin` isn't allowed, so other websites can't call tools as a visitor.
- Users can revoke an app and delete a workspace and all its data. A daily cron deletes workspaces with no activity for 90 days; `last_active_at` updates at most once a day.

**What we accept from assistants (`report_stack`)**
- A strict schema, not trust in the assistant: ecosystem from a fixed list, package names and versions matching each ecosystem's format, length caps, at most 5,000 items per stack, labels limited to short slugs (`^[a-z0-9-]{1,32}$`).
- Reject anything that looks like a path, hostname, IP, email, URL, or secret (known key prefixes or high-entropy strings). Rejected items are dropped and listed back to the assistant, never stored or logged.
- Nothing from the request body is logged, and the `Authorization` header is never logged.

**What we send to assistants**
- Structured fields only by default (see "MCP tools"). Free text is opt-in, sanitized, truncated and labeled untrusted.
- The same rule covers markdown pages: upstream strings are escaped so they can't add headings, links or images. (Done for `/vulns/*.md`.)

**Data minimization**
- Store only ecosystem, name, and version. No personal info at all: no emails, names, or accounts.
- We don't store IP addresses. Honest caveat: Vercel's own request logs see IPs, like any host. We keep log retention at the minimum, add no log drains, and do rate limiting in Vercel's firewall rather than in our database.
- Feed items include CVE IDs and package names, not the full stack.

**Caching**
- Workspace data is never cached with `'use cache'` or public `Cache-Control`. Private routes send `Cache-Control: private, no-store` and `X-Robots-Tag: noindex`.

**Untrusted upstream data** (done in phase 1)
- OSV records are size-capped, schema-validated and fetched with timeouts. IDs and aliases must look like advisory IDs. Control and bidi characters are stripped.
- One bad record can't stall the sync: it goes to `sync_failures` and is retried, and inserts are chunked so batch size can't break them.
- Rendered as plain text, escaped in RSS and markdown, parameterized SQL only.

**Abuse**
- No webhooks: the server never sends requests to user-supplied URLs, which rules out SSRF.
- Vercel firewall rate limits on `/vulns`, `/feed.xml`, `/api/*` and the approval flow.
- Alert if `sync_state.last_success_at` is more than 30 minutes old.

**Platform**
- Security headers: CSP, HSTS, `X-Content-Type-Options`, `frame-ancestors 'none'`, `Cross-Origin-Opener-Policy`. The image optimizer is off.
- Cron routes require a strong `CRON_SECRET` (weak or example values are refused in production). Secrets live only in Vercel env vars.
- Separate database roles: migrations use an owner role; the app uses a role that can't change the schema.

**Our own dependencies**
- Dogfood: report this app's own stack to itself and act on its alerts.
- Committed lockfile, install scripts off, new releases must be 7 days old before install, Dependabot with a 7-day cooldown, `pnpm audit` in CI, actions and container images pinned by hash.
- Run gitleaks before the first push, and a security review at the end of each phase. `/.well-known/security.txt` says how to report issues.

## Open source

The code is a public GitHub repo (`Status-Labs/watchpost`). We also run the hosted instance at `watchpost.now`. The code is open, but the hosted instance's data (workspaces, stacks) stays private.

**Repo basics**
- MIT `LICENSE`, `README.md` (what it is, how to self-host), `CONTRIBUTING.md`, `SECURITY.md`, and `.env.example`.
- Nothing in code is specific to our deployment. Domain, site name, and limits come from env vars, so anyone can self-host (see `docs/self-hosting.md`).
- `AGENTS.md`, `docs/`, and `PLAN.md` are public too, so they must never hold secrets, internal URLs, or private notes.

**Security with public code**
Attackers can read the code too, so the security plan above matters even more.
- `SECURITY.md` points to GitHub private vulnerability reporting, never public issues.
- Turn on secret scanning with push protection, Dependabot, and CodeQL.
- Protect `main`: PRs only, passing checks, and at least one review.
- CI must never expose secrets to fork PRs. Use `pull_request`, not `pull_request_target`, keep secrets out of PR workflows, and pin Actions to commit SHAs.
- Deploys come from Vercel's Git integration on `main`, never from fork PRs.

**Data source terms**
- OSV data is CC BY 4.0, so credit OSV and link to each record's source.
- Show it in the site footer and the README. Sources added later (see the roadmap above) bring their own notices.

## Costs and limits

It's free and anonymous, so it has to stay cheap even if it gets popular, and degrade instead of running up a bill.

**Rough monthly cost** (estimates, Oct 2026 pricing; check vercel.com/pricing and neon.com/pricing):
- Launch: ~$20–25 (Vercel Pro seat with its included usage credit; Neon free plan or a few dollars).
- Popular (~1M page views plus crawlers): ~$50–120.
- OSV and GitHub (public repo) are free.

**What keeps it cheap**
- **Page caching (done):** CVE pages become static after their first visit and the CDN serves them (`s-maxage=900`); the JSON, markdown and RSS routes send the same CDN headers. Home and list queries go through the shared remote cache. In local tests, repeat visits ran zero database queries. The sync invalidates the `vulns` tag only when it writes new data. A bonus: cached pages return real 404s and 308 redirects.
- **Sync every 15 minutes:** lets Neon scale to zero between runs while traffic is low.
- **Spend caps (before launch):** a Vercel spend limit that pauses the project instead of billing more, and a max autoscaling size on Neon. If it outgrows the budget, it slows or pauses; it never surprises us with a bill.
- **Rate limits (before launch):** Vercel firewall rules on `/vulns/*`, `/feed.xml`, `/api/*`, and the open sign-in endpoints (`/oauth/register`, `/connect/approve`, `/key`), which scripts can call directly. Suggested limits are in `docs/self-hosting.md`. Random CVE-shaped URLs each create a cached 404 page, so a flood of them costs cache writes; per-IP limits stop that.

**Funding**
- Apply to Vercel's open source program once the repo is public ($3,600 in credits over 12 months for selected projects; it runs in cohorts).
- GitHub Sponsors or Open Collective for donations.
- Everything is self-hostable, so the project outlives our hosting if it has to.

## Local app (archived)

**Archived on 2026-10-28 on the `feat/local-app` branch.** It worked (offline checks matched OSV's API exactly), but the full local copy of OSV takes about 1.4 GB on the user's device, which is too much. Revisit only with a much smaller footprint, for example storing malicious-package reports as just ID, package and versions, or downloading only the ecosystems someone uses.

The whole app on the user's own machine: the web UI, the MCP server and a full copy of the public data. Checks run offline, so the package list never leaves the machine. watchpost.now stays up for public browsing, RSS and docs, and becomes the install page; its no-install check stays as the quick option.

- **Install:** `npx @status-labs/watchpost@<version>` (the `watchpost` name on npm is taken). Pinned versions in all docs, never `@latest`. It starts the app at `http://127.0.0.1:4141` and opens the browser.
- **AI apps:** the MCP config runs `npx -y @status-labs/watchpost@<version> mcp`, a small stdio bridge that starts the local app if it isn't running and forwards to its MCP endpoint. No URL, token or port in the AI app's config. One process owns the database; the bridge never opens it.
- **Database:** PGlite (Postgres compiled to WebAssembly) in a local data folder (`~/.local/share/watchpost`, `~/Library/Application Support/Watchpost` or `%LOCALAPPDATA%\Watchpost`). Same schema and queries as the hosted Postgres, so there's one codebase. `DATABASE_URL` selects hosted Postgres; without it, local mode uses PGlite.
- **Data:** the first run downloads OSV's per-ecosystem archives (about 300 MB compressed, mostly npm malware reports) and the CISA KEV catalog, with progress on the home page. After that the app runs the same incremental syncs as the hosted cron, on a timer, while it's open.
- **Offline matching:** for each package, load the advisories naming it and evaluate their affected ranges: exact `versions` lists first, then `SEMVER` ranges, then `ECOSYSTEM` ranges with a comparator per ecosystem (PyPI's PEP 440, Maven, NuGet, RubyGems, Packagist, Hackage, CRAN; the rest are semver-like). Before release, compare offline results with OSV's API on a large synthetic package list. Tests use recorded fixtures.
- **Local network rules:** the only outbound requests are to OSV's bucket and CISA, and they carry nothing about the user. The server binds to 127.0.0.1, accepts only `localhost`/`127.0.0.1` Host headers (against DNS rebinding) and rejects cross-site browser requests, so a website can't query it.
- **Not in local mode:** workspaces, OAuth, keys, cron routes and sitemaps.
- **Release safety.** A compromised package runs on users' machines, so: npm trusted publishing from GitHub Actions with provenance, pinned versions in the docs, the same 7-day release-age rule for our own dependencies, and few runtime dependencies.

Steps:
1. ✅ PGlite and local mode, full OSV download, in-process syncs. The full history is about 292k advisories (240k of them npm malware reports) and 1.4 GB on disk.
2. ✅ Offline matcher: osv-scalibr's comparators ported to TypeScript (all 42k fixture cases pass; identical to the Go code on 1.26M generated pairs). `scripts/parity.mts` found 0 differences from OSV's API across 42,535 matches in 12 ecosystems.
3. ✅ The CLI: Next.js standalone build, `start`, `mcp` and `stop`, data folder, localhost rules. (`check <lockfile>` later.)
4. Publishing (npm trusted publishing from a GitHub Actions release workflow, which also fails if the build contains a home-directory path), install docs, the local setup in the prompt tabs, and the install page on watchpost.now.

Later: shrink the 1.4 GB (malware reports need only their package and ID), and move PGlite off the main thread (a worker or `pglite-socket`) so long list queries can't stall MCP calls.

## Phases

1. **MVP** ✅ (built, not yet deployed): public GitHub repo setup (MIT license, README, SECURITY.md, CONTRIBUTING.md, `.env.example`, CI, branch protection), Next.js scaffold, Neon + Drizzle schema, 15-minute OSV sync cron, public CVE pages and RSS, LLM-friendly output (`llms.txt`, markdown pages, sitemap, robots.txt).
2. **Workspaces + MCP** ✅ (built, not yet deployed): OAuth 2.1 server (metadata, Dynamic Client Registration, `/connect` approval page, PKCE S256 only, refresh-token rotation with reuse detection, revocation), "Get a key" for apps without OAuth, `/api/mcp` with `report_stack`, `get_alerts`, `list_stacks`, `search_vulns`, `get_vuln`, `delete_stack` and `delete_workspace`, strict `report_stack` validation, and matching at report time through OSV's batch query API (same vulnerability under several IDs shown once). Changes from the original plan:
   - **No Client ID Metadata Documents.** The 2026-07-28 MCP spec prefers them over Dynamic Client Registration, but supporting them means fetching a URL the client chooses, which breaks our rule against requests to user-supplied URLs. We use Dynamic Client Registration, which MCP apps still support. Revisit if an important app drops it (it would need an SSRF-safe fetcher: https only, public IPs only, no redirects, size and time caps).
   - **Every MCP call needs a token,** including `search_vulns` and `get_vuln`. MCP apps only start sign-in after a 401, so optional auth would leave them never signing in. Public data stays available without a token through the JSON API and markdown pages.
   - **Matching happens when a stack is reported** (OSV's querybatch API, full history). Re-matching stored stacks when new advisories arrive is phase 3.
   - `dashboard_link` moves to phase 3 with the dashboard.
3. **Matching + dashboard** (on hold): re-match stored stacks on each sync; one-time-code dashboard login and `dashboard_link`. Waits to see whether people want stored stacks, now that checks need no storage. (The daily cleanup job for idle workspaces, expired tokens and abandoned sign-ins shipped with phase 2, after its security review.)
4. **Later**: NVD CVEs (see "Roadmap: more sources"), give missing CVE pages a real 404 and CVE IDs a real 308 redirect (pages stream, so today they return 200 with `noindex`; a check in `proxy.ts` would fix it), render advisory markdown safely, CVSS v4 scores, OS packages (OSV distro data), team workspaces (shared keys, still no personal info).
5. **Local app**: see above. Replaces the earlier optional CLI idea (hash-prefix lookups and a keychain token), since offline checks need neither.
