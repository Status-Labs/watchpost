# AGENTS.md

Watchpost: CVE alerts for your tech stack, reported by your AI assistant over MCP. Hosted at `watchpost.now`.

This is a guide for contributors and coding agents. Read `PLAN.md` for what we're building and why.

## Company context

This is a Status Labs product. Status Labs team members and agents: before starting, read Weeoh, the company brain, at https://github.com/Status-Labs/weeoh (private; start with its `AGENTS.md`). If it's checked out locally, it's at `../weeoh`. Track your work in Shyup under project `WAT`.

Outside contributors can skip this; everything you need is in this repo.

## Stack

| Area            | Choice                                                |
| --------------- | ----------------------------------------------------- |
| Language        | TypeScript, Node.js 24                                |
| Package manager | pnpm (pinned in `package.json` and `mise.toml`)       |
| App             | Next.js (App Router), Tailwind CSS + shadcn/ui        |
| Database        | Neon Postgres + Drizzle ORM, `pg` driver              |
| Background work | Vercel Cron calling API routes                        |
| MCP server      | `/api/mcp` using `mcp-handler`                        |
| Testing         | Vitest, Playwright, Testcontainers                    |
| CI              | GitHub Actions                                        |
| Task runner     | just (`justfile`), wrapping the pnpm scripts          |

Self-hosting and deploys: `docs/self-hosting.md`.

## Commands

- `just dev`: start Postgres (Docker), migrate, and run Next.js.
- `just sync`: run one OSV sync against the dev server.
- `just db-generate` after changing `src/db/schema.ts`, then commit the new file in `drizzle/`.
- `just check`: lint, types, unit and integration tests, and build. CI runs the same.

## Layout

- `src/osv/`: OSV sync (`sync.ts`), record parsing and CVSS scoring.
- `src/kev/`: CISA Known Exploited Vulnerabilities sync. Replaces the `kev` table wholesale.
- `src/lib/categories.ts`: keyword rules for the category filter, shared by SQL and tests.
- `src/auth/`: the OAuth server for MCP apps (`oauth.ts`), token helpers, and the static keys from `/key`.
- `src/stacks/`: package validation, stateless checks (`check.ts`), saved stacks (`store.ts`), and OSV's batch query API.
- `src/lib/lockfiles.ts`: lockfile parsers for the `/check` page. They run in the browser, so dropped files never leave the visitor's machine.
- `src/mcp/`: MCP tool definitions. `src/app/api/mcp` has no sign-in and stores nothing; `src/app/api/mcp/workspace` is signed in and keeps stacks.
- `src/db/`: Drizzle schema and connection. Migrations live in `drizzle/`.
- `src/lib/`: queries and output formats (RSS, markdown, sitemaps).
- `src/app/`: pages and route handlers. Cron entry points are `api/cron/sync-osv` (every 15 minutes), `api/cron/sync-kev` (hourly) and `api/cron/cleanup` (daily).

Next.js runs with Cache Components. Builds never touch the database:
- Public vulnerability reads go through `src/lib/cached.ts` (`use cache` with the `sync` profile and the `vulns` tag, which the sync invalidates). CVE pages become static after their first visit and are served from the CDN.
- Pages whose output depends on the clock or query string call `await connection()` inside `<Suspense>` and read through `use cache: remote`.
- Only public data goes through these caches, never workspace data.

## Rules that matter for every PR

**Privacy.** We store which software people run, so a leak would be a list of targets.
- Never collect personal info: no emails, names, accounts or stored IP addresses.
- Store only ecosystem, package name and version for stack items.
- Store only hashes of tokens and keys.

**Untrusted input.**
- Validate all MCP and API input with zod, and cap sizes.
- CVE text from OSV and CISA is untrusted, and MCP clients may have a shell. Render it as plain text, never with `dangerouslySetInnerHTML`. Escape it in RSS and markdown (`src/lib/sanitize.ts`). MCP tools return structured fields; free text only from `get_vuln`, sanitized and labeled untrusted.
- Use Drizzle's parameterized queries. Never build SQL from strings.
- The server never makes requests to user-supplied URLs.

**Tokens and caching.**
- No secret in a URL, a log line or a tool response. Tokens are stored as hashes only.
- Never use `'use cache'` or `PUBLIC_CACHE_HEADERS` on workspace data. Private routes send `Cache-Control: private, no-store`.
- `/api/mcp` authenticates with `Authorization: Bearer` only, never cookies.

**Secrets.** Secrets live only in env vars (see `.env.example`). Nothing is specific to our deployment: domain, site name and limits are all settings.

**Tests.**
- Tests run against a local Postgres container, never a Neon URL. Test setup refuses to run if `DATABASE_URL` isn't localhost.
- Never call OSV, NVD or other outside APIs in tests. Use recorded responses in `fixtures/`.
- Unit tests are `*.test.ts` next to the code, integration tests are `*.int.test.ts`, and e2e tests live in `e2e/`.

**UI.** Pages work at phone width (390px) and on desktop, meet WCAG AA contrast, and work with a keyboard.

## Workflow

- Branch off `main` (`feat/…`, `fix/…`, `docs/…`, `chore/…`) and open a PR. Nobody pushes to `main` directly.
- Run the full check before opening a PR.
- Report security issues privately, as described in `SECURITY.md`. Never use public issues.

<!-- BEGIN:nextjs-agent-rules -->

## This is NOT the Next.js you know

This version has breaking changes — APIs, conventions, and file structure may all differ from your training data. Read the relevant guide in `node_modules/next/dist/docs/` (resolved from this file's directory; in monorepos the `next` package may not be visible from the repo root) before writing any code. Heed deprecation notices.

This block is written and re-added by `next dev` — verify at `node_modules/next/dist/server/lib/generate-agent-files.js`. Removing it from a diff only re-creates the uncommitted change; committing it with your work keeps the tree clean.

<!-- END:nextjs-agent-rules -->
