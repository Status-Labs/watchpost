# Self-hosting

How to run the app on your own Vercel project and Neon database. This is also how we deploy the hosted instance. Read "Prerequisites", then follow "Setup" in order.

## Prerequisites

### Accounts and access

| Need                                                                      | For steps |
| ------------------------------------------------------------------------- | --------- |
| Neon account and project, in the same region as the Vercel functions      | 1         |
| Vercel account or team, with access to the GitHub repo                    | 2         |
| Vercel Pro plan, for cron jobs that run more often than once a day        | 2         |
| GitHub repo admin (Actions, secrets)                                      | 3         |
| DNS control for the production domain                                     | 2         |

### Tools

- `mise install`: Node, pnpm and just (pinned in `mise.toml`).
- `gh`, signed in.
- Optional: `vercel` and `neonctl` CLIs.

### Decisions

| Decision          | Suggested default                                                                   |
| ----------------- | ----------------------------------------------------------------------------------- |
| Region            | One region for everything; Neon and Vercel functions side by side.                  |
| Environments      | `prod` only; it serves as dev until real users. Add `staging` before launch.        |
| Vercel protection | All deployments, production included, until launch; then Standard (previews only).  |

### Secrets to generate

Set in Vercel env vars, never in the repo.

- `CRON_SECRET`: `openssl rand -base64 32`.

## Vercel

- Node 24. Pushes to `main` deploy production; PRs get previews.
- A domain can only be attached after a production deploy succeeds.

Env vars, set for Production and Preview. Preview uses a Neon `preview` branch and its own secrets, and leaves the URLs unset:

| Var                       | Value                                                  |
| ------------------------- | ------------------------------------------------------ |
| `DATABASE_URL`            | Neon pooled string                                     |
| `DATABASE_URL_UNPOOLED`   | Neon direct string, used only for migrations           |
| `SITE_URL`                | Production URL; previews fall back to `VERCEL_URL`     |
| `CRON_SECRET` (sensitive) | `openssl rand -base64 32`                              |
| `SITE_NAME` (optional)    | Defaults to `Watchpost`                                |
| `SOURCE_URL` (optional)   | Link to your fork's source code                        |

## Setup

### 1. Postgres

Create a Neon project. Apply migrations with the direct (unpooled) URL: `DATABASE_URL_UNPOOLED=<url> pnpm db:migrate`. For previews, create a `preview` branch of production. Neon may delete it after 30 days; reset it from production, or recreate it and update Preview's `DATABASE_URL`.

### 2. Vercel

Create the Vercel project from the repo. Set the env vars above, deploy, then attach the domain.

### 3. Check it works

1. `/api/cron/sync-osv` returns 401 without `CRON_SECRET`.
2. Within a few minutes, the cron logs show sync runs, and the home page lists recent CVEs. The first runs import the last 7 days of OSV data, 500 records per run.
3. Within an hour, `/api/cron/sync-kev` loads CISA's Known Exploited Vulnerabilities catalog (about 2 MB). Later runs send `If-Modified-Since` and only download it when CISA publishes a change. Run it right away with `just sync-kev`.

### 4. Rate limits (before going public)

Some endpoints are open to anyone and write to the database: client registration, the approval form, and "Get a key". Browsers can't abuse them from other sites, but scripts can call them directly, so add per-IP rate limits in your host's firewall (Vercel: Firewall → Rate limiting). Suggested starting points:

| Path | Method | Limit per IP |
| --- | --- | --- |
| `/oauth/register` | POST | 10 per hour |
| `/connect/approve` | POST | 10 per hour |
| `/key` | POST | 5 per hour |
| `/oauth/token` | POST | 60 per hour |
| `/api/mcp` | POST | 300 per hour |
| `/vulns/*`, `/feed.xml`, `/api/vulns/*` | GET | 600 per hour |

A daily cleanup job (`/api/cron/cleanup`) deletes abandoned sign-ins, expired tokens and workspaces idle for 90 days, so leftovers from abuse don't pile up.

## Upgrades

1. Pull the new release.
2. Run migrations on production before the new code serves traffic. Then reset the preview branch from production.
3. Deploy the web app (push to `main`).
