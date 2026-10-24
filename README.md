# Watchpost

CVE alerts for your tech stack. Watchpost collects public vulnerability data from [OSV.dev](https://osv.dev) every 15 minutes and CISA's [Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) hourly, and publishes it as web pages, RSS feeds, markdown and JSON.

Hosted at [watchpost.now](https://watchpost.now). No sign-up, and no personal information collected.

**Status:** early. Check your dependencies on the site, from a script or through your AI assistant over MCP, with no sign-up and nothing stored. Public CVE pages and feeds work too. See [`PLAN.md`](PLAN.md).

## For people and AI agents

- `/check`: drop a lockfile to see what affects you. Parsed in your browser; nothing is stored.
- `POST /api/check`: the same check for scripts, no key needed.
- `/api/mcp`: MCP server for AI assistants (`check_packages`, no sign-in). `/api/mcp/workspace` keeps stacks in an anonymous workspace (OAuth).
- `/vulns`: newest vulnerabilities, filterable by ecosystem and package.
- `/vulns/{id}`: one advisory. CVE IDs redirect to the matching advisory. Add `.md` for markdown.
- `/api/vulns/{id}`: JSON.
- `/rss`: build an RSS feed for the languages, categories and packages you follow. `/feed.xml` takes the same filters as `/vulns`.
- `/llms.txt`: a guide to the site for LLMs.

## Run it locally

You need Docker and [mise](https://mise.jdx.dev) (or Node 24, pnpm and just).

```sh
mise install
pnpm install
cp .env.example .env
just dev        # starts Postgres, runs migrations, starts Next.js
just sync       # in another terminal: pull the last 7 days of OSV data
```

Then open http://localhost:3000.

## Tests

```sh
just test       # unit tests
just test-int   # integration tests (needs Docker)
just check      # everything CI runs
```

## Self-hosting

See [`docs/self-hosting.md`](docs/self-hosting.md). Everything specific to a deployment (domain, site name, secrets) is an env var.

## Contributing and security

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Report vulnerabilities privately as described in [`SECURITY.md`](SECURITY.md), never in public issues.

## Data and license

Code: [MIT](LICENSE).

Vulnerability data comes from [OSV.dev](https://osv.dev) and is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Each record links to its OSV source.
