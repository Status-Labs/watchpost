# Security Policy

Watchpost exists to help people stay ahead of vulnerabilities, so we take reports about our own code seriously.

## Reporting a vulnerability

Report privately through GitHub: [open a private security advisory](https://github.com/Status-Labs/watchpost/security/advisories/new).

Please don't open a public issue, pull request or discussion for a security problem.

Include what you can:

- What the issue is and what an attacker could do with it.
- Steps to reproduce, or a proof of concept.
- The affected URL, route or file.

We'll acknowledge your report within 3 business days and keep you updated until it's resolved. Once a fix ships, we'll credit you in the advisory unless you'd rather stay anonymous.

## Scope

In scope: this repository and the hosted instance at `watchpost.now`.

Out of scope:

- Vulnerabilities in the upstream data itself. Report those to [OSV.dev](https://osv.dev) or the original advisory source.
- Denial of service through traffic volume, and automated scanner output without a demonstrated impact.
- Testing that touches other users' data, or social engineering.

## Supported versions

Only the latest version on `main` is supported.
