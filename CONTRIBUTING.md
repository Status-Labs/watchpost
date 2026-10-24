# Contributing

Thanks for helping. Start with [`PLAN.md`](PLAN.md) for what we're building, and [`AGENTS.md`](AGENTS.md) for the rules every change follows. Those rules apply to people and coding agents alike.

## Workflow

1. Fork the repo and branch off `main`: `feat/…`, `fix/…`, `docs/…` or `chore/…`.
2. Keep the change small and focused on one thing.
3. Run `just check` (lint, types, tests and build) before opening a PR.
4. Open a PR saying what changed, why, and how you tested it.

## Ground rules

- Privacy first: never collect personal information. See "Rules that matter for every PR" in `AGENTS.md`.
- Tests never touch real services. Use the Postgres container and recorded responses in `fixtures/`.
- Pages must work at phone width (390px) and with a keyboard.
- Found a security issue? Report it privately; see [`SECURITY.md`](SECURITY.md).

By contributing, you agree your work is released under the [MIT license](LICENSE).
