set dotenv-load

default:
    @just --list

# Install dependencies
install:
    pnpm install --frozen-lockfile

# Start the local Postgres
db-up:
    docker compose up -d --wait postgres

# Apply database migrations
db-migrate:
    pnpm db:migrate

# Generate a migration after changing src/db/schema.ts
db-generate:
    pnpm db:generate

# Start Postgres, migrate, and run the dev server
dev: db-up db-migrate
    pnpm dev

# Run one OSV sync against the local dev server, like Vercel Cron does
sync:
    curl -fsS -H "Authorization: Bearer $CRON_SECRET" http://localhost:3000/api/cron/sync-osv
    @echo

test:
    pnpm test

test-int:
    pnpm test:integration

# Everything CI runs
check:
    pnpm lint
    pnpm typecheck
    pnpm test
    pnpm test:integration
    pnpm build

# Run one CISA KEV sync against the local dev server
sync-kev:
    curl -fsS -H "Authorization: Bearer $CRON_SECRET" http://localhost:3000/api/cron/sync-kev
