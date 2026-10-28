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

# Build the local app package (cli/) from a standalone Next.js build
build-local:
    WATCHPOST_LOCAL_BUILD=1 pnpm build
    rm -rf cli/app
    cp -r .next/standalone cli/app
    cp -r .next/static cli/app/.next/static
    cp -r public cli/app/public
    cp -r drizzle cli/app/drizzle
    # Standalone builds copy .env files; none may ship.
    find cli/app -maxdepth 2 -name '.env*' -delete
    cp LICENSE cli/LICENSE

# Run the local app from the build, with its data in a scratch folder
local *args:
    WATCHPOST_DATA_DIR=.local-data node cli/bin/watchpost.mjs {{args}}
