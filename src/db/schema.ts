import {
  boolean,
  index,
  uniqueIndex,
  uuid,
  integer,
  jsonb,
  pgTable,
  primaryKey,
  real,
  text,
  timestamp,
} from "drizzle-orm/pg-core";

export const SEVERITIES = ["critical", "high", "medium", "low"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const vulns = pgTable(
  "vulns",
  {
    // OSV ID, e.g. GHSA-xxxx-xxxx-xxxx, PYSEC-2026-1, MAL-2026-123.
    id: text("id").primaryKey(),
    aliases: text("aliases").array().notNull().default([]),
    summary: text("summary"),
    details: text("details"),
    severity: text("severity", { enum: SEVERITIES }),
    cvssScore: real("cvss_score"),
    published: timestamp("published", { withTimezone: true }),
    modified: timestamp("modified", { withTimezone: true }).notNull(),
    withdrawn: timestamp("withdrawn", { withTimezone: true }),
    // The full OSV record, kept for version matching and future fields.
    record: jsonb("record").notNull(),
    syncedAt: timestamp("synced_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    index("vulns_published_idx").on(t.published),
    index("vulns_aliases_idx").using("gin", t.aliases),
  ],
);

// One row per package a vuln affects, for filtering and matching by package.
export const vulnPackages = pgTable(
  "vuln_packages",
  {
    vulnId: text("vuln_id")
      .notNull()
      .references(() => vulns.id, { onDelete: "cascade" }),
    ecosystem: text("ecosystem").notNull(),
    name: text("name").notNull(),
  },
  (t) => [
    primaryKey({ columns: [t.vulnId, t.ecosystem, t.name] }),
    index("vuln_packages_package_idx").on(t.ecosystem, t.name),
  ],
);

export const syncState = pgTable("sync_state", {
  source: text("source").primaryKey(),
  // "<modified>\t<ecosystem>/<id>" of the last record processed, so a batch can
  // stop partway through a group of records sharing one timestamp.
  cursor: text("cursor").notNull(),
  lastRunAt: timestamp("last_run_at", { withTimezone: true }).notNull(),
  lastSuccessAt: timestamp("last_success_at", { withTimezone: true }),
  lastError: text("last_error"),
});

// Records that failed to fetch or parse. The cursor moves past them so one bad
// record can't stall the sync; they're retried a few times, then left for review.
export const syncFailures = pgTable(
  "sync_failures",
  {
    source: text("source").notNull(),
    ecosystem: text("ecosystem").notNull(),
    vulnId: text("vuln_id").notNull(),
    modified: text("modified").notNull(),
    attempts: integer("attempts").notNull().default(1),
    lastError: text("last_error").notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [primaryKey({ columns: [t.source, t.ecosystem, t.vulnId] })],
);

// An anonymous workspace: no name, email or account. Everything in it is
// reachable only through tokens, which are stored as SHA-256 hashes.
export const workspaces = pgTable("workspaces", {
  id: uuid("id").primaryKey().defaultRandom(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  // Updated at most once a day; workspaces idle for 90 days are deleted.
  lastActiveAt: timestamp("last_active_at", { withTimezone: true }).notNull().defaultNow(),
});

// OAuth clients (MCP apps) registered through Dynamic Client Registration.
// Public clients only: no client secrets, PKCE required.
export const oauthClients = pgTable("oauth_clients", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  redirectUris: text("redirect_uris").array().notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

// One-time authorization codes, valid for a few minutes.
export const authCodes = pgTable("auth_codes", {
  codeHash: text("code_hash").primaryKey(),
  clientId: text("client_id")
    .notNull()
    .references(() => oauthClients.id, { onDelete: "cascade" }),
  workspaceId: uuid("workspace_id")
    .notNull()
    .references(() => workspaces.id, { onDelete: "cascade" }),
  redirectUri: text("redirect_uri").notNull(),
  codeChallenge: text("code_challenge").notNull(),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
});

export const TOKEN_KINDS = ["access", "refresh", "key"] as const;
export type TokenKind = (typeof TOKEN_KINDS)[number];

// Access and refresh tokens from OAuth, and static keys from "Get a key".
// A grant groups the tokens from one approval, so a reused refresh token can
// revoke all of them.
export const tokens = pgTable(
  "tokens",
  {
    hash: text("hash").primaryKey(),
    kind: text("kind", { enum: TOKEN_KINDS }).notNull(),
    workspaceId: uuid("workspace_id")
      .notNull()
      .references(() => workspaces.id, { onDelete: "cascade" }),
    clientId: text("client_id").references(() => oauthClients.id, { onDelete: "cascade" }),
    grantId: uuid("grant_id"),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    // Set when a refresh token has been used once; using it again revokes the grant.
    rotatedAt: timestamp("rotated_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("tokens_grant_idx").on(t.grantId), index("tokens_workspace_idx").on(t.workspaceId)],
);

// A named group of packages, like "laptop" or "api". Names are short slugs.
export const stacks = pgTable(
  "stacks",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id")
      .notNull()
      .references(() => workspaces.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex("stacks_workspace_name_idx").on(t.workspaceId, t.name)],
);

// Only ecosystem, package name and version: nothing else about the machine.
export const stackItems = pgTable(
  "stack_items",
  {
    stackId: uuid("stack_id")
      .notNull()
      .references(() => stacks.id, { onDelete: "cascade" }),
    ecosystem: text("ecosystem").notNull(),
    name: text("name").notNull(),
    version: text("version").notNull(),
  },
  (t) => [primaryKey({ columns: [t.stackId, t.ecosystem, t.name, t.version] })],
);

// A vulnerability affecting a package version in a stack. Kept across reports
// while the package stays affected, so first_seen_at says when it became an alert.
export const matches = pgTable(
  "matches",
  {
    stackId: uuid("stack_id")
      .notNull()
      .references(() => stacks.id, { onDelete: "cascade" }),
    ecosystem: text("ecosystem").notNull(),
    name: text("name").notNull(),
    version: text("version").notNull(),
    vulnId: text("vuln_id").notNull(),
    firstSeenAt: timestamp("first_seen_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    primaryKey({ columns: [t.stackId, t.ecosystem, t.name, t.version, t.vulnId] }),
    index("matches_vuln_idx").on(t.vulnId),
  ],
);

// CISA's Known Exploited Vulnerabilities catalog: CVEs attacked in the wild.
// Replaced wholesale on each sync. Most entries are operating systems, devices
// and commercial software rather than packages; advisories whose CVE alias is
// listed here are marked as exploited.
export const kev = pgTable(
  "kev",
  {
    cveId: text("cve_id").primaryKey(),
    vendor: text("vendor").notNull(),
    product: text("product").notNull(),
    name: text("name").notNull(),
    description: text("description").notNull(),
    requiredAction: text("required_action").notNull(),
    dateAdded: timestamp("date_added", { withTimezone: true }).notNull(),
    dueDate: timestamp("due_date", { withTimezone: true }),
    ransomware: boolean("ransomware").notNull().default(false),
  },
  (t) => [index("kev_date_added_idx").on(t.dateAdded)],
);
