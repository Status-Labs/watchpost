CREATE TABLE "sync_failures" (
	"source" text NOT NULL,
	"ecosystem" text NOT NULL,
	"vuln_id" text NOT NULL,
	"modified" text NOT NULL,
	"attempts" integer DEFAULT 1 NOT NULL,
	"last_error" text NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "sync_failures_source_ecosystem_vuln_id_pk" PRIMARY KEY("source","ecosystem","vuln_id")
);
--> statement-breakpoint
ALTER TABLE "sync_state" ADD COLUMN "last_success_at" timestamp with time zone;