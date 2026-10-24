CREATE TABLE "sync_state" (
	"source" text PRIMARY KEY NOT NULL,
	"cursor" text NOT NULL,
	"last_run_at" timestamp with time zone NOT NULL,
	"last_error" text
);
--> statement-breakpoint
CREATE TABLE "vuln_packages" (
	"vuln_id" text NOT NULL,
	"ecosystem" text NOT NULL,
	"name" text NOT NULL,
	CONSTRAINT "vuln_packages_vuln_id_ecosystem_name_pk" PRIMARY KEY("vuln_id","ecosystem","name")
);
--> statement-breakpoint
CREATE TABLE "vulns" (
	"id" text PRIMARY KEY NOT NULL,
	"aliases" text[] DEFAULT '{}' NOT NULL,
	"summary" text,
	"details" text,
	"severity" text,
	"cvss_score" real,
	"published" timestamp with time zone,
	"modified" timestamp with time zone NOT NULL,
	"withdrawn" timestamp with time zone,
	"record" jsonb NOT NULL,
	"synced_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "vuln_packages" ADD CONSTRAINT "vuln_packages_vuln_id_vulns_id_fk" FOREIGN KEY ("vuln_id") REFERENCES "public"."vulns"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "vuln_packages_package_idx" ON "vuln_packages" USING btree ("ecosystem","name");--> statement-breakpoint
CREATE INDEX "vulns_published_idx" ON "vulns" USING btree ("published");--> statement-breakpoint
CREATE INDEX "vulns_aliases_idx" ON "vulns" USING gin ("aliases");