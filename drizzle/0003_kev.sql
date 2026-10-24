CREATE TABLE "kev" (
	"cve_id" text PRIMARY KEY NOT NULL,
	"vendor" text NOT NULL,
	"product" text NOT NULL,
	"name" text NOT NULL,
	"description" text NOT NULL,
	"required_action" text NOT NULL,
	"date_added" timestamp with time zone NOT NULL,
	"due_date" timestamp with time zone,
	"ransomware" boolean DEFAULT false NOT NULL
);
--> statement-breakpoint
CREATE INDEX "kev_date_added_idx" ON "kev" USING btree ("date_added");