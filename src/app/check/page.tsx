import type { Metadata } from "next";
import Link from "next/link";
import { Checker } from "./checker";

export const metadata: Metadata = {
  title: "Check your dependencies",
  description: "Drop a lockfile to see which known vulnerabilities affect your packages. Parsed in your browser; nothing is stored.",
  alternates: { canonical: "/check" },
};

export default function CheckPage() {
  return (
    <div className="mx-auto flex w-full max-w-3xl flex-col gap-6 px-4 py-10">
      <header className="flex flex-col gap-2">
        <h1 className="text-3xl font-semibold tracking-tight">Check your dependencies</h1>
        <p className="text-sm text-muted">
          Drop a lockfile to see which known vulnerabilities affect your packages. Files are read in your browser: only
          package names and versions are sent, and nothing is stored. No sign-up.
        </p>
      </header>
      <Checker />
      <p className="text-xs text-muted">
        Want this on a schedule, or from your AI assistant?{" "}
        <Link href="/docs#automate" className="underline hover:text-foreground">
          Run checks on your machine
        </Link>
        .
      </p>
    </div>
  );
}
