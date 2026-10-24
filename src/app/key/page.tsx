import type { Metadata } from "next";
import Link from "next/link";
import { mcpResourceUrl } from "@/auth/oauth";
import { SITE_NAME } from "@/lib/site";
import { KeyForm } from "./key-form";

export const metadata: Metadata = {
  title: "Get a key",
  robots: { index: false, follow: false },
};

// For MCP apps that can't sign in with OAuth. Most apps can: they open the
// /connect page instead, and the token never passes through the user.
export default function KeyPage() {
  return (
    <div className="mx-auto flex w-full max-w-2xl flex-col gap-6 px-4 py-12">
      <header className="flex flex-col gap-2">
        <h1 className="text-3xl font-semibold tracking-tight">Get a key</h1>
        <p className="text-sm text-muted">
          Only for AI apps that can&apos;t sign in to MCP servers on their own. Most can: add{" "}
          <code className="font-mono text-xs">{mcpResourceUrl()}</code> and approve in the browser instead.{" "}
          <Link href="/docs#mcp" className="underline hover:text-foreground">
            Setup guide
          </Link>
        </p>
      </header>
      <ul className="flex flex-col gap-2 text-sm text-muted">
        <li>This creates a new, private {SITE_NAME} workspace with no account, email or name.</li>
        <li>Anyone with the key can see the workspace&apos;s stacks. There&apos;s no recovery if you lose it: make a new one.</li>
        <li>Unused workspaces are deleted after 90 days.</li>
      </ul>
      <KeyForm mcpUrl={mcpResourceUrl()} />
    </div>
  );
}
