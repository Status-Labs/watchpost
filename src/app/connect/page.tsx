import type { Metadata } from "next";
import Link from "next/link";
import { Suspense } from "react";
import { LogoMark } from "@/components/logo";
import { OAuthError, authorizeSchema, validateAuthorize } from "@/auth/oauth";
import { getDb } from "@/db";
import { SITE_NAME } from "@/lib/site";

export const metadata: Metadata = {
  title: "Connect an app",
  robots: { index: false, follow: false },
};

// The OAuth approval page. An MCP app opens it in the browser; approving
// creates a new, empty workspace and sends a one-time code back to the app.
export default function ConnectPage({ searchParams }: PageProps<"/connect">) {
  return (
    <div className="mx-auto flex w-full max-w-lg flex-col gap-6 px-4 py-12">
      <Suspense fallback={<div className="h-64 border border-border bg-surface" aria-busy="true" />}>
        <Approval searchParams={searchParams} />
      </Suspense>
    </div>
  );
}

async function Approval({ searchParams }: Pick<PageProps<"/connect">, "searchParams">) {
  const params = await searchParams;
  let validated;
  try {
    validated = await validateAuthorize(getDb(), params);
  } catch (error) {
    if (error instanceof OAuthError) return <Problem message={error.description} />;
    throw error;
  }
  const { request, client, redirectHost } = validated;

  return (
    <section className="flex flex-col gap-6 border border-border bg-surface p-6">
      <header className="flex items-center gap-3">
        <LogoMark className="h-7 w-auto" />
        <h1 className="text-xl font-semibold tracking-tight">Connect to {SITE_NAME}</h1>
      </header>

      <div className="flex flex-col gap-1">
        {/* The client name comes from the app itself: shown as plain text, never trusted. */}
        <p className="text-sm">
          An app calling itself <span className="font-semibold break-words">&ldquo;{client.name}&rdquo;</span> wants
          to report your software and read its alerts.
        </p>
        <p className="font-mono text-xs text-muted break-all">It will return to {redirectHost}</p>
      </div>

      <ul className="flex flex-col gap-2 text-sm text-muted">
        <li>This creates a new, private workspace. There&apos;s no account, email or name.</li>
        <li>The app sends only package names and versions. Nothing about you or your machine.</li>
        <li>Don&apos;t name stacks anything that can be traced back to you or your company.</li>
        <li>Unused workspaces are deleted after 90 days.</li>
      </ul>

      <form method="post" action="/connect/approve" className="flex flex-col gap-3 sm:flex-row-reverse">
        {Object.keys(authorizeSchema.shape).map((key) => {
          const value = request[key as keyof typeof request];
          return value === undefined ? null : <input key={key} type="hidden" name={key} value={value} />;
        })}
        <button
          type="submit"
          name="decision"
          value="approve"
          className="label min-h-11 flex-1 bg-foreground px-5 text-background"
        >
          Create a private workspace
        </button>
        <button type="submit" name="decision" value="deny" className="label min-h-11 border border-border-strong px-5">
          Cancel
        </button>
      </form>

      <p className="text-xs text-muted">
        Only continue if you just asked an AI app to connect to {SITE_NAME}.{" "}
        <Link href="/docs#privacy" className="underline hover:text-foreground">
          How we handle your data
        </Link>
      </p>
    </section>
  );
}

function Problem({ message }: { message: string }) {
  return (
    <section className="flex flex-col gap-3 border border-border bg-surface p-6">
      <h1 className="text-xl font-semibold tracking-tight">Can&apos;t connect</h1>
      <p className="text-sm text-muted">{message}</p>
      <Link href="/docs#mcp" className="label min-h-11 content-center self-start underline">
        Setup instructions
      </Link>
    </section>
  );
}
