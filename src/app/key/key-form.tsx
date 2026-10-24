"use client";

import { useState, useTransition } from "react";
import { CopyButton } from "@/components/copy-button";
import { createKey } from "./actions";

export function KeyForm({ mcpUrl }: { mcpUrl: string }) {
  const [key, setKey] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  if (!key) {
    return (
      <button
        type="button"
        disabled={pending}
        onClick={() => startTransition(async () => setKey((await createKey()).key))}
        className="label min-h-11 self-start bg-foreground px-5 text-background disabled:opacity-60"
      >
        {pending ? "Creating…" : "Create a workspace and key"}
      </button>
    );
  }

  const config = JSON.stringify(
    { mcpServers: { watchpost: { type: "http", url: mcpUrl, headers: { Authorization: "Bearer ${WATCHPOST_KEY}" } } } },
    null,
    2,
  );

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-col gap-2 border-2 border-foreground p-4">
        <p className="label">Your key. It&apos;s shown once.</p>
        <div className="flex items-start justify-between gap-3">
          <code className="min-w-0 flex-1 break-all font-mono text-sm">{key}</code>
          <CopyButton text={key} />
        </div>
      </div>
      <ol className="flex list-decimal flex-col gap-2 pl-5 text-sm">
        <li>
          Save it as an environment variable named <code className="font-mono text-xs">WATCHPOST_KEY</code>, for
          example in your shell profile or password manager&apos;s CLI. Never paste it into an AI chat or commit it.
        </li>
        <li>Point your MCP config at it, at user level (not a file in your project):</li>
      </ol>
      <div className="flex items-start justify-between gap-3 border border-border bg-surface py-1 pl-4 pr-1">
        <pre className="min-w-0 flex-1 overflow-x-auto py-2.5 font-mono text-xs">{config}</pre>
        <CopyButton text={config} />
      </div>
    </div>
  );
}
