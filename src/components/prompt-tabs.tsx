"use client";

import { useId, useRef, useState, type KeyboardEvent } from "react";
import type { AgentGuide } from "@/lib/snippets";
import { CopyButton } from "./copy-button";

// Setup for each AI app: add the MCP server once, then paste a prompt.
// Tabs follow the ARIA pattern: arrow keys move between them.
export function PromptTabs({ guides, expanded = false }: { guides: AgentGuide[]; expanded?: boolean }) {
  const [selected, setSelected] = useState(0);
  const tabs = useRef<(HTMLButtonElement | null)[]>([]);
  const id = useId();
  const guide = guides[selected];

  function onKeyDown(event: KeyboardEvent) {
    const moves: Record<string, number> = {
      ArrowRight: selected + 1,
      ArrowLeft: selected - 1,
      Home: 0,
      End: guides.length - 1,
    };
    if (!(event.key in moves)) return;
    event.preventDefault();
    const next = (moves[event.key] + guides.length) % guides.length;
    setSelected(next);
    tabs.current[next]?.focus();
  }

  return (
    <div className="w-full border border-border bg-surface">
      <div role="tablist" aria-label="AI app" onKeyDown={onKeyDown} className="grid grid-cols-2 border-b border-border sm:grid-cols-4">
        {guides.map((g, i) => (
          <button
            key={g.id}
            ref={(el) => {
              tabs.current[i] = el;
            }}
            type="button"
            role="tab"
            id={`${id}-tab-${g.id}`}
            aria-selected={i === selected}
            aria-controls={`${id}-panel`}
            tabIndex={i === selected ? 0 : -1}
            onClick={() => setSelected(i)}
            className={`label min-h-11 px-3 text-center ${
              i === selected ? "bg-foreground text-background" : "text-muted hover:text-foreground"
            }`}
          >
            {g.label}
          </button>
        ))}
      </div>

      <div role="tabpanel" id={`${id}-panel`} aria-labelledby={`${id}-tab-${guide.id}`} className="flex flex-col">
        <Step number={1} title={guide.setup.label} copyText={guide.setup.code} copyLabel="Copy">
          <pre className="overflow-x-auto border-t border-border px-4 py-3 font-mono text-xs leading-relaxed">
            {guide.setup.code}
          </pre>
          {guide.setupNote && <p className="border-t border-border px-4 py-2 text-xs text-muted">{guide.setupNote}</p>}
        </Step>
        <Step number={2} title="Then paste this prompt" copyText={guide.prompt} copyLabel="Copy prompt">
          <details open={expanded} className="group border-t border-border">
            <summary className="flex min-h-11 cursor-pointer list-none items-center gap-3 px-4 text-sm text-muted hover:text-foreground [&::-webkit-details-marker]:hidden">
              <span className="min-w-0 flex-1 truncate font-mono text-xs group-open:hidden">{guide.prompt.split("\n")[0]}</span>
              <span className="hidden flex-1 font-mono text-xs group-open:inline">Full prompt</span>
              <span className="label shrink-0">
                <span className="group-open:hidden">Show</span>
                <span className="hidden group-open:inline">Hide</span>
              </span>
            </summary>
            <pre className="whitespace-pre-wrap break-words border-t border-border p-4 font-mono text-xs leading-relaxed">
              {guide.prompt}
            </pre>
          </details>
        </Step>
      </div>
    </div>
  );
}

function Step({
  number,
  title,
  copyText,
  copyLabel,
  children,
}: {
  number: number;
  title: string;
  copyText: string;
  copyLabel: string;
  children: React.ReactNode;
}) {
  return (
    <div className="border-b border-border last:border-b-0">
      <div className="flex items-center justify-between gap-3 py-1 pl-4 pr-1">
        <span className="min-w-0 text-sm">
          <span className="label mr-2 text-muted">{number}</span>
          {title}
        </span>
        <CopyButton text={copyText} label={copyLabel} />
      </div>
      {children}
    </div>
  );
}
