"use client";

import { useState } from "react";

const RESET_AFTER_MS = 2000;

export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [status, setStatus] = useState<"idle" | "copied" | "failed">("idle");

  async function copy() {
    const copied = (await copyWithClipboardApi(text)) || copyWithSelection(text);
    setStatus(copied ? "copied" : "failed");
    setTimeout(() => setStatus("idle"), RESET_AFTER_MS);
  }

  return (
    <button
      type="button"
      onClick={copy}
      className="label min-h-11 shrink-0 border border-foreground px-4 hover:bg-foreground hover:text-background"
    >
      <span aria-live="polite">
        {status === "copied" ? "Copied" : status === "failed" ? "Select and copy" : label}
      </span>
    </button>
  );
}

async function copyWithClipboardApi(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Blocked by permissions or an insecure context.
    return false;
  }
}

// Older fallback for browsers that block the Clipboard API.
function copyWithSelection(text: string): boolean {
  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.opacity = "0";
  document.body.appendChild(textarea);
  textarea.select();
  try {
    return document.execCommand("copy");
  } catch {
    return false;
  } finally {
    textarea.remove();
  }
}
