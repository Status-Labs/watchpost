// Helpers for text that comes from upstream advisories or from users. Shared by
// ingest (what we store) and output (pages, markdown, feeds, MCP).

// OSV IDs, CVE IDs and aliases: GHSA-xxxx-xxxx-xxxx, CVE-2026-1234, PYSEC-2026-1, ...
export const VULN_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/;

export function isVulnId(value: string): boolean {
  return VULN_ID_PATTERN.test(value);
}

// Control characters and invisible format characters: bidi overrides that make
// text display differently from what it is ("Trojan Source"), zero-width
// characters, and Unicode tag characters, which can smuggle hidden instructions
// to an AI model reading the text. Tabs and newlines stay.
const UNSAFE_CHARS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\p{Cf}\u{E0000}-\u{E007F}]/gu;

export function stripUnsafe(value: string): string {
  return value.replace(UNSAFE_CHARS, "");
}

export function oneLine(value: string): string {
  return stripUnsafe(value).replace(/\s+/g, " ").trim();
}

// Escapes markdown syntax so upstream text renders as plain text. Collapsing to
// one line already rules out headings and lists (they need a line start); this
// rules out links, images, code spans, emphasis, tables and HTML.
export function escapeMarkdown(value: string): string {
  return oneLine(value).replace(/[\\`*_[\]()!|<>~]/g, "\\$&");
}

export function truncate(value: string, max: number): string {
  return value.length > max ? `${value.slice(0, max)}…` : value;
}

// Upstream package names and versions that are shown or sent to assistants
// as plain fields must look like names and versions, not prose.
export const PACKAGE_NAME_SHAPE = /^[A-Za-z0-9@._/:+~-]{1,214}$/;
export const VERSION_SHAPE = /^[A-Za-z0-9][A-Za-z0-9.+_~:!-]{0,99}$/;
