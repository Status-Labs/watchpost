import { SITE_NAME } from "@/lib/site";

// The Watchpost mark: two code chevrons forming an eye around a blue pupil.
// The chevrons follow the text color.
export function LogoMark({ className }: { className?: string }) {
  return (
    <svg viewBox="2 12 60 40" className={className} aria-hidden="true">
      <g fill="none" stroke="currentColor" strokeWidth="7" strokeLinecap="round" strokeLinejoin="round">
        <path d="M21 17 L7 32 L21 47" />
        <path d="M43 17 L57 32 L43 47" />
      </g>
      <circle cx="32" cy="32" r="7" className="fill-logo-accent" />
    </svg>
  );
}

// `compact` hides the wordmark on phones, where the header nav needs the room.
export function Logo({ className = "", compact = false }: { className?: string; compact?: boolean }) {
  return (
    <span className={`inline-flex items-center gap-2 ${className}`}>
      <LogoMark className="h-7 w-auto" />
      <span
        className={`font-wordmark text-lg font-bold lowercase tracking-[-0.03em] ${compact ? "hidden sm:inline" : ""}`}
      >
        {SITE_NAME}
      </span>
    </span>
  );
}
