// Package ecosystems we sync from OSV, labeled by the language people know
// them by. Kept free of server imports so client components can use it.
export const LANGUAGES: { ecosystem: string; label: string }[] = [
  { ecosystem: "npm", label: "JavaScript / TypeScript (npm)" },
  { ecosystem: "PyPI", label: "Python (PyPI)" },
  { ecosystem: "Go", label: "Go" },
  { ecosystem: "crates.io", label: "Rust (crates.io)" },
  { ecosystem: "Maven", label: "Java / Kotlin (Maven)" },
  { ecosystem: "NuGet", label: ".NET (NuGet)" },
  { ecosystem: "Packagist", label: "PHP (Packagist)" },
  { ecosystem: "RubyGems", label: "Ruby (RubyGems)" },
  { ecosystem: "Hex", label: "Elixir / Erlang (Hex)" },
  { ecosystem: "Pub", label: "Dart / Flutter (Pub)" },
  { ecosystem: "SwiftURL", label: "Swift" },
  { ecosystem: "Hackage", label: "Haskell (Hackage)" },
  { ecosystem: "CRAN", label: "R (CRAN)" },
  { ecosystem: "GitHub Actions", label: "GitHub Actions" },
];
