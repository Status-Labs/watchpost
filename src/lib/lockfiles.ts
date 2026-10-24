// Lockfile parsers for the /check page. They run in the browser, so a dropped
// file never leaves the visitor's machine: only the package names and versions
// they extract are sent. Lockfiles give installed versions; manifests like
// package.json only give ranges, so they aren't supported.

export type ParsedPackage = { ecosystem: string; name: string; version: string };

export type LockfileFormat = {
  id: string;
  label: string;
  matches: (filename: string) => boolean;
  parse: (text: string) => ParsedPackage[];
};

export const LOCKFILE_FORMATS: LockfileFormat[] = [
  { id: "npm", label: "package-lock.json", matches: (f) => /(^|\/)(package-lock|npm-shrinkwrap)\.json$/.test(f), parse: parseNpmLock },
  { id: "pnpm", label: "pnpm-lock.yaml", matches: (f) => /(^|\/)pnpm-lock\.ya?ml$/.test(f), parse: parsePnpmLock },
  { id: "yarn", label: "yarn.lock", matches: (f) => /(^|\/)yarn\.lock$/.test(f), parse: parseYarnLock },
  { id: "pip", label: "requirements.txt or pip freeze", matches: (f) => /requirements[^/]*\.txt$/.test(f), parse: parseRequirements },
  { id: "poetry", label: "poetry.lock", matches: (f) => /(^|\/)poetry\.lock$/.test(f), parse: (t) => parseTomlPackages(t, "PyPI") },
  { id: "uv", label: "uv.lock", matches: (f) => /(^|\/)uv\.lock$/.test(f), parse: (t) => parseTomlPackages(t, "PyPI") },
  { id: "cargo", label: "Cargo.lock", matches: (f) => /(^|\/)Cargo\.lock$/.test(f), parse: (t) => parseTomlPackages(t, "crates.io") },
  { id: "go", label: "go.mod", matches: (f) => /(^|\/)go\.mod$/.test(f), parse: parseGoMod },
  { id: "bundler", label: "Gemfile.lock", matches: (f) => /(^|\/)Gemfile\.lock$/.test(f), parse: parseGemfileLock },
  { id: "composer", label: "composer.lock", matches: (f) => /(^|\/)composer\.lock$/.test(f), parse: parseComposerLock },
  { id: "list", label: "A list: ecosystem name version, one per line", matches: () => false, parse: parsePlainList },
];

export function formatForFile(filename: string): LockfileFormat | null {
  return LOCKFILE_FORMATS.find((f) => f.matches(filename)) ?? null;
}

// Best guess for pasted text.
export function sniffFormat(text: string): LockfileFormat {
  const t = text.trimStart();
  const byId = (id: string) => LOCKFILE_FORMATS.find((f) => f.id === id)!;
  if (t.startsWith("{")) return /"lockfileVersion"/.test(t) ? byId("npm") : byId("composer");
  if (/^lockfileVersion:/m.test(t)) return byId("pnpm");
  if (/^# yarn lockfile|^__metadata:/m.test(t)) return byId("yarn");
  if (/^module\s+\S+/m.test(t) && /^require\b/m.test(t)) return byId("go");
  if (/^GEM$/m.test(t) && /^ {2}specs:$/m.test(t)) return byId("bundler");
  if (/^\[\[package\]\]$/m.test(t)) return /source = "registry\+/.test(t) ? byId("cargo") : byId("poetry");
  if (/^[A-Za-z0-9._-]+(\[[^\]]*\])?==/m.test(t)) return byId("pip");
  return byId("list");
}

export function dedupePackages(packages: ParsedPackage[]): ParsedPackage[] {
  return [...new Map(packages.map((p) => [`${p.ecosystem}\u0000${p.name}\u0000${p.version}`, p])).values()];
}

// npm v2/v3 lockfiles list every installed package under "packages", keyed by
// path; v1 nests them under "dependencies".
export function parseNpmLock(text: string): ParsedPackage[] {
  const json = JSON.parse(text) as {
    packages?: Record<string, { name?: string; version?: string; link?: boolean }>;
    dependencies?: Record<string, NpmV1Dep>;
  };
  const out: ParsedPackage[] = [];
  if (json.packages) {
    for (const [path, pkg] of Object.entries(json.packages)) {
      if (!path || pkg.link || !pkg.version) continue;
      const name = pkg.name ?? path.slice(path.lastIndexOf("node_modules/") + "node_modules/".length);
      out.push({ ecosystem: "npm", name, version: pkg.version });
    }
  } else if (json.dependencies) {
    const walk = (deps: Record<string, NpmV1Dep>) => {
      for (const [name, dep] of Object.entries(deps)) {
        if (dep.version && !dep.version.includes(":")) out.push({ ecosystem: "npm", name, version: dep.version });
        if (dep.dependencies) walk(dep.dependencies);
      }
    };
    walk(json.dependencies);
  }
  return dedupePackages(out);
}
type NpmV1Dep = { version?: string; dependencies?: Record<string, NpmV1Dep> };

// pnpm v6 to v9 keys look like "/name@1.2.3(peer@1)" or "name@1.2.3"; v5 used "/name/1.2.3".
export function parsePnpmLock(text: string): ParsedPackage[] {
  const out: ParsedPackage[] = [];
  let inPackages = false;
  for (const line of text.split(/\r?\n/)) {
    if (/^\S/.test(line)) {
      inPackages = line.startsWith("packages:");
      continue;
    }
    if (!inPackages) continue;
    const key = /^ {2}['"]?(\/?[^'"\s][^'"]*?)['"]?:\s*$/.exec(line)?.[1];
    if (!key) continue;
    const bare = key.replace(/^\//, "").replace(/\(.*$/, "");
    const at = bare.lastIndexOf("@");
    if (at > 0) {
      out.push({ ecosystem: "npm", name: bare.slice(0, at), version: bare.slice(at + 1) });
      continue;
    }
    const v5 = /^(@[^/]+\/[^/]+|[^/]+)\/([^/]+)$/.exec(bare);
    if (v5) out.push({ ecosystem: "npm", name: v5[1], version: v5[2] });
  }
  return dedupePackages(out.filter((p) => /^\d/.test(p.version)));
}

// yarn v1: `"name@^1.0.0", name@^1.2.0:` then `  version "1.2.3"`.
// yarn berry: `"name@npm:^1.0.0":` then `  version: 1.2.3`.
export function parseYarnLock(text: string): ParsedPackage[] {
  const out: ParsedPackage[] = [];
  let name: string | null = null;
  for (const line of text.split(/\r?\n/)) {
    if (/^\S.*:$/.test(line) && !line.startsWith("#") && !line.startsWith("__metadata")) {
      const spec = line.slice(0, -1).split(",")[0].trim().replace(/^"|"$/g, "");
      const at = spec.lastIndexOf("@");
      name = at > 0 ? spec.slice(0, at) : null;
      // Workspace packages and links aren't from the registry.
      if (spec.includes("@workspace:") || spec.includes("@link:") || spec.includes("@portal:")) name = null;
      continue;
    }
    const version = /^ {2}version:? "?([^"\s]+)"?$/.exec(line)?.[1];
    if (name && version) {
      out.push({ ecosystem: "npm", name, version });
      name = null;
    }
  }
  return dedupePackages(out);
}

// "name==1.2.3", with optional extras, markers, comments and hashes.
export function parseRequirements(text: string): ParsedPackage[] {
  const out: ParsedPackage[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/\s+#.*$/, "").trim();
    const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9.!+_-]+)/.exec(line);
    if (m) out.push({ ecosystem: "PyPI", name: m[1], version: m[2] });
  }
  return dedupePackages(out);
}

// [[package]] blocks with name, version and (for Cargo and uv) a source.
// Local packages (the project itself, workspace members, path dependencies) are skipped.
export function parseTomlPackages(text: string, ecosystem: string): ParsedPackage[] {
  const out: ParsedPackage[] = [];
  for (const block of text.split(/^\[\[package\]\]\s*$/m).slice(1)) {
    const body = block.split(/^\[(?!\[package\])/m)[0];
    const name = /^name\s*=\s*"([^"]+)"/m.exec(body)?.[1];
    const version = /^version\s*=\s*"([^"]+)"/m.exec(body)?.[1];
    const source = /^source\s*=\s*(.+)$/m.exec(body)?.[1] ?? "";
    if (!name || !version) continue;
    if (ecosystem === "crates.io" && !source.includes("registry+")) continue;
    if (/editable|virtual|path|directory|git\s*=/.test(source)) continue;
    out.push({ ecosystem, name, version });
  }
  return dedupePackages(out);
}

// go.mod require lines: "require module v1.2.3" or inside "require ( ... )".
export function parseGoMod(text: string): ParsedPackage[] {
  const out: ParsedPackage[] = [];
  let inRequire = false;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/\/\/.*$/, "").trim();
    if (/^require\s*\($/.test(line)) {
      inRequire = true;
      continue;
    }
    if (inRequire && line === ")") {
      inRequire = false;
      continue;
    }
    const m = (inRequire ? /^(\S+)\s+(v\S+)$/ : /^require\s+(\S+)\s+(v\S+)$/).exec(line);
    if (m) out.push({ ecosystem: "Go", name: m[1], version: m[2] });
  }
  return dedupePackages(out);
}

// Gemfile.lock: gems are listed under "GEM" / "  specs:" as "    name (version)".
export function parseGemfileLock(text: string): ParsedPackage[] {
  const out: ParsedPackage[] = [];
  let section = "";
  for (const line of text.split(/\r?\n/)) {
    if (/^\S/.test(line)) section = line.trim();
    if (section !== "GEM") continue;
    const m = /^ {4}([A-Za-z0-9_.-]+) \(([^)\s]+)\)$/.exec(line);
    if (m) out.push({ ecosystem: "RubyGems", name: m[1], version: m[2].replace(/-(x86|arm|aarch|universal|java|x64).*$/, "") });
  }
  return dedupePackages(out);
}

export function parseComposerLock(text: string): ParsedPackage[] {
  const json = JSON.parse(text) as Record<string, { name?: string; version?: string }[] | undefined>;
  const out: ParsedPackage[] = [];
  for (const pkg of [...(json.packages ?? []), ...(json["packages-dev"] ?? [])]) {
    if (pkg.name && pkg.version) out.push({ ecosystem: "Packagist", name: pkg.name, version: pkg.version.replace(/^v(?=\d)/, "") });
  }
  return dedupePackages(out);
}

const ECOSYSTEM_ALIASES: Record<string, string> = {
  npm: "npm",
  pypi: "PyPI",
  pip: "PyPI",
  go: "Go",
  golang: "Go",
  "crates.io": "crates.io",
  cargo: "crates.io",
  rust: "crates.io",
  maven: "Maven",
  nuget: "NuGet",
  packagist: "Packagist",
  composer: "Packagist",
  rubygems: "RubyGems",
  gem: "RubyGems",
  hex: "Hex",
  pub: "Pub",
};

// "npm lodash 4.17.21" or "npm lodash@4.17.21", one per line.
export function parsePlainList(text: string): ParsedPackage[] {
  const out: ParsedPackage[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, "").trim();
    if (!line) continue;
    const [eco, rest, maybeVersion] = line.split(/\s+/);
    const ecosystem = ECOSYSTEM_ALIASES[eco?.toLowerCase() ?? ""];
    if (!ecosystem || !rest) continue;
    if (maybeVersion) {
      out.push({ ecosystem, name: rest, version: maybeVersion });
    } else {
      const at = rest.lastIndexOf("@");
      if (at > 0) out.push({ ecosystem, name: rest.slice(0, at), version: rest.slice(at + 1) });
    }
  }
  return dedupePackages(out);
}
