import { describe, expect, it } from "vitest";
import {
  formatForFile,
  parseComposerLock,
  parseGemfileLock,
  parseGoMod,
  parseNpmLock,
  parsePlainList,
  parsePnpmLock,
  parseRequirements,
  parseTomlPackages,
  parseYarnLock,
  sniffFormat,
} from "./lockfiles";

const names = (list: { name: string; version: string }[]) => list.map((p) => `${p.name}@${p.version}`);

describe("lockfile parsers", () => {
  it("reads npm v3 and v1 lockfiles, skipping the root and links", () => {
    const v3 = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { name: "my-app", version: "1.0.0" },
        "node_modules/lodash": { version: "4.17.21" },
        "node_modules/@types/node": { version: "24.3.0" },
        "node_modules/a/node_modules/lodash": { version: "4.17.15" },
        "node_modules/local": { link: true },
      },
    });
    expect(names(parseNpmLock(v3))).toEqual(["lodash@4.17.21", "@types/node@24.3.0", "lodash@4.17.15"]);
    const v1 = JSON.stringify({ lockfileVersion: 1, dependencies: { react: { version: "18.2.0", dependencies: { "loose-envify": { version: "1.4.0" } } } } });
    expect(names(parseNpmLock(v1))).toEqual(["react@18.2.0", "loose-envify@1.4.0"]);
  });

  it("reads pnpm lockfiles from v5 to v9", () => {
    const v9 = `lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      next:
        specifier: 16.0.0
        version: 16.0.0

packages:

  '@next/env@16.0.0':
    resolution: {integrity: sha512-x}

  next@16.0.0(react@19.2.0):
    resolution: {integrity: sha512-y}

snapshots:

  next@16.0.0(react@19.2.0):
    dependencies: {}
`;
    expect(names(parsePnpmLock(v9))).toEqual(["@next/env@16.0.0", "next@16.0.0"]);
    expect(names(parsePnpmLock("lockfileVersion: 5.4\npackages:\n  /lodash/4.17.21:\n    resolution: {}\n  /@babel/core/7.0.0:\n    dev: true\n"))).toEqual([
      "lodash@4.17.21",
      "@babel/core@7.0.0",
    ]);
  });

  it("reads yarn v1 and berry lockfiles, skipping workspaces", () => {
    const v1 = `# yarn lockfile v1\n\n"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.22.13":\n  version "7.22.13"\n  resolved "https://registry.yarnpkg.com/x"\n\nlodash@^4.17.15:\n  version "4.17.21"\n`;
    expect(names(parseYarnLock(v1))).toEqual(["@babel/code-frame@7.22.13", "lodash@4.17.21"]);
    const berry = `__metadata:\n  version: 8\n\n"lodash@npm:^4.17.21":\n  version: 4.17.21\n\n"my-app@workspace:.":\n  version: 0.0.0-use.local\n`;
    expect(names(parseYarnLock(berry))).toEqual(["lodash@4.17.21"]);
    expect(names(parseYarnLock(`"@babel/core@npm:^7.25.0":\n  version: 7.25.2\n`))).toEqual(["@babel/core@7.25.2"]);
  });

  it("reads pip requirements and freeze output", () => {
    const text = "# comment\nDjango==5.2.1\nrequests[socks]==2.32.3 ; python_version >= '3.9'\n-r other.txt\nflask>=3.0\nnumpy==2.1.0 --hash=sha256:abc\n";
    expect(names(parseRequirements(text))).toEqual(["Django@5.2.1", "requests@2.32.3", "numpy@2.1.0"]);
  });

  it("reads poetry, uv and Cargo lockfiles, skipping local packages", () => {
    const cargo = `[[package]]\nname = "my-app"\nversion = "0.1.0"\n\n[[package]]\nname = "serde"\nversion = "1.0.210"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n`;
    expect(names(parseTomlPackages(cargo, "crates.io"))).toEqual(["serde@1.0.210"]);
    const uv = `version = 1\n\n[[package]]\nname = "my-app"\nversion = "0.1.0"\nsource = { editable = "." }\n\n[[package]]\nname = "httpx"\nversion = "0.28.1"\nsource = { registry = "https://pypi.org/simple" }\n`;
    expect(names(parseTomlPackages(uv, "PyPI"))).toEqual(["httpx@0.28.1"]);
    const poetry = `[[package]]\nname = "click"\nversion = "8.1.7"\n\n[package.dependencies]\ncolorama = "*"\n`;
    expect(names(parseTomlPackages(poetry, "PyPI"))).toEqual(["click@8.1.7"]);
  });

  it("reads go.mod, Gemfile.lock and composer.lock", () => {
    const gomod = "module example.com/app\n\ngo 1.24\n\nrequire github.com/gin-gonic/gin v1.10.0\n\nrequire (\n\tgolang.org/x/net v0.30.0 // indirect\n)\n";
    expect(names(parseGoMod(gomod))).toEqual(["github.com/gin-gonic/gin@v1.10.0", "golang.org/x/net@v0.30.0"]);
    const gemfile = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (8.0.0)\n      actionpack (= 8.0.0)\n    nokogiri (1.16.7-x86_64-linux)\n\nPLATFORMS\n  x86_64-linux\n";
    expect(names(parseGemfileLock(gemfile))).toEqual(["rails@8.0.0", "nokogiri@1.16.7"]);
    const composer = JSON.stringify({ packages: [{ name: "laravel/framework", version: "v11.0.0" }], "packages-dev": [{ name: "phpunit/phpunit", version: "11.4.0" }] });
    expect(names(parseComposerLock(composer))).toEqual(["laravel/framework@11.0.0", "phpunit/phpunit@11.4.0"]);
  });

  it("reads a plain list", () => {
    expect(parsePlainList("npm lodash 4.17.21\npypi Django@5.2.1\nnot a package\n")).toEqual([
      { ecosystem: "npm", name: "lodash", version: "4.17.21" },
      { ecosystem: "PyPI", name: "Django", version: "5.2.1" },
    ]);
  });

  it("picks a parser from the file name or the content", () => {
    expect(formatForFile("frontend/package-lock.json")?.id).toBe("npm");
    expect(formatForFile("Cargo.lock")?.id).toBe("cargo");
    expect(formatForFile("package.json")).toBeNull();
    expect(sniffFormat("lockfileVersion: '9.0'\n").id).toBe("pnpm");
    expect(sniffFormat("Django==5.2.1\n").id).toBe("pip");
    expect(sniffFormat("npm lodash 4.17.21").id).toBe("list");
  });
});
