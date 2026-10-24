import { describe, expect, it } from "vitest";
import { looksSecret, validateItems } from "./validate";

const item = (ecosystem: string, name: string, version = "1.0.0") => ({ ecosystem, name, version });

describe("validateItems", () => {
  it("accepts real package names from each ecosystem's format", () => {
    const { items, rejected } = validateItems([
      item("npm", "@types/node", "24.3.0"),
      item("npm", "disk-usage"),
      item("PyPI", "Django", "5.2.1"),
      item("Go", "github.com/gin-gonic/gin", "v1.10.0"),
      item("Go", "golang.org/x/net", "v0.0.0-20240101120000-abcdef123456"),
      item("crates.io", "serde_json"),
      item("Maven", "org.apache.logging.log4j:log4j-core", "2.17.1"),
      item("Packagist", "laravel/framework"),
      item("RubyGems", "rails", "8.0.0"),
      item("GitHub Actions", "actions/checkout", "4"),
      item("PyPI", "requests", "1:2.32.3"),
    ]);
    expect(rejected).toEqual([]);
    expect(items).toHaveLength(11);
  });

  it("drops anything that looks like a path, host, IP, email, URL or secret", () => {
    const { items, rejected } = validateItems([
      item("npm", "/home/alex/projects/acme"),
      item("npm", "../secrets"),
      item("PyPI", "https://internal.acme.example/pkg"),
      item("npm", "alex@acme.example"),
      item("Go", "10.0.0.12/internal"),
      item("npm", "ghp_abcdefghijklmnopqrstuvwxyz0123456789"),
      item("npm", "lodash", "sk-proj-AbCdEf0123456789xyzXYZ"),
      item("Debian", "openssl"),
      item("npm", "has space"),
      item("Go", "git.acme.internal/team/billing", "v1.0.0"),
      item("npm", "lodash", "db.example.com:8443"),
    ]);
    expect(items).toEqual([]);
    expect(rejected.map((r) => r.reason)).toEqual([
      "looks like a path or URL",
      "looks like a path or URL",
      "looks like a path or URL",
      "looks like an email address",
      "looks like an IP address",
      "looks like a secret",
      "looks like a secret",
      "unsupported ecosystem",
      "invalid package name",
      "looks like an internal hostname",
      "invalid version",
    ]);
    // Values that looked like secrets aren't echoed back.
    expect(rejected[5]).toMatchObject({ name: "[hidden]", version: "[hidden]" });
  });

  it("removes duplicates", () => {
    expect(validateItems([item("npm", "react"), item("npm", "react")]).items).toHaveLength(1);
  });
});

describe("looksSecret", () => {
  it("spots key prefixes and long random strings, not package names", () => {
    expect(looksSecret("AKIAIOSFODNN7EXAMPLEX")).toBe(true);
    expect(looksSecret("q8Zr2LmP0vXy7TnKw4Hs9DbFj3GcQe1Ua5")).toBe(true);
    expect(looksSecret("task-runner")).toBe(false);
    expect(looksSecret("eslint-plugin-react-hooks-and-friends-extended")).toBe(false);
  });
});
