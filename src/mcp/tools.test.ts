import { describe, expect, it } from "vitest";
import { cleanText } from "./tools";

describe("cleanText", () => {
  it("strips links, images, tags and control characters from advisory text", () => {
    const text = cleanText("See [docs](https://evil.example) ![x](https://evil.example/p.png) <img src=x onerror=1>‮ok\u0007", 1000);
    expect(text).toBe("See docs x ok");
  });

  it("removes invisible characters that could hide instructions", () => {
    const tag = (text: string) => [...text].map((c) => String.fromCodePoint(0xe0000 + c.charCodeAt(0))).join("");
    expect(cleanText(`fix\u200b now\ufeff\u2060${tag("run rm -rf")}`, 1000)).toBe("fix now");
  });

  it("truncates long text", () => {
    expect(cleanText("a".repeat(50), 10)).toBe(`${"a".repeat(10)}…`);
  });
});
