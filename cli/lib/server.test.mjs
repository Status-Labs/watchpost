import { describe, expect, it } from "vitest";
import { allowedRequest } from "./server.mjs";

describe("allowedRequest", () => {
  it("accepts localhost on our port", () => {
    expect(allowedRequest({ host: "127.0.0.1:4141" }, 4141)).toBe(true);
    expect(allowedRequest({ host: "localhost:4141" }, 4141)).toBe(true);
    expect(allowedRequest({ host: "[::1]:4141" }, 4141)).toBe(true);
    expect(allowedRequest({ host: "LOCALHOST:4141", "sec-fetch-site": "same-origin" }, 4141)).toBe(true);
    expect(allowedRequest({ host: "localhost:4141", "sec-fetch-site": "none" }, 4141)).toBe(true);
  });

  it("refuses other hosts (DNS rebinding) and other ports", () => {
    expect(allowedRequest({ host: "evil.example:4141" }, 4141)).toBe(false);
    expect(allowedRequest({ host: "127.0.0.1.nip.io:4141" }, 4141)).toBe(false);
    expect(allowedRequest({ host: "localhost:3000" }, 4141)).toBe(false);
    expect(allowedRequest({ host: "localhost" }, 4141)).toBe(false);
    expect(allowedRequest({}, 4141)).toBe(false);
  });

  it("refuses requests other websites make from the browser", () => {
    expect(allowedRequest({ host: "localhost:4141", "sec-fetch-site": "cross-site" }, 4141)).toBe(false);
  });
});
