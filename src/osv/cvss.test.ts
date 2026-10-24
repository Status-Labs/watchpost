import { describe, expect, it } from "vitest";
import { cvss3BaseScore, severityFromScore } from "./cvss";

describe("cvss3BaseScore", () => {
  it.each([
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8],
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5],
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1],
    ["CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8],
    ["CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 2],
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0],
  ])("scores %s as %s", (vector, score) => {
    expect(cvss3BaseScore(vector)).toBe(score);
  });

  it("rejects other versions and malformed vectors", () => {
    expect(cvss3BaseScore("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")).toBeNull();
    expect(cvss3BaseScore("CVSS:3.1/AV:N/AC:L")).toBeNull();
    expect(cvss3BaseScore("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toBeNull();
  });
});

describe("severityFromScore", () => {
  it("maps scores to the CVSS rating bands", () => {
    expect(severityFromScore(9.8)).toBe("critical");
    expect(severityFromScore(7)).toBe("high");
    expect(severityFromScore(4)).toBe("medium");
    expect(severityFromScore(0.1)).toBe("low");
    expect(severityFromScore(0)).toBeNull();
    expect(severityFromScore(null)).toBeNull();
  });
});
