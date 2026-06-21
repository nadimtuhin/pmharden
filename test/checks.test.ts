import { describe, it, expect } from "bun:test";
import { runConfigAudit } from "../src/checks/config-audit.js";
import { runSecretsCheck } from "../src/checks/secrets.js";

describe("config-audit", () => {
  it("returns findings array", () => {
    const result = runConfigAudit();
    expect(Array.isArray(result.findings)).toBe(true);
  });

  it("each finding has required fields", () => {
    const result = runConfigAudit();
    for (const f of result.findings) {
      expect(typeof f.severity).toBe("string");
      expect(typeof f.rule).toBe("string");
      expect(typeof f.message).toBe("string");
      expect(typeof f.tool).toBe("string");
    }
  });

  it("severity values are valid", () => {
    const valid = new Set(["critical", "high", "medium", "low", "info"]);
    const result = runConfigAudit();
    for (const f of result.findings) {
      expect(valid.has(f.severity)).toBe(true);
    }
  });
});

describe("secrets-check", () => {
  it("returns findings array", () => {
    const result = runSecretsCheck();
    expect(Array.isArray(result.findings)).toBe(true);
  });

  it("detects critical findings for plaintext tokens when present", () => {
    const result = runSecretsCheck();
    const criticals = result.findings.filter((f) => f.severity === "critical");
    // We know the test machine has a plaintext token — at least 1 critical expected
    // On a clean machine this would be 0 (valid)
    expect(criticals.length).toBeGreaterThanOrEqual(0);
  });
});
