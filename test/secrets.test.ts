import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { mkdtempSync, writeFileSync, chmodSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { runSecretsCheck } from "../src/checks/secrets.js";

describe("secrets check", () => {
  let home: string;
  let cwd: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "pmharden-secrets-home-"));
    cwd = mkdtempSync(join(tmpdir(), "pmharden-secrets-cwd-"));
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
    rmSync(cwd, { recursive: true, force: true });
  });

  it("plaintext npm token fires plaintext-npm-token critical + config-file-permissions high, redacts value", () => {
    const token = "npm_" + "a".repeat(40);
    writeFileSync(join(home, ".npmrc"), `//registry.npmjs.org/:_authToken=${token}\n`);
    chmodSync(join(home, ".npmrc"), 0o644);

    const result = runSecretsCheck({ home, cwd });

    const tokenFinding = result.findings.find((f) => f.rule === "plaintext-npm-token");
    expect(tokenFinding?.severity).toBe("critical");
    expect(tokenFinding?.message).toContain("***REDACTED***");
    expect(tokenFinding?.message).not.toContain(token);

    const permFinding = result.findings.find((f) => f.rule === "config-file-permissions");
    expect(permFinding?.severity).toBe("high");
  });

  it("clean policy-only npmrc produces zero findings", () => {
    writeFileSync(join(home, ".npmrc"), "ignore-scripts=true\naudit=true\n");
    chmodSync(join(home, ".npmrc"), 0o600);

    const result = runSecretsCheck({ home, cwd });

    expect(result.findings).toEqual([]);
  });

  it("statefulness canary: repeated calls with same fixture return deep-equal findings", () => {
    const token = "npm_" + "a".repeat(40);
    writeFileSync(join(home, ".npmrc"), `//registry.npmjs.org/:_authToken=${token}\n`);
    chmodSync(join(home, ".npmrc"), 0o644);

    const first = runSecretsCheck({ home, cwd });
    const second = runSecretsCheck({ home, cwd });

    expect(second.findings).toEqual(first.findings);
  });

  it("env-var reference token produces no plaintext-* finding", () => {
    writeFileSync(join(home, ".npmrc"), "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n");
    chmodSync(join(home, ".npmrc"), 0o600);

    const result = runSecretsCheck({ home, cwd });

    expect(result.findings.some((f) => f.rule.startsWith("plaintext-"))).toBe(false);
  });

  it("legacy UUID token fires legacy-publish-token high (and plaintext-npm-token-generic critical)", () => {
    writeFileSync(
      join(home, ".npmrc"),
      "//registry.npmjs.org/:_authToken=00000000-0000-0000-0000-000000000000\n"
    );
    chmodSync(join(home, ".npmrc"), 0o600);

    const result = runSecretsCheck({ home, cwd });

    const legacyFinding = result.findings.find((f) => f.rule === "legacy-publish-token");
    expect(legacyFinding?.severity).toBe("high");

    // The generic plaintext pattern also matches a bare UUID token — encode observed behavior.
    const genericFinding = result.findings.find((f) => f.rule === "plaintext-npm-token-generic");
    expect(genericFinding?.severity).toBe("critical");
  });

  it("empty token line fires empty-token-line medium", () => {
    writeFileSync(join(home, ".npmrc"), "//registry.npmjs.org/:_authToken=\n");
    chmodSync(join(home, ".npmrc"), 0o600);

    const result = runSecretsCheck({ home, cwd });

    const emptyFinding = result.findings.find((f) => f.rule === "empty-token-line");
    expect(emptyFinding?.severity).toBe("medium");
  });
});
