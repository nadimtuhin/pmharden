import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync } from "fs";
import { execFileSync } from "child_process";
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

  it("one npm token line yields exactly one plaintext finding, from the most specific rule", () => {
    const token = "npm_" + "a".repeat(40);
    writeFileSync(join(home, ".npmrc"), `//registry.npmjs.org/:_authToken=${token}\n`);
    chmodSync(join(home, ".npmrc"), 0o600);

    const result = runSecretsCheck({ home, cwd });

    const plaintext = result.findings.filter((f) => f.rule.startsWith("plaintext-"));
    expect(plaintext.map((f) => f.rule)).toEqual(["plaintext-npm-token"]);
  });

  it("two different secrets on separate lines still yield one finding each", () => {
    writeFileSync(join(home, ".npmrc"), `//registry.npmjs.org/:_authToken=npm_${"a".repeat(40)}\n_password=hunter22\n`);
    chmodSync(join(home, ".npmrc"), 0o600);

    const result = runSecretsCheck({ home, cwd });

    const plaintext = result.findings.filter((f) => f.rule.startsWith("plaintext-"));
    expect(plaintext.map((f) => f.rule).sort()).toEqual(["plaintext-npm-password", "plaintext-npm-token"]);
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

  // root can read chmod 0o000 files, so this fault-injection doesn't apply when running as root.
  it.skipIf(process.getuid?.() === 0)(
    "unreadable .npmrc (chmod 000) fires skipped naming the path, with no plaintext findings claimed",
    () => {
      writeFileSync(join(home, ".npmrc"), `//registry.npmjs.org/:_authToken=${"npm_" + "a".repeat(40)}\n`);
      chmodSync(join(home, ".npmrc"), 0o000);

      try {
        const result = runSecretsCheck({ home, cwd });

        expect(result.skipped).toBeDefined();
        expect(result.skipped).toContain(join(home, ".npmrc"));
        expect(result.findings.some((f) => f.rule.startsWith("plaintext-"))).toBe(false);
      } finally {
        chmodSync(join(home, ".npmrc"), 0o600);
      }
    }
  );
});

describe("secrets check: project under $HOME", () => {
  let home: string;
  let cwd: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "pmharden-secrets-home-"));
    cwd = join(home, "code", "project");
    mkdirSync(cwd, { recursive: true });
    execFileSync("git", ["init", "-q"], { cwd });
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
  });

  it("a committed project .npmrc with a token fires config-committed-to-git even though the project lives under $HOME", () => {
    writeFileSync(join(cwd, ".npmrc"), `//registry.npmjs.org/:_authToken=npm_${"b".repeat(40)}\n`);
    execFileSync("git", ["add", ".npmrc"], { cwd });

    const result = runSecretsCheck({ home, cwd });
    expect(result.findings.some((f) => f.rule === "config-committed-to-git")).toBe(true);
  });

  it("a second scan in the same process still finds the token (shared /g regex state is not leaked)", () => {
    writeFileSync(join(cwd, ".npmrc"), `//registry.npmjs.org/:_authToken=npm_${"d".repeat(40)}\n`);
    execFileSync("git", ["add", ".npmrc"], { cwd });

    runSecretsCheck({ home, cwd });
    const second = runSecretsCheck({ home, cwd });
    expect(second.findings.some((f) => f.rule === "plaintext-npm-token")).toBe(true);
  });

  it("running from $HOME itself does not report the same file twice", () => {
    writeFileSync(join(home, ".npmrc"), `//registry.npmjs.org/:_authToken=npm_${"c".repeat(40)}\n`);
    chmodSync(join(home, ".npmrc"), 0o600);

    const result = runSecretsCheck({ home, cwd: home });
    expect(result.findings.filter((f) => f.rule === "plaintext-npm-token")).toHaveLength(1);
  });
});

describe("secrets check on Windows", () => {
  const realPlatform = process.platform;
  let home: string;
  let cwd: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "pmharden-secrets-home-"));
    cwd = mkdtempSync(join(tmpdir(), "pmharden-secrets-cwd-"));
    Object.defineProperty(process, "platform", { value: "win32" });
  });

  afterEach(() => {
    Object.defineProperty(process, "platform", { value: realPlatform });
    rmSync(home, { recursive: true, force: true });
    rmSync(cwd, { recursive: true, force: true });
  });

  it("does not report POSIX mode bits as config-file-permissions (Windows always reports 0o666)", () => {
    writeFileSync(join(home, ".npmrc"), "ignore-scripts=true\n");
    chmodSync(join(home, ".npmrc"), 0o666);

    const result = runSecretsCheck({ home, cwd });
    expect(result.findings.some((f) => f.rule === "config-file-permissions")).toBe(false);
  });
});
