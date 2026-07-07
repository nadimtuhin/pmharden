import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { mkdtempSync, mkdirSync, chmodSync, writeFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { runConfigAudit } from "../src/checks/config-audit.js";

const FIXTURES = join(import.meta.dir, "fixtures");
const BAD_HOME = join(FIXTURES, "bad-home");
const CLEAN_HOME = join(FIXTURES, "clean-home");

describe("config-audit npm rules", () => {
  let cwd: string;

  beforeEach(() => {
    cwd = mkdtempSync(join(tmpdir(), "pmharden-cwd-"));
  });

  afterEach(() => {
    rmSync(cwd, { recursive: true, force: true });
  });

  it("bad-home fires ignore-scripts-disabled, audit-disabled, npmrc-permissions by rule name with matching severities, and no unsafe-perm finding (obsolete rule)", () => {
    chmodSync(join(BAD_HOME, ".npmrc"), 0o644);
    const result = runConfigAudit({ home: BAD_HOME, cwd });
    const bySev = Object.fromEntries(result.findings.map((f) => [f.rule, f.severity]));

    expect(bySev["ignore-scripts-disabled"]).toBe("critical");
    expect(bySev["audit-disabled"]).toBe("high");
    expect(bySev["unsafe-perm"]).toBeUndefined();
    expect(bySev["npmrc-permissions"]).toBe("medium");
  });

  it("clean-home does not fire any of the four bad-home rules", () => {
    chmodSync(join(CLEAN_HOME, ".npmrc"), 0o600);
    const result = runConfigAudit({ home: CLEAN_HOME, cwd });
    const rules = new Set(result.findings.map((f) => f.rule));

    expect(rules.has("ignore-scripts-disabled")).toBe(false);
    expect(rules.has("audit-disabled")).toBe(false);
    expect(rules.has("unsafe-perm")).toBe(false);
    expect(rules.has("npmrc-permissions")).toBe(false);
  });
});

describe("config-audit allow-git", () => {
  let home: string;
  let cwd: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "pmharden-home-"));
    cwd = mkdtempSync(join(tmpdir(), "pmharden-cwd-"));
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
    rmSync(cwd, { recursive: true, force: true });
  });

  it("absent allow-git key fires allow-git-unset (medium) with an honest message, and no allow-git-all", () => {
    writeFileSync(join(home, ".npmrc"), "ignore-scripts=true\naudit=true\n");
    const result = runConfigAudit({ home, cwd });

    const unset = result.findings.find((f) => f.rule === "allow-git-unset");
    expect(unset).toBeDefined();
    expect(unset?.severity).toBe("medium");
    expect(unset?.message.toLowerCase()).not.toContain("set to all");
    expect(unset?.message.toLowerCase()).not.toContain("=all is set");
    expect(result.findings.some((f) => f.rule === "allow-git-all")).toBe(false);
  });

  it("allow-git=all fires allow-git-all (high) and not allow-git-unset", () => {
    writeFileSync(join(home, ".npmrc"), "ignore-scripts=true\naudit=true\nallow-git=all\n");
    const result = runConfigAudit({ home, cwd });

    const finding = result.findings.find((f) => f.rule === "allow-git-all");
    expect(finding?.severity).toBe("high");
    expect(result.findings.some((f) => f.rule === "allow-git-unset")).toBe(false);
  });

  it("allow-git=none produces neither allow-git-all nor allow-git-unset", () => {
    writeFileSync(join(home, ".npmrc"), "ignore-scripts=true\naudit=true\nallow-git=none\n");
    const result = runConfigAudit({ home, cwd });

    expect(result.findings.some((f) => f.rule === "allow-git-all")).toBe(false);
    expect(result.findings.some((f) => f.rule === "allow-git-unset")).toBe(false);
  });

  it("allow-git=root produces neither allow-git-all nor allow-git-unset", () => {
    writeFileSync(join(home, ".npmrc"), "ignore-scripts=true\naudit=true\nallow-git=root\n");
    const result = runConfigAudit({ home, cwd });

    expect(result.findings.some((f) => f.rule === "allow-git-all")).toBe(false);
    expect(result.findings.some((f) => f.rule === "allow-git-unset")).toBe(false);
  });
});

describe("config-audit no-npmrc fix text", () => {
  let home: string;
  let cwd: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "pmharden-home-"));
    cwd = mkdtempSync(join(tmpdir(), "pmharden-cwd-"));
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
    rmSync(cwd, { recursive: true, force: true });
  });

  it("no-npmrc finding recommends min-release-age=7, not minimum-release-age", () => {
    const result = runConfigAudit({ home, cwd });
    const finding = result.findings.find((f) => f.rule === "no-npmrc");

    expect(finding).toBeDefined();
    expect(finding?.fix).toContain("min-release-age=7");
    expect(finding?.fix).not.toContain("minimum-release-age");
    expect(finding?.agentPrompt).toContain("min-release-age=7");
    expect(finding?.agentPrompt).not.toContain("minimum-release-age");
  });
});

describe("config-audit pnpm rules", () => {
  let home: string;
  let cwd: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "pmharden-home-"));
    cwd = mkdtempSync(join(tmpdir(), "pmharden-cwd-"));
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
    rmSync(cwd, { recursive: true, force: true });
  });

  it("empty home+cwd fires no-pnpm-config, no-strict-dep-builds, no-minimum-release-age", () => {
    const result = runConfigAudit({ home, cwd });
    const rules = new Set(result.findings.map((f) => f.rule));

    expect(rules.has("no-pnpm-config")).toBe(true);
    expect(rules.has("no-strict-dep-builds")).toBe(true);
    expect(rules.has("no-minimum-release-age")).toBe(true);
  });

  it("pnpm-workspace.yaml in cwd with strictDepBuilds+minimumReleaseAge clears those findings and no-pnpm-config", () => {
    writeFileSync(join(cwd, "pnpm-workspace.yaml"), "strictDepBuilds: true\nminimumReleaseAge: 10080\n");
    const result = runConfigAudit({ home, cwd });
    const rules = new Set(result.findings.map((f) => f.rule));

    expect(rules.has("no-pnpm-config")).toBe(false);
    expect(rules.has("no-strict-dep-builds")).toBe(false);
    expect(rules.has("no-minimum-release-age")).toBe(false);
  });

  it("~/.config/pnpm/config.yaml with strictDepBuilds+minimumReleaseAge clears those findings and no-pnpm-config", () => {
    mkdirSync(join(home, ".config", "pnpm"), { recursive: true });
    writeFileSync(
      join(home, ".config", "pnpm", "config.yaml"),
      "strictDepBuilds: true\nminimumReleaseAge: 10080\n"
    );
    const result = runConfigAudit({ home, cwd });
    const rules = new Set(result.findings.map((f) => f.rule));

    expect(rules.has("no-pnpm-config")).toBe(false);
    expect(rules.has("no-strict-dep-builds")).toBe(false);
    expect(rules.has("no-minimum-release-age")).toBe(false);
  });

  it("blockExoticSubdeps: false in pnpm-workspace.yaml fires block-exotic-subdeps-disabled", () => {
    writeFileSync(
      join(cwd, "pnpm-workspace.yaml"),
      "strictDepBuilds: true\nminimumReleaseAge: 10080\nblockExoticSubdeps: false\n"
    );
    const result = runConfigAudit({ home, cwd });

    expect(result.findings.some((f) => f.rule === "block-exotic-subdeps-disabled")).toBe(true);
  });

  it("never emits the deleted no-block-exotic-subdeps or no-only-built-dependencies rules", () => {
    const result = runConfigAudit({ home, cwd });
    const rules = new Set(result.findings.map((f) => f.rule));

    expect(rules.has("no-block-exotic-subdeps")).toBe(false);
    expect(rules.has("no-only-built-dependencies")).toBe(false);
  });
});

describe("config-audit yarn rules", () => {
  let home: string;
  let cwd: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "pmharden-home-"));
    cwd = mkdtempSync(join(tmpdir(), "pmharden-cwd-"));
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
    rmSync(cwd, { recursive: true, force: true });
  });

  it(".yarnrc.yml lacking both keys fires enable-scripts-missing (low) and no-npm-minimal-age-gate", () => {
    writeFileSync(join(home, ".yarnrc.yml"), "# empty\n");
    const result = runConfigAudit({ home, cwd });
    const bySev = Object.fromEntries(result.findings.map((f) => [f.rule, f.severity]));

    expect(bySev["enable-scripts-missing"]).toBe("low");
    expect(result.findings.some((f) => f.rule === "no-npm-minimal-age-gate")).toBe(true);
  });

  it("enableScripts: false + npmMinimalAgeGate: 10080 fires neither enable-scripts-missing nor no-npm-minimal-age-gate", () => {
    writeFileSync(join(home, ".yarnrc.yml"), "enableScripts: false\nnpmMinimalAgeGate: 10080\n");
    const result = runConfigAudit({ home, cwd });
    const rules = new Set(result.findings.map((f) => f.rule));

    expect(rules.has("enable-scripts-missing")).toBe(false);
    expect(rules.has("no-npm-minimal-age-gate")).toBe(false);
  });
});
