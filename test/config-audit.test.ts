import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { mkdtempSync, chmodSync, writeFileSync, rmSync } from "fs";
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

  it("bad-home fires ignore-scripts-disabled, audit-disabled, unsafe-perm, npmrc-permissions by rule name with matching severities", () => {
    chmodSync(join(BAD_HOME, ".npmrc"), 0o644);
    const result = runConfigAudit({ home: BAD_HOME, cwd });
    const bySev = Object.fromEntries(result.findings.map((f) => [f.rule, f.severity]));

    expect(bySev["ignore-scripts-disabled"]).toBe("critical");
    expect(bySev["audit-disabled"]).toBe("high");
    expect(bySev["unsafe-perm"]).toBe("high");
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

  it("absent allow-git key produces no allow-git-all finding", () => {
    writeFileSync(join(home, ".npmrc"), "ignore-scripts=true\naudit=true\n");
    const result = runConfigAudit({ home, cwd });

    expect(result.findings.some((f) => f.rule === "allow-git-all")).toBe(false);
  });

  it("allow-git=all fires allow-git-all", () => {
    writeFileSync(join(home, ".npmrc"), "ignore-scripts=true\naudit=true\nallow-git=all\n");
    const result = runConfigAudit({ home, cwd });

    expect(result.findings.some((f) => f.rule === "allow-git-all")).toBe(true);
  });

  it("allow-git=none produces no allow-git-all finding", () => {
    writeFileSync(join(home, ".npmrc"), "ignore-scripts=true\naudit=true\nallow-git=none\n");
    const result = runConfigAudit({ home, cwd });

    expect(result.findings.some((f) => f.rule === "allow-git-all")).toBe(false);
  });
});
