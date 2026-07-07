import { describe, it, expect, afterEach } from "bun:test";
import { mkdtempSync, writeFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { runPublishCheck } from "../src/checks/publish-check.js";

let dirs: string[] = [];

function makeCwd(): string {
  const dir = mkdtempSync(join(tmpdir(), "pmharden-publish-"));
  dirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of dirs) {
    rmSync(dir, { recursive: true, force: true });
  }
  dirs = [];
});

describe("publish-check private packages", () => {
  it("private:true with no files field produces zero findings", () => {
    const cwd = makeCwd();
    writeFileSync(join(cwd, "package.json"), JSON.stringify({ private: true }));

    const result = runPublishCheck({ cwd });

    expect(result.findings).toEqual([]);
  });
});

describe("publish-check missing allowlist", () => {
  it("no files field and no .npmignore fires no-publish-allowlist (high)", () => {
    const cwd = makeCwd();
    writeFileSync(join(cwd, "package.json"), JSON.stringify({}));

    const result = runPublishCheck({ cwd });

    const finding = result.findings.find((f) => f.rule === "no-publish-allowlist");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("high");
  });
});

describe("publish-check overly broad files glob", () => {
  for (const glob of ["*", ".", "**"]) {
    it(`files: ["${glob}"] fires files-glob-too-broad (medium)`, () => {
      const cwd = makeCwd();
      writeFileSync(join(cwd, "package.json"), JSON.stringify({ files: [glob] }));

      const result = runPublishCheck({ cwd });

      const finding = result.findings.find((f) => f.rule === "files-glob-too-broad");
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("medium");
    });
  }
});

describe("publish-check .npmignore denylist", () => {
  it("no files field + .npmignore present fires npmignore-over-files-allowlist (low) and not no-publish-allowlist", () => {
    const cwd = makeCwd();
    writeFileSync(join(cwd, "package.json"), JSON.stringify({}));
    writeFileSync(join(cwd, ".npmignore"), "test/\n");

    const result = runPublishCheck({ cwd });

    const finding = result.findings.find((f) => f.rule === "npmignore-over-files-allowlist");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("low");
    expect(result.findings.some((f) => f.rule === "no-publish-allowlist")).toBe(false);
  });
});

describe("publish-check safe allowlist", () => {
  it("files: [dist, README.md] with no .npmignore produces zero findings", () => {
    const cwd = makeCwd();
    writeFileSync(join(cwd, "package.json"), JSON.stringify({ files: ["dist", "README.md"] }));

    const result = runPublishCheck({ cwd });

    expect(result.findings).toEqual([]);
  });
});

describe("publish-check no package.json", () => {
  it("cwd with no package.json at all produces zero findings", () => {
    const cwd = makeCwd();

    const result = runPublishCheck({ cwd });

    expect(result.findings).toEqual([]);
  });
});

describe("publish-check malformed package.json", () => {
  it("invalid JSON fires skipped naming the path and a parse failure, with zero findings", () => {
    const cwd = makeCwd();
    const pkgPath = join(cwd, "package.json");
    writeFileSync(pkgPath, "{ this is not valid json");

    const result = runPublishCheck({ cwd });

    expect(result.findings).toEqual([]);
    expect(result.skipped).toBeDefined();
    expect(result.skipped).toContain(pkgPath);
    expect(result.skipped?.toLowerCase()).toContain("pars");
  });
});
