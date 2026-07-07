import { describe, it, expect } from "bun:test";
import { readFileSync } from "fs";
import { join } from "path";

describe("cli --version", () => {
  it("matches the version in package.json", () => {
    const pkg = JSON.parse(readFileSync(join(import.meta.dir, "..", "package.json"), "utf8"));
    const proc = Bun.spawnSync(["bun", "src/cli.ts", "--version"], {
      cwd: join(import.meta.dir, ".."),
    });
    const stdout = new TextDecoder().decode(proc.stdout).trim();

    expect(stdout).toBe(pkg.version);
  });
});
