import { describe, it, expect } from "bun:test";
import { existsSync } from "fs";
import { runGlobalAudit } from "../src/checks/global-audit.js";

interface ExecCall {
  cmd: string;
  args: string[];
}

interface ExecConfig {
  npmList?: string | null;
  pnpmList?: string | null;
  yarnList?: string | null;
  /** keyed by package name -> value returned by `npm view <name> version` */
  latestVersions?: Record<string, string | null>;
  /** keyed by `${name}@${version}` -> value returned by `npm view <name>@<version> scripts --json` */
  scripts?: Record<string, string | null>;
}

function makeFakeExec(config: ExecConfig) {
  const calls: ExecCall[] = [];
  const exec = (cmd: string, args: string[]): string | null => {
    calls.push({ cmd, args });
    if (cmd === "npm" && args[0] === "list") return config.npmList ?? null;
    if (cmd === "pnpm" && args[0] === "list") return config.pnpmList ?? null;
    if (cmd === "yarn" && args[0] === "global") return config.yarnList ?? null;
    if (cmd === "npm" && args[0] === "view" && args[2] === "version") {
      const name = args[1] ?? "";
      return config.latestVersions?.[name] ?? null;
    }
    if (cmd === "npm" && args[0] === "view" && args[2] === "scripts") {
      const nameVersion = args[1] ?? "";
      return config.scripts?.[nameVersion] ?? null;
    }
    return null;
  };
  return { exec, calls };
}

describe("global-audit known-risky-global", () => {
  it("flags create-react-app by name", async () => {
    const { exec } = makeFakeExec({
      npmList: JSON.stringify({ dependencies: { "create-react-app": { version: "5.0.1" } } }),
      latestVersions: { "create-react-app": "5.0.1" },
      scripts: {},
    });

    const result = await runGlobalAudit({ exec });

    const finding = result.findings.find((f) => f.rule === "known-risky-global");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("high");
    expect(finding?.message).toContain("create-react-app");
  });
});

describe("global-audit outdated version thresholds", () => {
  it("2+ majors behind fires severely-outdated-global (high)", async () => {
    const { exec } = makeFakeExec({
      npmList: JSON.stringify({ dependencies: { "severely-behind": { version: "1.0.0" } } }),
      latestVersions: { "severely-behind": "3.2.0" },
      scripts: {},
    });

    const result = await runGlobalAudit({ exec });

    const finding = result.findings.find((f) => f.rule === "severely-outdated-global");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("high");
    expect(result.findings.some((f) => f.rule === "outdated-global")).toBe(false);
  });

  it("exactly 1 major behind fires outdated-global (medium)", async () => {
    const { exec } = makeFakeExec({
      npmList: JSON.stringify({ dependencies: { "one-behind": { version: "1.0.0" } } }),
      latestVersions: { "one-behind": "2.0.0" },
      scripts: {},
    });

    const result = await runGlobalAudit({ exec });

    const finding = result.findings.find((f) => f.rule === "outdated-global");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("medium");
    expect(result.findings.some((f) => f.rule === "severely-outdated-global")).toBe(false);
  });

  it("equal versions fire neither outdated rule", async () => {
    const { exec } = makeFakeExec({
      npmList: JSON.stringify({ dependencies: { "up-to-date": { version: "1.0.0" } } }),
      latestVersions: { "up-to-date": "1.0.0" },
      scripts: {},
    });

    const result = await runGlobalAudit({ exec });

    expect(result.findings.some((f) => f.rule === "outdated-global")).toBe(false);
    expect(result.findings.some((f) => f.rule === "severely-outdated-global")).toBe(false);
  });
});

describe("global-audit install scripts", () => {
  it("flags packages with postinstall scripts", async () => {
    const { exec } = makeFakeExec({
      npmList: JSON.stringify({ dependencies: { "has-scripts": { version: "1.0.0" } } }),
      latestVersions: { "has-scripts": "1.0.0" },
      scripts: { "has-scripts@1.0.0": JSON.stringify({ postinstall: "node x.js" }) },
    });

    const result = await runGlobalAudit({ exec });

    const finding = result.findings.find((f) => f.rule === "global-with-install-scripts");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("low");
  });
});

describe("global-audit no globals", () => {
  it("all three commands succeed but report zero deps -> skipped 'No global packages found'", async () => {
    const { exec } = makeFakeExec({
      npmList: JSON.stringify({ dependencies: {} }),
      pnpmList: JSON.stringify([{ dependencies: {} }]),
      yarnList: JSON.stringify({ type: "info", data: { items: [] } }),
    });

    const result = await runGlobalAudit({ exec });

    expect(result.skipped).toBe("No global packages found");
    expect(result.findings).toEqual([]);
  });
});

describe("global-audit all commands failed", () => {
  it("all list commands return null -> skipped says commands failed, NOT 'No global packages found'", async () => {
    const { exec } = makeFakeExec({});

    const result = await runGlobalAudit({ exec });

    expect(result.skipped).toBeDefined();
    expect(result.skipped).not.toBe("No global packages found");
    expect(result.skipped?.toLowerCase()).toContain("failed");
    expect(result.findings).toEqual([]);
  });
});

describe("global-audit partial command failure", () => {
  it("npm succeeds with a package while pnpm/yarn fail -> findings still processed, skipped names pnpm+yarn failure", async () => {
    const { exec } = makeFakeExec({
      npmList: JSON.stringify({ dependencies: { "some-pkg": { version: "1.0.0" } } }),
      pnpmList: null,
      yarnList: null,
      latestVersions: { "some-pkg": "1.0.0" },
      scripts: { "some-pkg@1.0.0": JSON.stringify({ postinstall: "node x.js" }) },
    });

    const result = await runGlobalAudit({ exec });

    const finding = result.findings.find((f) => f.rule === "global-with-install-scripts");
    expect(finding).toBeDefined();
    expect(result.skipped).toBeDefined();
    expect(result.skipped).toContain("pnpm");
    expect(result.skipped).toContain("yarn");
  });
});

describe("global-audit hostile package name (argv isolation canary)", () => {
  it("passes a shell-metacharacter package name as a single argv element, never shell-interpreted", async () => {
    const hostileName = '; touch /tmp/pwned; $(id) "x"';
    const { exec, calls } = makeFakeExec({
      npmList: JSON.stringify({ dependencies: { [hostileName]: { version: "1.0.0" } } }),
      latestVersions: { [hostileName]: null },
      scripts: {},
    });

    const result = await runGlobalAudit({ exec });

    // The finding should exist and carry the raw name — no crash, no shell interpretation.
    expect(result.findings).toBeDefined();

    const callsReferencingPackage = calls.filter((c) =>
      c.args.some((a) => a.includes(hostileName))
    );

    // Expect the two npm view calls (version + scripts) to reference the package.
    expect(callsReferencingPackage.length).toBe(2);

    for (const call of callsReferencingPackage) {
      // (a) cmd must be npm, never a shell.
      expect(call.cmd).toBe("npm");

      const matchingArgs = call.args.filter((a) => a.includes(hostileName));
      // Exactly one argv element should reference the package name.
      expect(matchingArgs.length).toBe(1);

      const arg = matchingArgs[0]!;
      // (b) that element must be EXACTLY the hostile name or `${name}@${version}` —
      // never the hostile name glued to other tokens/flags in a single string
      // (which would indicate shell-string construction rather than argv array usage).
      expect(arg === hostileName || arg === `${hostileName}@1.0.0`).toBe(true);
    }

    // Belt-and-braces: the injected exec never actually spawns anything, but confirm
    // no real side effect occurred.
    expect(existsSync("/tmp/pwned")).toBe(false);
  });
});

describe("global-audit dedupe", () => {
  it("processes a package seen in both npm and pnpm lists only once", async () => {
    const { exec, calls } = makeFakeExec({
      npmList: JSON.stringify({ dependencies: { "dup-pkg": { version: "1.0.0" } } }),
      pnpmList: JSON.stringify([{ dependencies: { "dup-pkg": { version: "2.0.0" } } }]),
      latestVersions: { "dup-pkg": "1.0.0" },
      scripts: {},
    });

    await runGlobalAudit({ exec });

    const viewVersionCalls = calls.filter(
      (c) => c.cmd === "npm" && c.args[0] === "view" && c.args[2] === "version" && c.args[1] === "dup-pkg"
    );
    const viewScriptsCalls = calls.filter(
      (c) => c.cmd === "npm" && c.args[0] === "view" && c.args[2] === "scripts" && c.args[1]?.startsWith("dup-pkg@")
    );

    expect(viewVersionCalls.length).toBe(1);
    expect(viewScriptsCalls.length).toBe(1);
  });
});

describe("global-audit concurrency", () => {
  it("runs npm view calls concurrently (bounded at 4) and keeps findings in package order", async () => {
    const names = Array.from({ length: 10 }, (_, i) => `pkg-${i}`);
    const deps = Object.fromEntries(names.map((n) => [n, { version: "1.0.0" }]));
    let inFlight = 0;
    let maxInFlight = 0;
    const exec = async (cmd: string, args: string[]): Promise<string | null> => {
      if (cmd === "npm" && args[0] === "list") return JSON.stringify({ dependencies: deps });
      if (cmd !== "npm" || args[0] !== "view") return null;
      inFlight++;
      maxInFlight = Math.max(maxInFlight, inFlight);
      // earlier packages answer slower, so completion order is the reverse of package order
      const index = Number((args[1] ?? "").replace(/\D+/g, "").slice(0, 1));
      await new Promise((r) => setTimeout(r, (10 - index) * 3));
      inFlight--;
      return args[2] === "version" ? "2.0.0" : null;
    };

    const result = await runGlobalAudit({ exec });

    expect(maxInFlight).toBeGreaterThan(1);
    expect(maxInFlight).toBeLessThanOrEqual(4);
    expect(result.findings.map((f) => f.message.split("@")[0])).toEqual(names);
  });
});
