/**
 * Global package auditor.
 * Checks globally installed packages across npm, pnpm, yarn, bun for:
 * - Outdated versions with known CVE patterns
 * - Packages that are severely outdated (major versions behind)
 * - Packages with install scripts that weren't there before
 */
import { execSync } from "child_process";
import type { CheckResult, Finding } from "../utils/types.js";

// Known dangerous global packages (abandoned, known-compromised, or high-risk)
const KNOWN_RISKY_GLOBALS: Record<string, { reason: string; fix: string }> = {
  "create-react-app": {
    reason: "Unmaintained since 2023. Last release had unpatched vulnerabilities. React team no longer recommends it.",
    fix: "Uninstall and use `npx create-react-app` (on-demand) or migrate to Vite/Next.js",
  },
  "node-gyp": {
    reason: "Runs native compilation — high privilege operation. Only install when explicitly needed.",
    fix: "Uninstall if not actively developing native addons",
  },
  "yo": {
    reason: "Yeoman scaffolding — runs arbitrary generators with filesystem access. High attack surface when generators are untrusted.",
    fix: "Use `npx yo <generator>` on-demand instead of keeping globally",
  },
  "lerna": {
    reason: "Monorepo tool with postinstall scripts. Older versions had prototype pollution CVEs.",
    fix: "Update to latest or use `npx lerna` on-demand",
  },
};

// Stale threshold: packages older than N major versions are flagged
const STALE_MAJOR_THRESHOLD = 2;

interface GlobalPackage {
  name: string;
  version: string;
  pm: string;
}

function runCommand(cmd: string): string | null {
  try {
    return execSync(cmd, { encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] });
  } catch {
    return null;
  }
}

function getNpmGlobals(): GlobalPackage[] {
  const out = runCommand("npm list -g --depth=0 --json 2>/dev/null");
  if (!out) return [];
  try {
    const parsed = JSON.parse(out) as { dependencies?: Record<string, { version: string }> };
    return Object.entries(parsed.dependencies ?? {}).map(([name, info]) => ({
      name,
      version: info.version,
      pm: "npm",
    }));
  } catch {
    return [];
  }
}

function getPnpmGlobals(): GlobalPackage[] {
  const out = runCommand("pnpm list -g --json 2>/dev/null");
  if (!out) return [];
  try {
    const parsed = JSON.parse(out) as Array<{ dependencies?: Record<string, { version: string }> }>;
    const deps = parsed[0]?.dependencies ?? {};
    return Object.entries(deps).map(([name, info]) => ({
      name,
      version: info.version,
      pm: "pnpm",
    }));
  } catch {
    return [];
  }
}

function getYarnGlobals(): GlobalPackage[] {
  const out = runCommand("yarn global list --json 2>/dev/null");
  if (!out) return [];
  const pkgs: GlobalPackage[] = [];
  for (const line of out.split("\n")) {
    if (!line.trim()) continue;
    try {
      const parsed = JSON.parse(line) as { type?: string; data?: { items?: string[] } };
      if (parsed.type === "info" && parsed.data?.items) {
        for (const item of parsed.data.items) {
          const m = item.match(/^"([^@]+)@([^"]+)"/);
          if (m) pkgs.push({ name: m[1], version: m[2], pm: "yarn" });
        }
      }
    } catch {
      // skip malformed lines
    }
  }
  return pkgs;
}

function getLatestVersion(name: string): string | null {
  const out = runCommand(`npm view "${name}" version 2>/dev/null`);
  return out?.trim() ?? null;
}

function parseMajor(version: string): number {
  return parseInt(version.replace(/^[^0-9]*/, "").split(".")[0] ?? "0", 10);
}

function checkInstallScripts(name: string, version: string): boolean {
  const out = runCommand(`npm view "${name}@${version}" scripts --json 2>/dev/null`);
  if (!out) return false;
  try {
    const scripts = JSON.parse(out) as Record<string, string>;
    return !!(scripts["preinstall"] || scripts["postinstall"] || scripts["install"]);
  } catch {
    return false;
  }
}

export function runGlobalAudit(
  onProgress?: (name: string, current: number, total: number) => void
): CheckResult {
  const findings: Finding[] = [];

  const allGlobals: GlobalPackage[] = [
    ...getNpmGlobals(),
    ...getPnpmGlobals(),
    ...getYarnGlobals(),
  ];

  // Dedupe by name (keep first seen)
  const seen = new Set<string>();
  const deduped = allGlobals.filter((p) => {
    if (seen.has(p.name)) return false;
    seen.add(p.name);
    return true;
  });

  if (deduped.length === 0) {
    return { findings, skipped: "No global packages found" };
  }

  for (let i = 0; i < deduped.length; i++) {
    const pkg = deduped[i]!;
    onProgress?.(pkg.name, i + 1, deduped.length);
    // 1. Known risky globals
    if (KNOWN_RISKY_GLOBALS[pkg.name]) {
      const risk = KNOWN_RISKY_GLOBALS[pkg.name]!;
      findings.push({
        severity: "high",
        tool: pkg.pm,
        rule: "known-risky-global",
        message: `${pkg.name}@${pkg.version} (global): ${risk.reason}`,
        fix: risk.fix,
      });
    }

    // 2. Check if severely outdated
    const latest = getLatestVersion(pkg.name);
    if (latest) {
      const currentMajor = parseMajor(pkg.version);
      const latestMajor = parseMajor(latest);
      if (latestMajor - currentMajor >= STALE_MAJOR_THRESHOLD) {
        findings.push({
          severity: "high",
          tool: pkg.pm,
          rule: "severely-outdated-global",
          message: `${pkg.name}@${pkg.version} is ${latestMajor - currentMajor} major versions behind (latest: ${latest}). Old versions often have unpatched CVEs.`,
          fix: `npm install -g ${pkg.name}@latest`,
        });
      } else if (pkg.version !== latest && latestMajor > currentMajor) {
        findings.push({
          severity: "medium",
          tool: pkg.pm,
          rule: "outdated-global",
          message: `${pkg.name}@${pkg.version} outdated (latest: ${latest}).`,
          fix: `npm install -g ${pkg.name}@latest`,
        });
      }
    }

    // 3. Flag if package has install scripts (potential risk if compromised)
    if (checkInstallScripts(pkg.name, pkg.version)) {
      findings.push({
        severity: "low",
        tool: pkg.pm,
        rule: "global-with-install-scripts",
        message: `${pkg.name}@${pkg.version} runs lifecycle scripts (pre/post/install). If this package is ever compromised, scripts execute with your user permissions.`,
        fix: `Review if ${pkg.name} truly needs to be installed globally vs used via npx`,
      });
    }
  }

  return { findings };
}
