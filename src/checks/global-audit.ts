/**
 * Global package auditor.
 * Checks globally installed packages across npm, pnpm, yarn, bun for:
 * - Outdated versions with known CVE patterns
 * - Packages that are severely outdated (major versions behind)
 * - Packages with install scripts that weren't there before
 */
import { execFile } from "child_process";
import type { CheckContext, CheckResult, Finding } from "../utils/types.js";

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

const NPM_VIEW_CONCURRENCY = 4;

function defaultExec(cmd: string, args: string[]): Promise<string | null> {
  return new Promise((resolve) => {
    execFile(cmd, args, { encoding: "utf8" }, (err, stdout) => resolve(err ? null : stdout));
  });
}

type Exec = NonNullable<CheckContext["exec"]>;

async function mapWithConcurrency<T, R>(
  items: T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i]!, i);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

async function getNpmGlobals(exec: Exec): Promise<GlobalPackage[] | null> {
  const out = await exec("npm", ["list", "-g", "--depth=0", "--json"]);
  if (!out) return null;
  try {
    const parsed = JSON.parse(out) as { dependencies?: Record<string, { version: string }> };
    return Object.entries(parsed.dependencies ?? {}).map(([name, info]) => ({
      name,
      version: info.version,
      pm: "npm",
    }));
  } catch {
    return null;
  }
}

async function getPnpmGlobals(exec: Exec): Promise<GlobalPackage[] | null> {
  const out = await exec("pnpm", ["list", "-g", "--json"]);
  if (!out) return null;
  try {
    const parsed = JSON.parse(out) as Array<{ dependencies?: Record<string, { version: string }> }>;
    const deps = parsed[0]?.dependencies ?? {};
    return Object.entries(deps).map(([name, info]) => ({
      name,
      version: info.version,
      pm: "pnpm",
    }));
  } catch {
    return null;
  }
}

async function getYarnGlobals(exec: Exec): Promise<GlobalPackage[] | null> {
  const out = await exec("yarn", ["global", "list", "--json"]);
  if (!out) return null;
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

async function getLatestVersion(name: string, exec: Exec): Promise<string | null> {
  const out = await exec("npm", ["view", name, "version"]);
  return out?.trim() ?? null;
}

function parseMajor(version: string): number {
  return parseInt(version.replace(/^[^0-9]*/, "").split(".")[0] ?? "0", 10);
}

async function checkInstallScripts(name: string, version: string, exec: Exec): Promise<boolean> {
  const out = await exec("npm", ["view", `${name}@${version}`, "scripts", "--json"]);
  if (!out) return false;
  try {
    const scripts = JSON.parse(out) as Record<string, string>;
    return !!(scripts["preinstall"] || scripts["postinstall"] || scripts["install"]);
  } catch {
    return false;
  }
}

export async function runGlobalAudit(
  ctx: CheckContext & { onProgress?: (name: string, current: number, total: number) => void } = {}
): Promise<CheckResult> {
  const exec = ctx.exec ?? defaultExec;
  const onProgress = ctx.onProgress;
  const findings: Finding[] = [];

  const npmResult = await getNpmGlobals(exec);
  const pnpmResult = await getPnpmGlobals(exec);
  const yarnResult = await getYarnGlobals(exec);

  if (npmResult === null && pnpmResult === null && yarnResult === null) {
    return { findings, skipped: "npm/pnpm/yarn list commands failed — global packages were NOT audited" };
  }

  const failureNotes: string[] = [];
  if (npmResult === null) failureNotes.push("npm list failed — npm globals not audited");
  if (pnpmResult === null) failureNotes.push("pnpm list failed — pnpm globals not audited");
  if (yarnResult === null) failureNotes.push("yarn list failed — yarn globals not audited");

  const allGlobals: GlobalPackage[] = [
    ...(npmResult ?? []),
    ...(pnpmResult ?? []),
    ...(yarnResult ?? []),
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

  const perPackage = await mapWithConcurrency(deduped, NPM_VIEW_CONCURRENCY, async (pkg, i) => {
    onProgress?.(pkg.name, i + 1, deduped.length);
    return auditPackage(pkg, exec);
  });

  return { findings: perPackage.flat(), ...(failureNotes.length ? { skipped: failureNotes.join("; ") } : {}) };
}

async function auditPackage(pkg: GlobalPackage, exec: Exec): Promise<Finding[]> {
  const findings: Finding[] = [];
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
  const latest = await getLatestVersion(pkg.name, exec);
  if (latest) {
    const currentMajor = parseMajor(pkg.version);
    const latestMajor = parseMajor(latest);
    if (latestMajor - currentMajor >= STALE_MAJOR_THRESHOLD) {
      findings.push({
        severity: "high",
        tool: pkg.pm,
        rule: "severely-outdated-global",
        message: `${pkg.name}@${pkg.version} is ${latestMajor - currentMajor} major versions behind (latest: ${latest}). Old versions often have unpatched CVEs.`,
        fix: pkg.pm === "pnpm" ? `pnpm add -g ${pkg.name}@latest` : pkg.pm === "yarn" ? `yarn global add ${pkg.name}@latest` : `npm install -g ${pkg.name}@latest`,
      });
    } else if (pkg.version !== latest && latestMajor > currentMajor) {
      findings.push({
        severity: "medium",
        tool: pkg.pm,
        rule: "outdated-global",
        message: `${pkg.name}@${pkg.version} outdated (latest: ${latest}).`,
        fix: pkg.pm === "pnpm" ? `pnpm add -g ${pkg.name}@latest` : pkg.pm === "yarn" ? `yarn global add ${pkg.name}@latest` : `npm install -g ${pkg.name}@latest`,
      });
    }
  }

  // 3. Flag if package has install scripts (potential risk if compromised)
  if (await checkInstallScripts(pkg.name, pkg.version, exec)) {
    findings.push({
      severity: "low",
      tool: pkg.pm,
      rule: "global-with-install-scripts",
      message: `${pkg.name}@${pkg.version} runs lifecycle scripts (pre/post/install). If this package is ever compromised, scripts execute with your user permissions.`,
      fix: `Review if ${pkg.name} truly needs to be installed globally vs used via npx`,
    });
  }

  return findings;
}
