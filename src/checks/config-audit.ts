/**
 * Package manager config linter.
 * Checks: .npmrc, .pnpmrc / pnpm-workspace.yaml, .yarnrc.yml, bunfig.toml
 */
import { join } from "path";
import { HOME, readFile, fileExists, fileMode } from "../utils/fs.js";
import type { CheckResult, Finding } from "../utils/types.js";

// ─── npm ───────────────────────────────────────────────────────────────────

function parseNpmrc(content: string): Record<string, string> {
  const cfg: Record<string, string> = {};
  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith(";") || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim().toLowerCase();
    const val = trimmed.slice(eq + 1).trim();
    cfg[key] = val;
  }
  return cfg;
}

function auditNpmrc(path: string, findings: Finding[]): void {
  const content = readFile(path);
  if (!content) return;

  const cfg = parseNpmrc(content);
  const tool = "npm";
  const file = path;

  // 1. Scripts not blocked
  if (cfg["ignore-scripts"] !== "true") {
    findings.push({
      severity: "critical",
      tool,
      file,
      rule: "ignore-scripts-disabled",
      message: `ignore-scripts is not set to true. Postinstall/preinstall scripts can execute arbitrary code on npm install.`,
      fix: `npm config set ignore-scripts true   (or add ignore-scripts=true to ${path})`,
    });
  }

  // 2. audit disabled
  if (cfg["audit"] === "false") {
    findings.push({
      severity: "high",
      tool,
      file,
      rule: "audit-disabled",
      message: `audit=false disables vulnerability scanning on every install.`,
      fix: `Remove audit=false from ${path}`,
    });
  }

  // 3. allow-git too permissive
  const allowGit = cfg["allow-git"];
  if (!allowGit || allowGit === "all") {
    findings.push({
      severity: "high",
      tool,
      file,
      rule: "allow-git-all",
      message: `allow-git=all permits installing packages directly from git (including unreviewed commits). Supply-chain risk.`,
      fix: `npm config set allow-git=none  (or restrict to specific organizations)`,
    });
  }

  // 4. No minimum-release-age (freshly published packages are high risk)
  if (!cfg["minimum-release-age"] && !cfg["min-release-age"]) {
    findings.push({
      severity: "medium",
      tool,
      file,
      rule: "no-minimum-release-age",
      message: `No minimum-release-age set. Packages published in the last 7 days are a common zero-day supply-chain vector.`,
      fix: `Add minimum-release-age=7 days to ${path}`,
    });
  }

  // 5. unsafe-perm
  if (cfg["unsafe-perm"] === "true") {
    findings.push({
      severity: "high",
      tool,
      file,
      rule: "unsafe-perm",
      message: `unsafe-perm=true runs install scripts with elevated privileges. Removes sandboxing.`,
      fix: `Remove unsafe-perm=true from ${path}`,
    });
  }

  // 6. registry pointing away from npmjs.org
  if (cfg["registry"] && !cfg["registry"].includes("registry.npmjs.org")) {
    findings.push({
      severity: "medium",
      tool,
      file,
      rule: "custom-registry",
      message: `Custom registry: ${cfg["registry"]}. Ensure this is intentional and trusted.`,
    });
  }

  // 7. File permissions too open
  const mode = fileMode(path);
  if (mode !== null && (mode & 0o044) !== 0) {
    findings.push({
      severity: "medium",
      tool,
      file,
      rule: "npmrc-permissions",
      message: `${path} is group/world readable (mode ${mode.toString(8)}). May expose auth tokens.`,
      fix: `chmod 600 ${path}`,
    });
  }
}

// ─── pnpm ──────────────────────────────────────────────────────────────────

function auditPnpmrc(findings: Finding[]): void {
  const paths = [
    join(HOME, ".pnpmrc"),
    join(HOME, ".npmrc"), // pnpm also reads .npmrc
    "pnpm-workspace.yaml",
    ".pnpmfile.cjs",
  ];

  const found = paths.filter(fileExists);
  if (found.length === 0) {
    // Check if pnpm is installed but unconfigured
    findings.push({
      severity: "info",
      tool: "pnpm",
      rule: "no-pnpmrc",
      message: `No pnpm config found. Consider setting strictDepBuilds=true and minimumReleaseAge.`,
      fix: `Create ~/.pnpmrc with:\nstrict-dep-builds=true\nminimum-release-age=7`,
    });
    return;
  }

  for (const path of found) {
    const content = readFile(path);
    if (!content) continue;

    // strictDepBuilds / strict-dep-builds
    if (!content.includes("strict-dep-builds") && !content.includes("strictDepBuilds")) {
      findings.push({
        severity: "high",
        tool: "pnpm",
        file: path,
        rule: "no-strict-dep-builds",
        message: `strict-dep-builds not set. pnpm will silently run dependency build scripts without review.`,
        fix: `Add to ${path}:\nstrict-dep-builds=true`,
      });
    }

    // minimumReleaseAge
    if (!content.includes("minimum-release-age") && !content.includes("minimumReleaseAge")) {
      findings.push({
        severity: "medium",
        tool: "pnpm",
        file: path,
        rule: "no-minimum-release-age",
        message: `minimumReleaseAge not set. Fresh packages (<7 days) are a top supply-chain risk.`,
        fix: `Add to ${path}:\nminimum-release-age=7`,
      });
    }

    // blockExoticSubdeps
    if (!content.includes("block-exotic-subdeps") && !content.includes("blockExoticSubdeps")) {
      findings.push({
        severity: "medium",
        tool: "pnpm",
        file: path,
        rule: "no-block-exotic-subdeps",
        message: `block-exotic-subdeps not set. Git and tarball transitive deps can bypass registry vetting.`,
        fix: `Add to ${path}:\nblock-exotic-subdeps=true`,
      });
    }
  }
}

// ─── yarn ──────────────────────────────────────────────────────────────────

function auditYarnrc(findings: Finding[]): void {
  const v2path = join(HOME, ".yarnrc.yml");
  const v1path = join(HOME, ".yarnrc");

  if (fileExists(v2path)) {
    const content = readFile(v2path)!;
    if (!content.includes("enableScripts: false")) {
      findings.push({
        severity: "critical",
        tool: "yarn",
        file: v2path,
        rule: "enable-scripts-missing",
        message: `enableScripts: false not set in .yarnrc.yml. Yarn Berry runs lifecycle scripts by default.`,
        fix: `Add to ${v2path}:\nenableScripts: false`,
      });
    }
    if (!content.includes("minimumReleaseAge")) {
      findings.push({
        severity: "medium",
        tool: "yarn",
        file: v2path,
        rule: "no-minimum-release-age",
        message: `minimumReleaseAge not set in .yarnrc.yml.`,
        fix: `Add to ${v2path}:\nminimumReleaseAge: "7 days"`,
      });
    }
  } else if (fileExists(v1path)) {
    // yarn v1 classic — enableScripts not supported but worth flagging
    findings.push({
      severity: "high",
      tool: "yarn",
      file: v1path,
      rule: "yarn-v1-no-script-control",
      message: `yarn v1 classic has no built-in script blocking. Consider upgrading to yarn berry or using npm config set ignore-scripts=true.`,
      fix: `yarn set version berry  OR  migrate to pnpm/bun`,
    });
  }
}

// ─── bun ───────────────────────────────────────────────────────────────────

function auditBunfig(findings: Finding[]): void {
  const path = join(HOME, ".bunfig.toml");
  if (!fileExists(path)) {
    // Bun blocks scripts by default — just note it's good but config could be explicit
    findings.push({
      severity: "info",
      tool: "bun",
      rule: "no-bunfig",
      message: `No ~/.bunfig.toml found. Bun blocks scripts by default (good), but consider adding an explicit registry setting.`,
      fix: `Create ~/.bunfig.toml:\n[install]\nregistry = "https://registry.npmjs.org/"`,
    });
    return;
  }

  const content = readFile(path)!;
  if (!content.includes("registry")) {
    findings.push({
      severity: "low",
      tool: "bun",
      file: path,
      rule: "no-registry-pinned",
      message: `No registry pinned in bunfig.toml. Add explicit registry to prevent accidental scoped package resolution to untrusted sources.`,
      fix: `Add to ${path}:\n[install]\nregistry = "https://registry.npmjs.org/"`,
    });
  }
}

// ─── Main export ───────────────────────────────────────────────────────────

export function runConfigAudit(): CheckResult {
  const findings: Finding[] = [];

  // npm: check both global and local .npmrc
  const npmrcPaths = [join(HOME, ".npmrc"), ".npmrc"];
  let foundNpmrc = false;
  for (const p of npmrcPaths) {
    if (fileExists(p)) {
      auditNpmrc(p, findings);
      foundNpmrc = true;
    }
  }
  if (!foundNpmrc) {
    findings.push({
      severity: "high",
      tool: "npm",
      rule: "no-npmrc",
      message: `No .npmrc found. npm runs with insecure defaults (scripts enabled, no release age gate).`,
      fix: `Create ~/.npmrc with:\nignore-scripts=true\nminimum-release-age=7 days\naudit=true`,
    });
  }

  auditPnpmrc(findings);
  auditYarnrc(findings);
  auditBunfig(findings);

  return { findings };
}
