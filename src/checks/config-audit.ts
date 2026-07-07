/**
 * Package manager config linter.
 * Checks: .npmrc, pnpm-workspace.yaml / ~/.config/pnpm/config.yaml, .yarnrc.yml, bunfig.toml
 */
import { join } from "path";
import { HOME, readFile, fileExists, fileMode } from "../utils/fs.js";
import type { CheckContext, CheckResult, Finding } from "../utils/types.js";

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

function auditNpmrc(path: string, findings: Finding[], skips: string[]): void {
  const content = readFile(path);
  if (content === null) {
    skips.push(`could not read ${path}`);
    return;
  }

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
      agentPrompt: `Open ${path} and add the line "ignore-scripts=true" if it is missing. Do not remove any existing lines. Run: npm config set ignore-scripts true`,
    });
  }

  // 2. audit disabled
  if (cfg["audit"] === "false") {
    findings.push({
      severity: "high",
      tool,
      file,
      rule: "audit-disabled",
      message: `audit=false disables the automatic vulnerability report shown on install. It does not affect running "npm audit" manually.`,
      fix: `Remove audit=false from ${path}`,
      agentPrompt: `Open ${path} and remove the line "audit=false". Do not change any other lines.`,
    });
  }

  // 3. allow-git too permissive, or left at its permissive default
  const allowGit = cfg["allow-git"];
  if (allowGit === "all") {
    findings.push({
      severity: "high",
      tool,
      file,
      rule: "allow-git-all",
      message: `allow-git=all permits installing packages directly from git (including unreviewed commits). Supply-chain risk.`,
      fix: `npm config set allow-git=none  (or restrict to specific organizations)`,
      agentPrompt: `Open ${path} and set "allow-git=none". If the line does not exist, add it. If it says "allow-git=all", change it to "allow-git=none". Do not change any other lines.`,
    });
  } else if (allowGit === undefined) {
    findings.push({
      severity: "medium",
      tool,
      file,
      rule: "allow-git-unset",
      message: `allow-git is unset. npm's current default permits installing packages directly from git (including unreviewed commits) — supply-chain risk.`,
      fix: `npm config set allow-git=none  (or restrict to specific organizations)`,
      agentPrompt: `Open ${path} and add the line "allow-git=none" if it is not already present. Do not change any other lines.`,
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
      agentPrompt: `Review ${path}. The registry is set to "${cfg["registry"]}" instead of "https://registry.npmjs.org/". If this is intentional (e.g. a private registry), add a comment explaining why. If it is a mistake, change it to "registry=https://registry.npmjs.org/".`,
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
      agentPrompt: `Run: chmod 600 ${path}`,
    });
  }
}

// ─── pnpm ──────────────────────────────────────────────────────────────────
// pnpm never reads ~/.pnpmrc. It reads pnpm-workspace.yaml (project, pnpm >=
// 11 canonical), ~/.config/pnpm/config.yaml (global, pnpm >= 11, XDG default),
// and the project .npmrc (pnpm 10.x kebab-case keys).

function usesPnpm(home: string, cwd: string, hasWorkspace: boolean, hasGlobal: boolean): boolean {
  if (hasWorkspace || hasGlobal) return true;
  if (fileExists(join(cwd, "pnpm-lock.yaml"))) return true;
  const pkgContent = readFile(join(cwd, "package.json"));
  if (!pkgContent) return false;
  try {
    const pkg = JSON.parse(pkgContent) as { packageManager?: string };
    return typeof pkg.packageManager === "string" && pkg.packageManager.startsWith("pnpm");
  } catch {
    return false; // malformed package.json is publish-check's concern, not ours
  }
}

function auditPnpm(findings: Finding[], home: string, cwd: string, skips: string[]): void {
  const workspaceYaml = join(cwd, "pnpm-workspace.yaml");
  const globalYaml = join(home, ".config", "pnpm", "config.yaml");
  const projectNpmrc = join(cwd, ".npmrc");

  const hasWorkspace = fileExists(workspaceYaml);
  const hasGlobal = fileExists(globalYaml);

  // No evidence this project uses pnpm at all (no lockfile, no packageManager field,
  // no workspace/global config) — checking its .npmrc for pnpm-only keys would flag
  // every npm-only project that happens to have a policy .npmrc. Note-only and stop.
  if (!usesPnpm(home, cwd, hasWorkspace, hasGlobal)) {
    findings.push({
      severity: "info",
      tool: "pnpm",
      rule: "no-pnpm-config",
      message: `No pnpm usage detected (no pnpm-lock.yaml, workspace config, or "packageManager" field). Skipping pnpm-specific hardening checks.`,
      fix: `If this project uses pnpm, add pnpm-workspace.yaml:\nstrictDepBuilds: true\nminimumReleaseAge: 10080`,
      agentPrompt: `Only relevant if this project uses pnpm. If so, create pnpm-workspace.yaml at the project root with:\nstrictDepBuilds: true\nminimumReleaseAge: 10080`,
    });
    return;
  }

  if (!hasWorkspace && !hasGlobal) {
    findings.push({
      severity: "info",
      tool: "pnpm",
      rule: "no-pnpm-config",
      message: `pnpm is in use but no pnpm-workspace.yaml or global config was found.`,
      fix: `Add to pnpm-workspace.yaml:\nstrictDepBuilds: true\nminimumReleaseAge: 10080`,
      agentPrompt: `Create or edit pnpm-workspace.yaml at the project root and add:\nstrictDepBuilds: true\nminimumReleaseAge: 10080\nDo not change any other lines.`,
    });
  }

  const sources = [workspaceYaml, globalYaml, projectNpmrc].filter((p) => fileExists(p));
  const combined = sources
    .map((p) => {
      const content = readFile(p);
      if (content === null) skips.push(`could not read ${p}`);
      return content ?? "";
    })
    .join("\n");
  const primarySource = hasWorkspace ? workspaceYaml : sources[0];
  const fileField = primarySource ? { file: primarySource } : {};

  if (!combined.includes("strictDepBuilds") && !combined.includes("strict-dep-builds")) {
    findings.push({
      severity: "high",
      tool: "pnpm",
      ...fileField,
      rule: "no-strict-dep-builds",
      message: `strictDepBuilds not set. pnpm will silently run dependency build scripts without review.`,
      fix: `Add to pnpm-workspace.yaml:\nstrictDepBuilds: true\n(pnpm >= 10.3; on pnpm 10.x you can alternatively add strict-dep-builds=true to the project .npmrc)`,
      agentPrompt: `Open pnpm-workspace.yaml and add the line "strictDepBuilds: true" if it is not already present. On pnpm 10.x, "strict-dep-builds=true" in the project .npmrc also works. Do not change any other lines.`,
    });
  }

  if (!combined.includes("minimumReleaseAge") && !combined.includes("minimum-release-age")) {
    findings.push({
      severity: "medium",
      tool: "pnpm",
      ...fileField,
      rule: "no-minimum-release-age",
      message: `minimumReleaseAge not set. Fresh packages (<7 days) are a top supply-chain risk.`,
      fix: `Add to pnpm-workspace.yaml:\nminimumReleaseAge: 10080   (value is minutes; pnpm >= 10.16)`,
      agentPrompt: `Open pnpm-workspace.yaml and add the line "minimumReleaseAge: 10080" (value is minutes, 10080 = 7 days) if it is not already present. Do not change any other lines.`,
    });
  }

  if (combined.includes("blockExoticSubdeps: false")) {
    findings.push({
      severity: "medium",
      tool: "pnpm",
      ...fileField,
      rule: "block-exotic-subdeps-disabled",
      message: `blockExoticSubdeps is explicitly set to false. pnpm >= 11 defaults this to true; disabling it re-opens git/tarball transitive dependencies that bypass registry vetting.`,
      fix: `Remove "blockExoticSubdeps: false" from pnpm-workspace.yaml, or change it to true.`,
      agentPrompt: `Open pnpm-workspace.yaml and remove the line "blockExoticSubdeps: false" (or change it to "blockExoticSubdeps: true"). Do not change any other lines.`,
    });
  }
}

// ─── yarn ──────────────────────────────────────────────────────────────────

function auditYarnrc(findings: Finding[], home: string, skips: string[]): void {
  const v2path = join(home, ".yarnrc.yml");
  const v1path = join(home, ".yarnrc");

  if (fileExists(v2path)) {
    const content = readFile(v2path);
    if (content === null) {
      skips.push(`could not read ${v2path}`);
      return;
    }
    if (!content.includes("enableScripts: false")) {
      findings.push({
        severity: "low",
        tool: "yarn",
        file: v2path,
        rule: "enable-scripts-missing",
        message: `enableScripts: false not set in .yarnrc.yml. Current Yarn Berry defaults enableScripts to false, but older Berry versions ran scripts by default — set it explicitly to be safe on any version.`,
        fix: `Add to ${v2path}:\nenableScripts: false`,
        agentPrompt: `Open ${v2path} and add the line "enableScripts: false" at the top level if it is not already present. This is a YAML file — preserve indentation of existing lines. Do not change any other lines.`,
      });
    }
    if (!content.includes("npmMinimalAgeGate")) {
      findings.push({
        severity: "low",
        tool: "yarn",
        file: v2path,
        rule: "no-npm-minimal-age-gate",
        message: `npmMinimalAgeGate not set in .yarnrc.yml. Yarn gates fresh packages by default (npmMinimalAgeGate: "1w"), but pinning it explicitly avoids relying on the default.`,
        fix: `Add to ${v2path}:\nnpmMinimalAgeGate: 10080`,
        agentPrompt: `Open ${v2path} and add the line "npmMinimalAgeGate: 10080" (a plain number of minutes, not a day-suffix string like "7d" — Yarn has a known bug silently ignoring day-suffix duration strings, yarnpkg/berry#6899) at the top level if it is not already present. Do not change any other lines.`,
      });
    }
  } else if (fileExists(v1path)) {
    findings.push({
      severity: "high",
      tool: "yarn",
      file: v1path,
      rule: "yarn-v1-no-script-control",
      message: `yarn v1 classic has no built-in script blocking. Consider upgrading to yarn berry or using npm config set ignore-scripts=true.`,
      fix: `yarn set version berry  OR  migrate to pnpm/bun`,
      agentPrompt: `yarn v1 has no config-level way to block postinstall scripts. Two options:\n1. Run "yarn set version berry" to upgrade to Yarn Berry, then add "enableScripts: false" to .yarnrc.yml\n2. Migrate the project to pnpm: run "npx pnpm import" to convert the lockfile, then replace "yarn" with "pnpm" in package.json scripts\nAsk the user which approach they prefer before proceeding.`,
    });
  }
}

// ─── bun ───────────────────────────────────────────────────────────────────

function auditBunfig(findings: Finding[], home: string, skips: string[]): void {
  const path = join(home, ".bunfig.toml");
  if (!fileExists(path)) {
    findings.push({
      severity: "info",
      tool: "bun",
      rule: "no-bunfig",
      message: `No ~/.bunfig.toml found. Bun blocks scripts by default (good), but consider adding an explicit registry setting.`,
      fix: `Create ~/.bunfig.toml:\n[install]\nregistry = "https://registry.npmjs.org/"`,
      agentPrompt: `Create the file ~/.bunfig.toml with these contents:\n[install]\nregistry = "https://registry.npmjs.org/"`,
    });
    return;
  }

  const content = readFile(path);
  if (content === null) {
    skips.push(`could not read ${path}`);
    return;
  }
  if (!content.includes("registry")) {
    findings.push({
      severity: "low",
      tool: "bun",
      file: path,
      rule: "no-registry-pinned",
      message: `No registry pinned in bunfig.toml. Add explicit registry to prevent accidental scoped package resolution to untrusted sources.`,
      fix: `Add to ${path}:\n[install]\nregistry = "https://registry.npmjs.org/"`,
      agentPrompt: `Open ${path} and add the following under an [install] section:\nregistry = "https://registry.npmjs.org/"\nIf [install] already exists, add the line inside it. This is a TOML file — preserve existing structure.`,
    });
  }
}

// ─── Main export ───────────────────────────────────────────────────────────

export function runConfigAudit(ctx: CheckContext = {}): CheckResult {
  const home = ctx.home ?? HOME;
  const cwd = ctx.cwd ?? process.cwd();
  const findings: Finding[] = [];
  const skips: string[] = [];

  // npm: check both global and local .npmrc
  const npmrcPaths = [join(home, ".npmrc"), join(cwd, ".npmrc")];
  let foundNpmrc = false;
  for (const p of npmrcPaths) {
    if (fileExists(p)) {
      auditNpmrc(p, findings, skips);
      foundNpmrc = true;
    }
  }
  if (!foundNpmrc) {
    findings.push({
      severity: "high",
      tool: "npm",
      rule: "no-npmrc",
      message: `No .npmrc found. npm runs with insecure defaults (scripts enabled, no release age gate).`,
      fix: `Create ~/.npmrc with:\nignore-scripts=true\nmin-release-age=7\naudit=true`,
      agentPrompt: `Create the file ~/.npmrc with these contents:\nignore-scripts=true\nmin-release-age=7\naudit=true\nallow-git=none`,
    });
  }

  auditPnpm(findings, home, cwd, skips);
  auditYarnrc(findings, home, skips);
  auditBunfig(findings, home, skips);

  return { findings, ...(skips.length ? { skipped: skips.join("; ") } : {}) };
}
