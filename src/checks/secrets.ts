/**
 * .npmrc / .yarnrc / .pnpmrc secret scanner.
 * Detects: plaintext tokens, overly permissive file modes, committed secrets.
 */
import { join, dirname } from "path";
import { execSync } from "child_process";
import { HOME, readFile, fileExists, fileMode } from "../utils/fs.js";
import type { CheckResult, Finding } from "../utils/types.js";

// Patterns that indicate a hardcoded secret
const SECRET_PATTERNS: Array<{ name: string; regex: RegExp }> = [
  { name: "npm-token", regex: /\/\/[^:]+:_authToken=(npm_[A-Za-z0-9_]{10,})/g },
  { name: "npm-token-generic", regex: /\/\/[^:]+:_authToken=(?!\$\{)[^$\s]{10,}/g },
  { name: "npm-password", regex: /_password=(?!\$\{)[^$\s]{6,}/g },
  { name: "npm-email-leak", regex: /email=[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g },
  { name: "generic-secret", regex: /(?:secret|password|passwd|token|apikey|api_key)\s*=\s*(?!\$\{)[^\s]{6,}/gi },
];

function scanFileForSecrets(path: string, findings: Finding[], tool: string): void {
  const content = readFile(path);
  if (!content) return;

  for (const pattern of SECRET_PATTERNS) {
      const matches = Array.from(content.matchAll(pattern.regex));
    for (const match of matches) {
      // Redact the actual value in the message
      const redacted = match[0].replace(/=.+/, "=***REDACTED***");
      findings.push({
        severity: "critical",
        tool,
        file: path,
        rule: `plaintext-${pattern.name}`,
        message: `Plaintext secret found: ${redacted}`,
        fix: `Replace with env var reference, e.g. //registry.npmjs.org/:_authToken=\${NPM_TOKEN}`,
      });
    }
  }
}

function checkFilePermissions(path: string, findings: Finding[], tool: string): void {
  const mode = fileMode(path);
  if (mode === null) return;
  if ((mode & 0o077) !== 0) {
    findings.push({
      severity: "high",
      tool,
      file: path,
      rule: "config-file-permissions",
      message: `${path} permissions are too open (${mode.toString(8)}). Group/world can read credentials.`,
      fix: `chmod 600 ${path}`,
    });
  }
}

function checkGitTracked(path: string, findings: Finding[], tool: string): void {
  if (!fileExists(path)) return;
  try {
    // Check if file is tracked in git
    execSync(`git ls-files --error-unmatch "${path}" 2>/dev/null`, { stdio: "pipe" });
    findings.push({
      severity: "critical",
      tool,
      file: path,
      rule: "config-committed-to-git",
      message: `${path} is tracked by git! Any auth tokens in it are exposed in git history.`,
      fix: `git rm --cached ${path}\necho "${path}" >> .gitignore\n# Also rotate any tokens that were ever in this file`,
    });
  } catch {
    // not tracked — good
  }
}

function checkEnvVarUsage(path: string, findings: Finding[], tool: string): void {
  const content = readFile(path);
  if (!content) return;

  // If file has _authToken lines but they use env var syntax — good, no finding
  // If they do NOT use ${...} — already caught by scanFileForSecrets
  // Here we check for "token line exists but is empty" which might mean deleted but not rotated
  const tokenLineEmpty = content.match(/\/\/[^:]+:_authToken=\s*$/m);
  if (tokenLineEmpty) {
    findings.push({
      severity: "medium",
      tool,
      file: path,
      rule: "empty-token-line",
      message: `Empty _authToken line found. Token may have been deleted but the registry line remains.`,
      fix: `Remove the empty //registry:_authToken= line from ${path}`,
    });
  }
}

const CONFIG_FILES = [
  { path: join(HOME, ".npmrc"), tool: "npm" },
  { path: ".npmrc", tool: "npm" },
  { path: join(HOME, ".pnpmrc"), tool: "pnpm" },
  { path: ".pnpmrc", tool: "pnpm" },
  { path: join(HOME, ".yarnrc"), tool: "yarn" },
  { path: ".yarnrc", tool: "yarn" },
  { path: join(HOME, ".yarnrc.yml"), tool: "yarn" },
  { path: ".yarnrc.yml", tool: "yarn" },
];

export function runSecretsCheck(): CheckResult {
  const findings: Finding[] = [];

  for (const { path, tool } of CONFIG_FILES) {
    if (!fileExists(path)) continue;
    scanFileForSecrets(path, findings, tool);
    checkFilePermissions(path, findings, tool);
    checkEnvVarUsage(path, findings, tool);
    // Only check git tracking for project-level files (not home dir ones)
    if (!path.startsWith(HOME)) {
      checkGitTracked(path, findings, tool);
    }
  }

  return { findings };
}
