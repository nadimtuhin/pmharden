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
        agentPrompt: `Open ${path} and replace any line matching //:_authToken=<plaintext> with //:_authToken=\${NPM_TOKEN}. Do not delete the line — only replace the literal token with the env var reference. Do not change any other lines. Then remind the user to: (1) set NPM_TOKEN in their shell profile, (2) rotate the exposed token at https://www.npmjs.com/settings/<username>/tokens`,
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
      agentPrompt: `Run: chmod 600 ${path}`,
    });
  }
}

function checkGitTracked(path: string, findings: Finding[], tool: string): void {
  if (!fileExists(path)) return;
  // Only flag if the file is git-tracked AND contains secrets.
  // A committed .npmrc with only policy settings (ignore-scripts etc.) is intentional.
  const content = readFile(path);
  if (!content) return;
  const hasSecret = SECRET_PATTERNS.some((p) => {
    p.regex.lastIndex = 0;
    return p.regex.test(content);
  });
  if (!hasSecret) return;
  try {
    execSync(`git ls-files --error-unmatch "${path}" 2>/dev/null`, { stdio: "pipe" });
    findings.push({
      severity: "critical",
      tool,
      file: path,
      rule: "config-committed-to-git",
      message: `${path} is tracked by git and contains secrets! Tokens are exposed in git history.`,
      fix: `git rm --cached ${path}\necho "${path}" >> .gitignore\n# Also rotate any tokens that were ever in this file`,
      agentPrompt: `Run these commands in order:\n1. git rm --cached ${path}\n2. echo "${path}" >> .gitignore\n3. git commit -m "security: untrack ${path} from git history"\nThen warn the user: any token that was ever committed in this file must be rotated immediately at https://www.npmjs.com/settings/<username>/tokens — git history retains the old value even after removal.`,
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
      agentPrompt: `Open ${path} and remove any line that matches the pattern "//registry:_authToken=" with nothing after the equals sign. Do not change any other lines.`,
    });
  }
}

function checkTokenScope(path: string, findings: Finding[], tool: string): void {
  const content = readFile(path);
  if (!content) return;

  // Modern npm tokens start with "npm_" — publish tokens are higher risk than read-only
  // Granular tokens (npm_...) vs legacy tokens (UUID-like)
  const publishTokenPattern = /\/\/[^:]+:_authToken=(npm_[A-Za-z0-9]{35,})/g;
  const legacyTokenPattern = /\/\/[^:]+:_authToken=([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/g;

  // Legacy tokens are automation tokens — always full publish scope, highest risk
  const legacyMatches = Array.from(content.matchAll(legacyTokenPattern));
  for (const _ of legacyMatches) {
    findings.push({
      severity: "high",
      tool,
      file: path,
      rule: "legacy-publish-token",
      message: `Legacy npm token (UUID format) detected. These are automation tokens with full publish scope and cannot be scoped down. Replace with a granular read-only token if publish access is not needed here.`,
      fix: `Generate a granular read-only token at https://www.npmjs.com/settings/<username>/tokens/new and replace the UUID token in ${path}`,
      agentPrompt: `Open ${path}. The file contains a legacy UUID-format npm token on a _authToken line. Remind the user to: (1) go to https://www.npmjs.com/settings/<username>/tokens and create a new granular token with read-only scope, (2) replace the UUID token in ${path} with the new token value wrapped in \${NPM_TOKEN} env var reference, (3) revoke the old UUID token. Do not modify the file directly — token rotation requires user action.`,
    });
  }

  // Modern npm_ tokens — flag if they look like they might be publish tokens
  // (we can't tell scope from the token value alone, so flag as advisory)
  const modernMatches = Array.from(content.matchAll(publishTokenPattern));
  for (const _ of modernMatches) {
    findings.push({
      severity: "info",
      tool,
      file: path,
      rule: "token-scope-unverified",
      message: `npm token found. Verify it is scoped to the minimum required permissions (read-only if publish is not needed in this context).`,
      fix: `Check token scope at https://www.npmjs.com/settings/<username>/tokens`,
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
    checkTokenScope(path, findings, tool);
    // Only check git tracking for project-level files (not home dir ones)
    if (!path.startsWith(HOME)) {
      checkGitTracked(path, findings, tool);
    }
  }

  return { findings };
}
