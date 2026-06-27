/**
 * Publish safety check.
 * Checks: .npmignore presence, package.json "files" field, accidental publish of secrets.
 */
import { readFileSync, existsSync } from "fs";
import { join } from "path";
import type { CheckResult, Finding } from "../utils/types.js";

function readJson(path: string): Record<string, unknown> | null {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return null;
  }
}

export function runPublishCheck(): CheckResult {
  const findings: Finding[] = [];
  const pkgPath = join(process.cwd(), "package.json");

  if (!existsSync(pkgPath)) return { findings };

  const pkg = readJson(pkgPath);
  if (!pkg) return { findings };

  // Skip private packages — they can't be published
  if (pkg.private === true) return { findings };

  const hasFiles = Array.isArray(pkg.files) && (pkg.files as unknown[]).length > 0;
  const hasNpmignore = existsSync(join(process.cwd(), ".npmignore"));

  if (!hasFiles && !hasNpmignore) {
    findings.push({
      severity: "high",
      tool: "npm",
      file: pkgPath,
      rule: "no-publish-allowlist",
      message: `No "files" field in package.json and no .npmignore. Publishing will include everything in the package directory — including .env files, test fixtures, and internal scripts.`,
      fix: `Add a "files" array to package.json listing only what should be published:\n  "files": ["dist", "README.md"]\nOR create a .npmignore listing paths to exclude.`,
      agentPrompt: `Open ${pkgPath} and add a "files" field listing only the distributable output (e.g. ["dist", "README.md"]). Do not add test files, .env, or config files. Prefer "files" allowlist over .npmignore denylist — it is safer because new files are excluded by default.`,
    });
  }

  // Warn if .npmignore exists but "files" does not — denylist approach is riskier
  if (hasNpmignore && !hasFiles) {
    findings.push({
      severity: "low",
      tool: "npm",
      file: join(process.cwd(), ".npmignore"),
      rule: "npmignore-over-files-allowlist",
      message: `.npmignore denylist used instead of "files" allowlist. New files added to the repo are published by default unless explicitly ignored.`,
      fix: `Replace .npmignore with a "files" field in package.json for safer allowlist-style publish control.`,
    });
  }

  // Check for dangerous patterns in files allowlist
  if (hasFiles) {
    const files = pkg.files as string[];
    const dangerousPatterns = [".", "*", "**"];
    for (const f of files) {
      if (dangerousPatterns.includes(f.trim())) {
        findings.push({
          severity: "medium",
          tool: "npm",
          file: pkgPath,
          rule: "files-glob-too-broad",
          message: `"files" entry "${f}" is too broad and will publish everything, including sensitive files.`,
          fix: `Replace "${f}" with explicit paths like ["dist", "README.md", "LICENSE"].`,
          agentPrompt: `Open ${pkgPath} and replace the overly broad "files" entry "${f}" with an explicit list of directories/files to publish (e.g. ["dist", "README.md", "LICENSE"]). Do not publish src/, test/, or config files.`,
        });
      }
    }
  }

  return { findings };
}
