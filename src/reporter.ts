import chalk from "chalk";
import type { Finding, Severity } from "./utils/types.js";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

const SEVERITY_COLOR: Record<Severity, (s: string) => string> = {
  critical: chalk.bgRed.white.bold,
  high: chalk.red.bold,
  medium: chalk.yellow.bold,
  low: chalk.cyan,
  info: chalk.gray,
};

const SEVERITY_ICON: Record<Severity, string> = {
  critical: "✖",
  high: "✖",
  medium: "⚠",
  low: "ℹ",
  info: "·",
};

export function renderFindings(findings: Finding[], title: string): void {
  if (findings.length === 0) {
    console.log(chalk.green(`✔ ${title}: No issues found`));
    return;
  }

  const sorted = [...findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );

  console.log("\n" + chalk.bold.underline(title));
  console.log("");

  for (const f of sorted) {
    const colorFn = SEVERITY_COLOR[f.severity];
    const icon = SEVERITY_ICON[f.severity];
    const badge = colorFn(` ${f.severity.toUpperCase()} `);
    const tool = chalk.dim(`[${f.tool}]`);
    const rule = chalk.dim(`(${f.rule})`);
    const file = f.file ? chalk.dim(` ${f.file}`) : "";

    console.log(`${icon} ${badge} ${tool}${file} ${rule}`);
    console.log(`  ${f.message}`);
    if (f.fix) {
      console.log(chalk.dim(`  Fix: ${f.fix.split("\n").join("\n       ")}`));
    }
    console.log("");
  }
}

function buildConsolidatedPrompt(findings: Finding[]): string {
  const withPrompts = findings.filter((f) => f.agentPrompt);
  if (withPrompts.length === 0) return "";

  // Dedupe: same rule on same file from different tools (e.g. npm+pnpm both flag .npmrc)
  const seen = new Set<string>();
  const unique = withPrompts.filter((f) => {
    const key = `${f.rule}::${f.file ?? ""}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // Order: critical → high → medium → low → info
  const ordered = unique.sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );

  const steps = ordered
    .map((f, i) => {
      const label = `[${f.severity.toUpperCase()}] ${f.rule}${f.file ? ` in ${f.file}` : ""}`;
      return `${i + 1}. ${label}\n   ${f.agentPrompt}`;
    })
    .join("\n\n");

  return (
    `You are fixing package manager security issues found by pmharden. ` +
    `Apply ALL of the following fixes in order. After each fix, verify the change is correct before proceeding. ` +
    `Do not make any changes beyond what is listed. Do not install packages.\n\n` +
    steps
  );
}

export function renderSummary(allFindings: Finding[]): boolean {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of allFindings) counts[f.severity]++;

  console.log(chalk.bold("─── Summary ───────────────────────────────────"));
  console.log(
    [
      counts.critical > 0 ? chalk.bgRed.white.bold(` ${counts.critical} critical `) : null,
      counts.high > 0 ? chalk.red.bold(`${counts.high} high`) : null,
      counts.medium > 0 ? chalk.yellow(`${counts.medium} medium`) : null,
      counts.low > 0 ? chalk.cyan(`${counts.low} low`) : null,
      counts.info > 0 ? chalk.gray(`${counts.info} info`) : null,
    ]
      .filter(Boolean)
      .join("  ")
  );

  const hasSevere = counts.critical > 0 || counts.high > 0;

  if (hasSevere) {
    console.log(chalk.red("\nAction required: Fix critical/high issues before your next install."));
  } else if (counts.medium > 0) {
    console.log(chalk.yellow("\nReview medium findings when you have time."));
  } else {
    console.log(chalk.green("\nLooking good. Keep your package managers updated."));
  }

  const prompt = buildConsolidatedPrompt(allFindings);
  if (prompt) {
    const escaped = prompt.replace(/'/g, '"');
    console.log(chalk.blue("\n⚡ Fix all with one command:"));
    console.log(chalk.blue(`\n  claude -p '${escaped}'`));
    console.log(chalk.dim(`\n  # or:`));
    console.log(chalk.blue(`  opencode run '${escaped}'`));
  }

  return hasSevere;
}
