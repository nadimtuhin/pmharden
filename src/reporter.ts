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

    if (f.agentPrompt) {
      const prompt = f.agentPrompt.replace(/'/g, '"');
      console.log(chalk.blue(`  ⚡ Auto-fix:`));
      console.log(chalk.blue(`     claude -p '${prompt}'`));
      console.log(chalk.blue(`     opencode run '${prompt}'`));
    }

    console.log("");
  }
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
  const withPrompts = allFindings.filter((f) => f.agentPrompt);

  if (hasSevere) {
    console.log(chalk.red("\nAction required: Fix critical/high issues before your next install."));
  } else if (counts.medium > 0) {
    console.log(chalk.yellow("\nReview medium findings when you have time."));
  } else {
    console.log(chalk.green("\nLooking good. Keep your package managers updated."));
  }

  if (withPrompts.length > 0) {
    console.log(
      chalk.blue(
        `\n⚡ ${withPrompts.length} finding${withPrompts.length > 1 ? "s" : ""} above have AI auto-fix prompts.`
      )
    );
    console.log(
      chalk.dim(`   Paste the claude -p '...' or opencode run '...' line for each one.`)
    );
  }

  return hasSevere;
}
