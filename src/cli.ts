#!/usr/bin/env node
import { Command } from "commander";
import { runConfigAudit } from "./checks/config-audit.js";
import { runSecretsCheck } from "./checks/secrets.js";
import { runGlobalAudit } from "./checks/global-audit.js";
import { renderFindings, renderSummary } from "./reporter.js";
import type { Finding } from "./utils/types.js";

const program = new Command();

program
  .name("pmharden")
  .description("Security hardening CLI for npm, pnpm, yarn, and bun")
  .version("0.1.0");

program
  .command("audit")
  .description("Audit package manager config files (.npmrc, .pnpmrc, .yarnrc, bunfig.toml) against security baseline")
  .action(() => {
    const result = runConfigAudit();
    renderFindings(result.findings, "Config Audit");
    const severe = renderSummary(result.findings);
    process.exit(severe ? 1 : 0);
  });

program
  .command("secrets")
  .description("Scan .npmrc / .yarnrc / .pnpmrc files for plaintext tokens, bad permissions, and git exposure")
  .action(() => {
    const result = runSecretsCheck();
    renderFindings(result.findings, "Secrets Scan");
    const severe = renderSummary(result.findings);
    process.exit(severe ? 1 : 0);
  });

program
  .command("global")
  .description("Audit globally installed npm/pnpm/yarn packages for CVEs, stale versions, and install-script risks")
  .action(() => {
    console.log("Fetching global package info (this may take a moment)...\n");
    const result = runGlobalAudit();
    if (result.skipped) {
      console.log(`Skipped: ${result.skipped}`);
      process.exit(0);
    }
    renderFindings(result.findings, "Global Package Audit");
    const severe = renderSummary(result.findings);
    process.exit(severe ? 1 : 0);
  });

program
  .command("all")
  .description("Run all checks: config audit + secrets scan + global audit")
  .action(() => {
    const allFindings: Finding[] = [];

    console.log("Running all pmharden checks...\n");

    const configResult = runConfigAudit();
    renderFindings(configResult.findings, "1. Config Audit");
    allFindings.push(...configResult.findings);

    const secretsResult = runSecretsCheck();
    renderFindings(secretsResult.findings, "2. Secrets Scan");
    allFindings.push(...secretsResult.findings);

    console.log("Fetching global package info...");
    const globalResult = runGlobalAudit();
    renderFindings(globalResult.findings, "3. Global Package Audit");
    allFindings.push(...globalResult.findings);

    const severe = renderSummary(allFindings);
    process.exit(severe ? 1 : 0);
  });

// Default: run all
if (process.argv.length === 2) {
  process.argv.push("all");
}

program.parse(process.argv);
