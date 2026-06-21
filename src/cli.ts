#!/usr/bin/env node
import { Command } from "commander";
import { runConfigAudit } from "./checks/config-audit.js";
import { runSecretsCheck } from "./checks/secrets.js";
import { runGlobalAudit } from "./checks/global-audit.js";
import { renderFindings, renderSummary } from "./reporter.js";
import { Spinner } from "./utils/spinner.js";
import type { Finding } from "./utils/types.js";

const program = new Command();

program
  .name("pmharden")
  .description("Security hardening CLI for npm, pnpm, yarn, and bun")
  .version("0.1.0");

program
  .command("audit")
  .description("Audit package manager config files against security baseline")
  .action(() => {
    const spin = new Spinner("Auditing config files…").start();
    const result = runConfigAudit();
    spin.succeed("Config audit done");
    renderFindings(result.findings, "Config Audit");
    const severe = renderSummary(result.findings);
    process.exit(severe ? 1 : 0);
  });

program
  .command("secrets")
  .description("Scan config files for plaintext tokens, bad permissions, git exposure")
  .action(() => {
    const spin = new Spinner("Scanning for secrets…").start();
    const result = runSecretsCheck();
    spin.succeed("Secrets scan done");
    renderFindings(result.findings, "Secrets Scan");
    const severe = renderSummary(result.findings);
    process.exit(severe ? 1 : 0);
  });

program
  .command("global")
  .description("Audit globally installed packages for CVEs, stale versions, install-script risks")
  .action(() => {
    const spin = new Spinner("Fetching global package list…").start();
    const result = runGlobalAudit((name, current, total) => {
      spin.update(`Checking ${name} (${current}/${total})…`);
    });
    if (result.skipped) {
      spin.succeed(result.skipped);
      process.exit(0);
    }
    spin.succeed(`Global audit done`);
    renderFindings(result.findings, "Global Package Audit");
    const severe = renderSummary(result.findings);
    process.exit(severe ? 1 : 0);
  });

program
  .command("all")
  .description("Run all checks: config audit + secrets scan + global audit")
  .action(() => {
    const allFindings: Finding[] = [];
    console.log("");

    // 1. Config audit
    const configSpin = new Spinner("Auditing config files…").start();
    const configResult = runConfigAudit();
    if (configResult.findings.length === 0) {
      configSpin.succeed("Config files look good");
    } else {
      configSpin.fail(`Config audit: ${configResult.findings.length} issue(s) found`);
    }
    renderFindings(configResult.findings, "Config Audit");
    allFindings.push(...configResult.findings);

    // 2. Secrets scan
    const secretsSpin = new Spinner("Scanning for secrets…").start();
    const secretsResult = runSecretsCheck();
    if (secretsResult.findings.length === 0) {
      secretsSpin.succeed("No secrets found");
    } else {
      secretsSpin.fail(`Secrets: ${secretsResult.findings.length} issue(s) found`);
    }
    renderFindings(secretsResult.findings, "Secrets Scan");
    allFindings.push(...secretsResult.findings);

    // 3. Global audit with per-package progress
    const globalSpin = new Spinner("Fetching global package list…").start();
    const globalResult = runGlobalAudit((name, current, total) => {
      globalSpin.update(`Checking ${name} (${current}/${total})…`);
    });
    if (globalResult.skipped) {
      globalSpin.succeed(globalResult.skipped);
    } else if (globalResult.findings.length === 0) {
      globalSpin.succeed("Global packages look good");
    } else {
      globalSpin.fail(`Global audit: ${globalResult.findings.length} issue(s) found`);
    }
    renderFindings(globalResult.findings ?? [], "Global Package Audit");
    allFindings.push(...(globalResult.findings ?? []));

    renderSummary(allFindings);
    const severe = allFindings.some((f) => f.severity === "critical" || f.severity === "high");
    process.exit(severe ? 1 : 0);
  });

// Default: run all
if (process.argv.length === 2) {
  process.argv.push("all");
}

program.parse(process.argv);
