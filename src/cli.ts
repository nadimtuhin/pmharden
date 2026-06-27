#!/usr/bin/env node
import { Command } from "commander";
import { runConfigAudit } from "./checks/config-audit.js";
import { runSecretsCheck } from "./checks/secrets.js";
import { runGlobalAudit } from "./checks/global-audit.js";
import { runPublishCheck } from "./checks/publish-check.js";
import { renderFindings, renderSummary, renderJson } from "./reporter.js";
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
  .option("--json", "Output findings as JSON")
  .action(({ json }) => {
    const spin = json ? null : new Spinner("Auditing config files…").start();
    const result = runConfigAudit();
    if (json) {
      renderJson(result.findings);
      process.exit(result.findings.some((f) => f.severity === "critical" || f.severity === "high") ? 1 : 0);
    }
    spin!.succeed("Config audit done");
    renderFindings(result.findings, "Config Audit");
    const severe = renderSummary(result.findings);
    process.exit(severe ? 1 : 0);
  });

program
  .command("secrets")
  .description("Scan config files for plaintext tokens, bad permissions, git exposure")
  .option("--json", "Output findings as JSON")
  .action(({ json }) => {
    const spin = json ? null : new Spinner("Scanning for secrets…").start();
    const result = runSecretsCheck();
    if (json) {
      renderJson(result.findings);
      process.exit(result.findings.some((f) => f.severity === "critical" || f.severity === "high") ? 1 : 0);
    }
    spin!.succeed("Secrets scan done");
    renderFindings(result.findings, "Secrets Scan");
    const severe = renderSummary(result.findings);
    process.exit(severe ? 1 : 0);
  });

program
  .command("global")
  .description("Audit globally installed packages for CVEs, stale versions, install-script risks")
  .option("--json", "Output findings as JSON")
  .action(({ json }) => {
    const spin = json ? null : new Spinner("Fetching global package list…").start();
    const result = runGlobalAudit(json ? undefined : (name, current, total) => {
      spin!.update(`Checking ${name} (${current}/${total})…`);
    });
    if (json) {
      renderJson(result.findings ?? []);
      process.exit((result.findings ?? []).some((f) => f.severity === "critical" || f.severity === "high") ? 1 : 0);
    }
    if (result.skipped) {
      spin!.succeed(result.skipped);
      process.exit(0);
    }
    spin!.succeed(`Global audit done`);
    renderFindings(result.findings, "Global Package Audit");
    const severe = renderSummary(result.findings);
    process.exit(severe ? 1 : 0);
  });

program
  .command("all")
  .description("Run all checks: config audit + secrets scan + global audit + publish check")
  .option("--json", "Output findings as JSON")
  .action(({ json }) => {
    const allFindings: Finding[] = [];

    if (!json) console.log("");

    // 1. Config audit
    const configSpin = json ? null : new Spinner("Auditing config files…").start();
    const configResult = runConfigAudit();
    if (!json) {
      if (configResult.findings.length === 0) configSpin!.succeed("Config files look good");
      else configSpin!.fail(`Config audit: ${configResult.findings.length} issue(s) found`);
      renderFindings(configResult.findings, "Config Audit");
    }
    allFindings.push(...configResult.findings);

    // 2. Secrets scan
    const secretsSpin = json ? null : new Spinner("Scanning for secrets…").start();
    const secretsResult = runSecretsCheck();
    if (!json) {
      if (secretsResult.findings.length === 0) secretsSpin!.succeed("No secrets found");
      else secretsSpin!.fail(`Secrets: ${secretsResult.findings.length} issue(s) found`);
      renderFindings(secretsResult.findings, "Secrets Scan");
    }
    allFindings.push(...secretsResult.findings);

    // 3. Global audit
    const globalSpin = json ? null : new Spinner("Fetching global package list…").start();
    const globalResult = runGlobalAudit(json ? undefined : (name, current, total) => {
      globalSpin!.update(`Checking ${name} (${current}/${total})…`);
    });
    if (!json) {
      if (globalResult.skipped) globalSpin!.succeed(globalResult.skipped);
      else if (globalResult.findings.length === 0) globalSpin!.succeed("Global packages look good");
      else globalSpin!.fail(`Global audit: ${globalResult.findings.length} issue(s) found`);
      renderFindings(globalResult.findings ?? [], "Global Package Audit");
    }
    allFindings.push(...(globalResult.findings ?? []));

    // 4. Publish check
    const publishSpin = json ? null : new Spinner("Checking publish safety…").start();
    const publishResult = runPublishCheck();
    if (!json) {
      if (publishResult.findings.length === 0) publishSpin!.succeed("Publish config looks good");
      else publishSpin!.fail(`Publish check: ${publishResult.findings.length} issue(s) found`);
      renderFindings(publishResult.findings, "Publish Safety");
    }
    allFindings.push(...publishResult.findings);

    if (json) {
      renderJson(allFindings);
    } else {
      renderSummary(allFindings);
    }
    const severe = allFindings.some((f) => f.severity === "critical" || f.severity === "high");
    process.exit(severe ? 1 : 0);
  });

// Default: run all
if (process.argv.length === 2) {
  process.argv.push("all");
}

program.parse(process.argv);
