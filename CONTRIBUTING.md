# Contributing to pmharden

## Getting started

```bash
git clone https://github.com/nadimtuhin/pmharden.git
cd pmharden
npm install --ignore-scripts
bun test
```

## Project structure

```
src/
  cli.ts              — subcommands and --json wiring
  reporter.ts         — terminal and JSON output
  checks/
    config-audit.ts   — .npmrc / .pnpmrc / .yarnrc.yml / bunfig.toml linter
    secrets.ts        — plaintext tokens, file permissions, git exposure
    global-audit.ts   — globally installed package risk
    publish-check.ts  — files allowlist, .npmignore safety
  utils/
    fs.ts             — file helpers
    types.ts          — Finding, CheckResult, Severity
```

## Adding a check

1. Add a function to the relevant file in `src/checks/` (or create a new one).
2. Return `Finding[]` — each finding needs `severity`, `tool`, `rule`, `message`, and ideally `fix` + `agentPrompt`.
3. Wire it into `runConfigAudit()` / `runSecretsCheck()` / etc., and into the `all` subcommand in `cli.ts`.
4. Add a test in `test/checks.test.ts` that asserts the finding shape.

Severity guide:

| Severity | When to use |
|----------|-------------|
| `critical` | Active data exfiltration risk, plaintext secrets |
| `high` | Script execution risk, known attack vector |
| `medium` | Weakened defence-in-depth, real but indirect risk |
| `low` | Better practice available, minimal real risk |
| `info` | Advisory only, no action required |

## Running tests

```bash
bun test          # test suite
bun run lint      # type-check only
bun run build     # compile to dist/
```

## Pull requests

- One check per PR where possible.
- Tests must pass and `tsc` must be clean.
- Update CHANGELOG.md under `[Unreleased]`.
- Describe what attack the check prevents and link a real-world example if one exists.
