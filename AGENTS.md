# pmharden — Agent & AI Assistant Guide

This file tells AI coding assistants (Claude, Codex, Cursor, Copilot, Gemini)
how to work in this repo: what the project does, where things live, how to
build/test, and what to watch out for.

---

## Project Purpose

`pmharden` is a supply-chain security CLI that audits the *environment* your
package manager runs in — not just individual packages. It catches the class
of misconfiguration that made ua-parser-js (2021), eslint-scope (2018), and
node-ipc (CVE-2022-23812) possible.

Three distinct checks:
- `audit`   — lints .npmrc, .pnpmrc, .yarnrc.yml, bunfig.toml against a security baseline
- `secrets` — detects plaintext tokens and overly-permissive file modes
- `global`  — audits globally installed packages for stale/risky installs

---

## Repo Layout

```
src/
  cli.ts                  # Commander.js entry point — subcommands defined here
  index.ts                # Barrel exports for programmatic use
  checks/
    config-audit.ts       # .npmrc / .pnpmrc / .yarnrc / bunfig.toml linter
    secrets.ts            # Token scanner + file permission checker
    global-audit.ts       # Global package auditor
  utils/
    fs.ts                 # readFile, fileExists, fileMode, expandHome
    types.ts              # Finding, CheckResult, Severity types
  reporter.ts             # renderFindings (color output), renderSummary (exit code)
test/
  checks.test.ts          # bun:test — 5 tests
dist/                     # Compiled JS (NodeNext, .js extensions)
```

---

## Build & Test

```bash
# Install deps (ignore-scripts is mandatory — this repo practices what it preaches)
npm install --ignore-scripts

# Compile TypeScript
npx tsc

# Run tests
bun test

# Run the CLI locally (no install needed)
node dist/cli.js audit
node dist/cli.js secrets
node dist/cli.js global
node dist/cli.js all
```

TypeScript config: `NodeNext` module resolution. All relative imports in
`src/` **must** use `.js` extensions (e.g. `import { foo } from "./bar.js"`),
even though the source files are `.ts`. This is a NodeNext requirement.

---

## Adding a New Check

### 1. Create the check file

```typescript
// src/checks/my-check.ts
import type { CheckResult, Finding } from "../utils/types.js";

export function runMyCheck(): CheckResult {
  const findings: Finding[] = [];

  // findings.push({ severity, tool, file, rule, message, fix })

  return { findings };
}
```

### 2. Severity levels

```typescript
type Severity = "critical" | "high" | "medium" | "low" | "info";
```

Use `critical` only for issues that directly expose credentials or allow
arbitrary code execution. Use `high` for misconfigs that are one step away
from exploitation. `medium` for hardening gaps. `low`/`info` for advisory.

### 3. Wire into cli.ts

Import and call in the relevant subcommand action (or add a new subcommand).
Push findings into `allFindings` in the `all` command.

### 4. Write a test

```typescript
// test/checks.test.ts
import { test, expect } from "bun:test";
import { runMyCheck } from "../src/checks/my-check.js";

test("my-check returns findings", () => {
  const result = runMyCheck();
  expect(Array.isArray(result.findings)).toBe(true);
});
```

---

## Finding Shape

Every finding must include all fields:

```typescript
interface Finding {
  severity: Severity;       // "critical" | "high" | "medium" | "low" | "info"
  tool: string;             // "npm" | "pnpm" | "yarn" | "bun" | "global"
  file: string;             // absolute path to the offending file
  rule: string;             // kebab-case rule ID, unique per check
  message: string;          // what is wrong and why it matters
  fix: string;              // exact command or line to add — actionable, copy-pasteable
}
```

The `fix` field is the most important UX element. It must be a concrete,
copy-pasteable command or config line. Not "update your config" — exact text.

---

## Key Files to Understand Before Editing

| File | Why it matters |
|------|---------------|
| `src/utils/types.ts` | All shared types — change here, update everywhere |
| `src/reporter.ts` | Color/severity rendering — exit code logic lives here |
| `src/checks/config-audit.ts` | Most complex check, 240+ lines — has per-PM parsers |
| `src/cli.ts` | Entry point — subcommand wiring |

---

## What Checks Already Exist (Avoid Duplicating)

### config-audit.ts
- npm: ignore-scripts, audit=false, allow-git, minimum-release-age, unsafe-perm, custom registry
- pnpm: strict-dep-builds, minimumReleaseAge, blockExoticSubdeps
- yarn: v1 detection (no script control), enableScripts (v2+), minimumReleaseAge
- bun: registry pin check

### secrets.ts
- Plaintext `_authToken=` in .npmrc
- `NPM_TOKEN=` / `NPM_SECRET=` / `NPM_PASSWORD=` patterns
- Config file permissions 644 (should be 600)

### global-audit.ts
- Known-risky global packages (create-react-app, yo, node-gyp)
- Stale package detection

---

## Good First Issues for AI Agents

These are well-scoped, don't require understanding the full codebase:

1. **`--fix` flag** — auto-apply safe remediations (e.g. add `ignore-scripts=true`
   to ~/.npmrc). Pattern: read the Finding, write the fix to the file.

2. **`--json` output** — add `--json` flag to all subcommands; output structured
   JSON instead of color text. Useful for CI pipelines.

3. **`binding.gyp` anomaly detection** — in `config-audit.ts`, warn when a
   package has `binding.gyp` but describes itself as pure JS. Requires checking
   package.json `description` vs presence of `binding.gyp`.

4. **Token scope check** — in `secrets.ts`, if an npm token is found, check
   whether it's a publish token vs read-only (publish tokens are higher risk).
   npm token format: `npm_` prefix (newer) or base64 (legacy).

5. **pnpm `onlyBuiltDependencies` enforcement** — pnpm 9+ supports an allowlist
   of packages permitted to run build scripts. Detect if it's not set and flag.

6. **`.npmignore` / `files` field check** — detect if a package is missing both
   `.npmignore` and the `files` field in package.json (risks publishing test/src
   files with embedded secrets).

---

## Pitfalls

- **Never run `npm install` without `--ignore-scripts`** in this repo.
  The whole point of pmharden is hardened installs. If CI or you run install
  without the flag, it's a self-contradiction.

- **NodeNext `.js` extensions are required** on all relative imports in `src/`.
  TypeScript resolves them to `.ts` at compile time. Missing extensions →
  runtime `ERR_MODULE_NOT_FOUND`.

- **`dist/` is committed** to npm (not to git — it's in .gitignore).
  Always run `npx tsc` before `npm publish`.

- **`process.exit(1)`** on CRITICAL/HIGH findings. Tests should not trigger
  real exit — mock or use try/catch if adding integration tests.

- **HOME path expansion** — all config file paths use `expandHome()` from
  `src/utils/fs.ts`. Use this helper, not raw string concatenation.

---

## Security Posture (Dogfooding)

This repo follows its own advice:

```
ignore-scripts=true     # set in ~/.npmrc
allow-git=none          # set in ~/.npmrc  (or: set it)
minimum-release-age=7   # set in ~/.npmrc  (or: set it)
```

If you're adding a dependency, verify it's not newly published (< 7 days) and
has no postinstall scripts. Check with:

```bash
npm view <package> scripts
npm view <package> time.created
```

---

## Publishing

```bash
npx tsc                                          # compile
bun test                                         # verify tests pass
npm publish --access public --ignore-scripts --otp=<TOTP>
```

npm `auth-type=web` requires `--otp=<code>` to bypass browser auth.
