# TASK-06 [core] — error visibility: broken environment must not report "clean"

Owner: sonnet executor · Wave: rev.4 · Deps: TASK-02..05

<context>
Every error path silently returns null/[] — an unreadable .npmrc, a missing npm binary, or a
malformed package.json all report "clean", the worst failure mode for a security tool. CheckResult
already has a `skipped?: string` field and cli.ts already renders it for the global check; populate
it everywhere and render it everywhere.
</context>

<decisions>
- A MISSING config file stays a non-event (or its existing no-*-config finding). Only a file that
  EXISTS but can't be read (readFile→null after fileExists), or a parse failure, or an exec failure
  surfaces via `skipped` (multiple reasons joined with "; ").
- global-audit distinguishes "commands all failed" (skipped names the failure) from "zero globals"
  (existing message) — exec null vs empty dependency set.
- Exit codes unchanged: skipped is visibility, not severity. JSON output stays a findings array —
  named ceiling: JSON consumers don't see skipped (upgrade path: {findings, skipped} envelope in 0.2).
- Human mode: cli.ts prints a ⚠ line with result.skipped for every check (audit/secrets/all/global).
</decisions>

<tdd>
Fault-injection, red first: chmod 000 .npmrc in fixture home → config-audit skipped names the path
(currently silent-clean); same for secrets; injected exec all-null → global-audit skipped says
commands failed, NOT "No global packages found"; malformed package.json → publish-check skipped
says parse failure. Existing 38 tests stay green.
</tdd>

<dod>
- [x] each of the four checks has a red-first fault-injection test
- [x] no check can report zero findings AND no skipped when its inputs were unreadable
- [x] gate green (fast + --full)
</dod>

<changelog>
Files touched:
- src/checks/config-audit.ts — threaded a `skips: string[]` through auditNpmrc/auditPnpm/auditYarnrc/auditBunfig;
  each readFile-after-fileExists null now pushes `could not read <path>` instead of silently returning.
  Replaced the `readFile(path)!` non-null assertions in auditYarnrc/auditBunfig with proper null checks.
  runConfigAudit returns `{ findings, ...(skips.length ? { skipped: skips.join("; ") } : {}) }`.
- src/checks/secrets.ts — runSecretsCheck now reads each CONFIG_FILE's content once per loop iteration;
  on readFile === null (file exists but unreadable) it records `could not read <path>` and skips further
  checks for that file. scanFileForSecrets/checkEnvVarUsage/checkTokenScope/checkGitTracked were changed to
  accept the already-read `content: string` instead of re-reading the path themselves.
- src/checks/global-audit.ts — getNpmGlobals/getPnpmGlobals/getYarnGlobals now return `GlobalPackage[] | null`
  (null = exec failed or JSON unparseable; [] = command succeeded with zero packages). runGlobalAudit:
  all three null -> `skipped: "npm/pnpm/yarn list commands failed — global packages were NOT audited"`,
  findings: []. All succeeded but zero total packages -> unchanged `skipped: "No global packages found"`.
  Partial failure with packages present -> findings processed normally, and `skipped` lists which
  command(s) failed (e.g. "pnpm list failed — pnpm globals not audited; yarn list failed — yarn globals not audited").
- src/checks/publish-check.ts — readJson returning null (unreadable OR malformed JSON) now returns
  `{ findings: [], skipped: "could not parse <pkgPath> — publish safety was NOT checked" }` instead of a
  silent `{ findings: [] }`. Missing package.json is unchanged (clean no-op, no skip).
- src/cli.ts — imported chalk. `audit`, `secrets`, and each section of `all` now print
  `chalk.yellow(\`⚠ ${result.skipped}\`)` after renderFindings when result.skipped is set. `global` command
  and the global section of `all` were adjusted so the early-exit/succeed(skipped) shortcut only fires when
  findings.length === 0; when skipped coexists with findings, findings render normally (fail/succeed by
  count) and the ⚠ line is printed afterward.
- test/config-audit.test.ts — added "config-audit unreadable npmrc" describe: chmod 0o000 fixture, asserts
  `result.skipped` is defined and contains the path. Guarded with `it.skipIf(process.getuid?.() === 0)`.
- test/secrets.test.ts — added chmod 0o000 fixture test asserting `skipped` contains the path and no
  `plaintext-*` findings are reported. Same root-guard.
- test/global-audit.test.ts — replaced the old "no globals" test's exec fixture (previously exec => null
  for everything) with one where npm/pnpm/yarn all return valid-but-empty JSON, so it still asserts
  `skipped === "No global packages found"` under the new semantics. Added
  "global-audit all commands failed" (exec => null for everything -> skipped names the failure, not "No
  global packages found") and "global-audit partial command failure" (npm succeeds with one package that
  has install scripts, pnpm/yarn fail -> finding still present AND skipped mentions pnpm+yarn).
- test/publish-check.test.ts — flipped the malformed-JSON test from asserting silent-clean to asserting
  `skipped` is defined, contains the package.json path, and mentions a parse failure.

Red evidence (before implementation, `bun test`):
  test/global-audit.test.ts:140 — expect(result.skipped).not.toBe("No global packages found") failed
    (received "No global packages found")
  test/global-audit.test.ts:160 — expect(result.skipped).toBeDefined() failed (received undefined)
  test/secrets.test.ts:103 — expect(result.skipped).toBeDefined() failed (received undefined)
  test/publish-check.test.ts:106 — expect(result.skipped).toBeDefined() failed (received undefined)
  test/config-audit.test.ts:213 — expect(result.skipped).toBeDefined() failed (received undefined)
  Summary: 37 pass, 5 fail, 99 expect() calls, Ran 42 tests across 5 files.

Gate (after implementation):
  $ bash backlog/checks.sh --full
  ▶ typecheck        ✓
  ▶ unit tests       ✓ (42 pass, 0 fail, 108 expect() calls)
  ▶ build            ✓
  ▶ cli smoke (bad home → exit 1 + JSON)  ✓
  ✓ all checks passed

Visual smoke (`bun src/cli.ts all` on the real dev machine, human mode):
  Global Package Audit section printed 7 findings (global-with-install-scripts, low) for real npm
  globals, followed by:
    ⚠ pnpm list failed — pnpm globals not audited
  confirming the ⚠ line renders correctly when skipped coexists with findings (pnpm was unavailable on
  this machine, npm/yarn/other checks proceeded normally).

Deviations: none from the locked decisions. Used `content === null` (strict null check) rather than
falsy checks when detecting "unreadable" vs "readable-but-empty" files, to avoid mis-classifying a
valid empty config file as unreadable — this is consistent with the decision's wording ("readFile(p)
returns null") and does not change any existing test's outcome.
</changelog>
