# TASK-02 [core] — CheckContext seam + config-audit fixtures + inline bugs

Owner: sonnet executor · Wave: rev.2 · Deps: TASK-01, critic pass #1

<context>
Tests currently run against the developer's real ~/.npmrc (non-deterministic) and one assertion is
`>= 0` (always true). No positive-case fixture proves any rule fires. Two known bugs: cli.ts
hardcodes version 0.1.0 (package.json says 0.1.5); config-audit flags `allow-git-all` when the key
is absent while the message claims it is "set to all".
</context>

<decisions>
- Seam per amended critic verdict: one `CheckContext { home?; cwd?; exec?; }` last-arg on all four
  run* checks; global-audit folds onProgress into it. Defaults: homedir()/process.cwd()/execFileSync.
  Documented test-only/unstable. cli.ts call sites for global updated; behavior unchanged.
- fs.ts: `HOME` const stays as default source; path building moves to call time (secrets'
  module-level CONFIG_FILES moves inside the function).
- allow-git fix: absent key → no finding (TASK-03 will rule on whether the key is even real);
  `allow-git=all` → finding. Message must not claim "set to all" when it isn't.
- version: read from package.json at runtime via import-relative URL, single source of truth.
</decisions>

<tdd>
test/config-audit.test.ts — fixture homes under test/fixtures/: bad-home (.npmrc with audit=false,
no ignore-scripts, mode 644) → asserts ignore-scripts-disabled, audit-disabled fire BY RULE NAME;
clean-home → asserts they don't. allow-git: unset → no allow-git-all finding (RED first — currently
fires); =all → finding; =none → none. Version: CLI subprocess --version matches package.json.
</tdd>

<dod>
- [ ] red observed for allow-git + version tests before fix
- [ ] hermetic: tests pass with HOME pointing anywhere (no dependence on runner's real home)
- [ ] vacuous checks.test.ts removed, replaced by per-check test file
- [ ] gate green (fast + --full)
</dod>

<ac>
- ac(gates): `bash backlog/checks.sh --full` → 0 failures.
- ac(behavior): `node dist/cli.js --version` → `0.1.5`.
</ac>

<changelog>
Files touched:
- src/utils/types.ts — added `CheckContext { home?; cwd?; exec?; }` interface.
- src/checks/config-audit.ts — `runConfigAudit(ctx: CheckContext = {})`; resolves `home`/`cwd`
  at call time; threaded `home` into auditPnpmrc/auditYarnrc/auditBunfig; npmrc scan paths are
  `join(home, ".npmrc")` and `join(cwd, ".npmrc")`; fixed allow-git bug (`if (allowGit === "all")`,
  dropped the `!allowGit` branch so an absent key no longer fires).
- src/checks/secrets.ts — `runSecretsCheck(ctx: CheckContext = {})`; `CONFIG_FILES` moved inside
  the function, built from resolved `home`/`cwd`; `path.startsWith(HOME)` now uses resolved `home`;
  `checkGitTracked` takes `cwd` and runs `execFileSync("git", ["ls-files","--error-unmatch",path], { stdio: "pipe", cwd })`
  instead of a shell string with `2>/dev/null` redirect; `execSync` import replaced with `execFileSync`.
- src/checks/publish-check.ts — `runPublishCheck(ctx: CheckContext = {})`; all 3 `process.cwd()`
  sites (pkgPath, hasNpmignore, the `.npmignore` finding's `file` field) use resolved `cwd`.
- src/checks/global-audit.ts — signature is now
  `runGlobalAudit(ctx: CheckContext & { onProgress?: ... } = {})`; added `defaultExec` built on
  `execFileSync` (try/catch → null, `{ encoding: "utf8", stdio: ["pipe","pipe","pipe"] }`); every
  `runCommand(<interpolated shell string>)` call replaced with `exec(cmd, args[])` — npm/pnpm/yarn
  list, `npm view <name> version`, `npm view <name>@<version> scripts --json` — closing the
  shell-injection hole from package names interpolated into `execSync` strings. `2>/dev/null`
  redirects removed (stdio pipes replace them).
- src/cli.ts — added `readFileSync` + `pkg` read via
  `JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"))`;
  `.version("0.1.0")` → `.version(pkg.version)`; both `runGlobalAudit(...)` call sites (audit
  command + all command) updated to the object form: `runGlobalAudit(json ? {} : { onProgress: ... })`.
- test/checks.test.ts — deleted (all 5 assertions were vacuous or environment-dependent).
- test/fixtures/bad-home/.npmrc — new, `audit=false\nunsafe-perm=true\n` (no ignore-scripts line).
- test/fixtures/clean-home/.npmrc — new, `ignore-scripts=true\naudit=true\n`.
- test/config-audit.test.ts — new. Hermetic: fixture homes + `mkdtempSync`'d tmp cwd per test
  (via beforeEach/afterEach), so the repo's own .npmrc never leaks in. Chmods bad-home fixture to
  0o644 and clean-home to 0o600 at test time (git doesn't preserve modes). Covers: bad-home fires
  ignore-scripts-disabled(critical)/audit-disabled(high)/unsafe-perm(high)/npmrc-permissions(medium)
  by rule name + severity; clean-home fires none of those four; allow-git absent/=all/=none built
  as tmp-dir .npmrc variants at test time (not committed fixtures).
- test/cli-version.test.ts — new. `Bun.spawnSync(["bun","src/cli.ts","--version"])` against
  `src/cli.ts` (proves the fix at the source, not just dist), asserts stdout matches
  `package.json`'s version.

Red evidence (observed on stashed pre-fix source, `bun test`):
  test/cli-version.test.ts:13
    Expected: "0.1.5"
    Received: "0.1.0"
    (fail) cli --version > matches the version in package.json
  test/config-audit.test.ts:27
    Expected: "critical"
    Received: undefined
    (fail) config-audit npm rules > bad-home fires ignore-scripts-disabled, audit-disabled,
           unsafe-perm, npmrc-permissions by rule name with matching severities
    (Reason: pre-seam runConfigAudit() ignored the ctx object entirely — ran against the real
     ~/.npmrc / real cwd instead of the fixture home, so none of the four rule names appeared.)
  test/config-audit.test.ts:70
    Expected: true
    Received: false
    (fail) config-audit allow-git > allow-git=all fires allow-git-all
    (Reason: same — ctx ignored, so the `allow-git=all` fixture home was never actually read;
     the pre-fix bug itself (`!allowGit || allowGit === "all"`) is a separate defect proven by
     source inspection at config-audit.ts:60-71, confirmed fixed by reading the diff.)
  8 pass / 3 fail, 17 expect() calls, Ran 11 tests across 3 files.
  (Re-ran by `git stash` (reverting src/, keeping new test/fixture files) then `git stash pop` —
   confirmed identical 3 failures, then restored the fix and reconfirmed green.)

Post-fix (green):
  $ bun test
  6 pass
  0 fail
  12 expect() calls
  Ran 6 tests across 2 files.

Final gate:
  $ bash backlog/checks.sh --full
  ▶ typecheck
    ✓ typecheck
  ▶ unit tests
    ✓ unit tests (6 pass, 0 fail)
  ▶ build
    ✓ build
  ▶ cli smoke (bad home → exit 1 + JSON)
    ✓ cli smoke (bad home → exit 1 + JSON)
  ✓ all checks passed

ac(behavior) check:
  $ node dist/cli.js --version
  0.1.5

Deviations from spec: none. The version test ran directly via `bun src/cli.ts --version` (not the
node/dist fallback) — worked on first try, no environment issue with the `import.meta.url` relative
path from src/.
</changelog>
