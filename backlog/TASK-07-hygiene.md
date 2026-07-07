# TASK-07 [hygiene] — pnpm-lock removal + pnpm-audit false-positive fix

Owner: claude · Wave: rev.4 · Deps: TASK-06

<context>
Plan named two items: drop the unused pnpm-lock.yaml (CI installs via npm; repo carried 3
lockfiles) and check for dist/src drift. Local-proof-first on the built CLI (`node dist/cli.js
audit --json` against this repo) surfaced a real correctness bug in TASK-03's pnpm rewrite: it
fired `no-strict-dep-builds` (high) and `no-minimum-release-age` (medium) against ANY project's
plain npm `.npmrc`, with zero evidence the project uses pnpm — so every npm-only project with a
policy `.npmrc` (this repo included) got flagged for pnpm settings it will never need, exit 1 on
every `pmharden self-audit` CI run. Fixed inline, test-first, folded into this task.
</context>

<decisions>
- Lockfile policy (locked in plan): keep package-lock.json, drop pnpm-lock.yaml. No packageManager
  field in package.json, so no ambiguity for npm/CI.
- pnpm evidence gate: usesPnpm = hasWorkspace || hasGlobal || pnpm-lock.yaml in cwd ||
  package.json "packageManager" starts with "pnpm". No evidence → info-only no-pnpm-config,
  early return (no high/medium checks). Evidence present but no workspace/global config → the
  full existing check set still fires (that's the useful case: you use pnpm, unconfigured).
- dist/ is gitignored (verified: `git ls-files dist` → 0 tracked files) and CI builds fresh
  (`npx tsc` immediately before `pmharden self-audit` in ci.yml) — no committed-artifact-drift
  risk exists to repair. No CI change needed for this.
</decisions>

<tdd>
Red first (test/config-audit.test.ts): flipped "empty home+cwd fires all three pnpm rules" to
assert no-strict-dep-builds/no-minimum-release-age do NOT fire without pnpm evidence; added
npm-only-project test (plain .npmrc, no evidence → same); added pnpm-lock.yaml-present and
packageManager-field-present tests asserting the full set still fires when evidence exists.
</tdd>

<dod>
- [x] pnpm-lock.yaml removed, CI install path unaffected (npm install/--ignore-scripts, untouched)
- [x] red-first tests for the evidence gate; 45/45 green
- [x] dist/src drift: verified non-issue (gitignored + fresh CI build), not "fixed" because nothing
      was broken
- [x] self-audit on this repo: exit 0 (previously exit 1 on a false-positive high)
</dod>

<ac>
- ac(gates): `bash backlog/checks.sh --full` → 0 failures.
- ac(behavior): `node dist/cli.js audit --json` on this repo → single info finding, exit 0.
</ac>

<changelog>
- pnpm-lock.yaml — removed (git rm).
- src/checks/config-audit.ts — added `usesPnpm()` evidence check; auditPnpm gates the
  strict-dep-builds/minimum-release-age/blockExoticSubdeps checks behind it; no-pnpm-config splits
  into two messages ("not detected, skipping" vs "in use but unconfigured").
- test/config-audit.test.ts — 4 tests added/changed for the evidence gate.

Proof:
```
$ node dist/cli.js audit --json   # before fix, on this repo
[... no-strict-dep-builds (high), no-minimum-release-age (medium), no-pnpm-config (info) ...]
exit: 1

$ node dist/cli.js audit --json   # after fix (pnpm-lock.yaml removed + evidence gate), rebuilt
[{"severity":"info","tool":"pnpm","rule":"no-pnpm-config", ...}]
exit: 0

$ bash backlog/checks.sh --full
✓ typecheck  ✓ unit tests (45 pass, 0 fail, 116 expect() calls)  ✓ build  ✓ cli smoke
✓ all checks passed
```

Ceilings (named): usesPnpm() detection is heuristic (lockfile/config/packageManager field) — a
project that uses pnpm via some other mechanism (e.g. CI-only, no committed lockfile) still gets
the info-only path. Acceptable: false-negative (under-warn) is the safe failure direction for a
tool whose prior bug was false-positive (over-warn to the point of breaking CI).
</changelog>
