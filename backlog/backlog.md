# pmharden backlog

Loop: plan → red→green → local-proof → critic → commit. Gate: `bash backlog/checks.sh` (fast),
`--full` adds build + real-CLI smoke.

## Index

- TASK-01 — init scaffold + gate
- TASK-02 — testability seam + config-audit fixtures + inline bugs (version, allow-git)
- TASK-03 — rule-truth audit: every recommended config key vs official docs
- TASK-04 — secrets check fixtures + regex-statefulness canary
- TASK-05 — global-audit + publish-check tests, execSync → execFileSync
- TASK-06 — error visibility: silent fails surface via `skipped`
- TASK-07 — hygiene: pnpm-lock.yaml, stale dist/src/, CI dist drift

## Decisions

- **Testability seam (locked, amended by critic pass #1 — APPROVE-WITH-CHANGES):** all four `run*`
  checks take one optional last-arg `CheckContext { home?: string; cwd?: string; exec?: (cmd, args) => string | null }`
  (global-audit additionally folds `onProgress` into the same object — positional param on a
  published API is a future breaking change). Defaults: real `homedir()` / `process.cwd()` /
  `execFileSync`. `cwd` must cover config-audit's relative `.npmrc` and secrets' `git ls-files`
  subprocess; secrets' `path.startsWith(HOME)` uses the injected home. Knobs documented test-only/unstable.
  CLI smoke drives fixture homes via `HOME=<fixture>` subprocess env (POSIX-only, scoped to `audit` —
  `all` still hits real npm/git subprocesses; global-audit is covered in-process via `exec` injection).
  Rejected: mocking os.homedir() (module-load `HOME` const makes it fragile), in-process env swap
  (Bun caches), DI container (YAGNI for 4 functions), settable config module (shared mutable state).
- **Lockfile policy:** keep `package-lock.json` (CI installs with npm), drop unused `pnpm-lock.yaml`.
- **Push policy:** commits stay local; push (incl. pre-existing bd986ba) only on explicit user confirmation.

## Rev log

- **rev.1** (TASK-01): backlog scaffold + checks.sh gate.
- **rev.2** (TASK-02, opus critic pass #1 APPROVE-WITH-CHANGES applied): unified CheckContext
  seam across all four checks; execSync→execFileSync in global-audit (closed a shell-injection
  hole); fixed hardcoded CLI version and the allow-git absent-key false positive; replaced vacuous
  test/checks.test.ts with hermetic fixture tests.
- **rev.3** (TASK-03/04/05, parallel — disjoint file footprints): pnpm config audit rewritten off
  the fictional ~/.pnpmrc onto files pnpm actually reads (doc-verified); deleted unsafe-perm
  (no-op since npm 7) and two never-valid pnpm INI rules; fixed npm/yarn release-age key names;
  hermetic secrets tests with regex-statefulness canary; global-audit/publish-check tests incl.
  hostile-package-name argv-isolation proof.
- **rev.4** (TASK-06/07 + opus critic pass #2 APPROVE-WITH-CHANGES applied): every check surfaces
  unreadable/unparseable inputs via `skipped` instead of silent-clean; removed unused
  pnpm-lock.yaml; fixed a self-discovered bug where the TASK-03 pnpm rewrite fired high/medium
  findings against ANY npm-only project with zero pnpm evidence (added `usesPnpm()` gate);
  reconciled README.md/AGENTS.md, which still advertised the placebo keys/rules the code no
  longer emits.

Final gate: `bash backlog/checks.sh --full` → 45 pass, 0 fail, typecheck/build/CLI-smoke all green.
Self-audit on this repo: `node dist/cli.js audit` → exit 0 (previously would have been a
false-positive exit 1 before the rev.4 pnpm-evidence fix).

Named ceilings (opus critic pass #2, minor, not fixed — logged per protocol):
- global-audit: a per-package `npm view` failure (network/404) is silently treated as
  up-to-date/script-free with no `skipped` note — same class TASK-06 fixed at the check level,
  not at per-package granularity. Low severity, network-dependent.
- config-audit pnpm: `combined.includes("minimumReleaseAge")` is a substring presence check, so an
  explicit `minimumReleaseAge: 0` or `strictDepBuilds: false` reads as "configured" (false
  negative, not false positive — accepted per TASK-07's "under-warn is the safe direction").
- `blockExoticSubdeps: false` detection is whitespace-exact (misses `blockExoticSubdeps:false`).
- `usesPnpm()`: an unreadable (EACCES) package.json is treated as "no evidence" with no skip note.
