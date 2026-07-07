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
