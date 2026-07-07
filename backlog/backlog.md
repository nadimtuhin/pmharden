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

- **Testability seam (locked):** each `run*` check takes an optional opts object
  (`{ home?: string }`, global-audit also `{ exec? }`), defaulting to real `homedir()`/`execFileSync`.
  CLI-level smoke drives fixture homes via `HOME=<fixture> node dist/cli.js` in a subprocess
  (os.homedir() reads $HOME at process start on POSIX) — no CLI flag needed, callers unchanged.
  Rejected: mocking os.homedir() (module-load `HOME` const makes it fragile), in-process env swap (Bun caches).
- **Lockfile policy:** keep `package-lock.json` (CI installs with npm), drop unused `pnpm-lock.yaml`.
- **Push policy:** commits stay local; push (incl. pre-existing bd986ba) only on explicit user confirmation.

## Rev log
