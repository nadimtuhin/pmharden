# TASK-01 [infra] — backlog scaffold + checks.sh gate

Owner: claude · Wave: rev.1 · Deps: none

<context>
pmharden has one vacuous test file and no repo gate. This task creates the backlog scaffold and a
checks.sh wired to the repo's real commands (package.json: `bun test`, `tsc --noEmit`, build `tsc`),
plus a --full tier that drives the REAL CLI (subprocess with HOME pointed at a generated bad fixture
home) asserting valid JSON + exit code 1 + a named rule.
</context>

<decisions>
- Gate commands detected from package.json scripts: test=`bun test`, lint/typecheck=`tsc --noEmit`, build=`tsc`.
- CLI smoke drives fixture homes via `HOME=<dir>` subprocess env, not an opts flag — os.homedir()
  resolves $HOME at process start. In-process tests use the opts seam (TASK-02).
- Smoke runs from a temp cwd so the repo's own .npmrc doesn't leak into project-level checks.
</decisions>

<dod>
- [x] checks.sh fast tier green on clean tree (no dishonest baseline needed — 5 pass, tsc clean)
- [x] --full tier: build + bad-home CLI run → valid JSON, exit 1, `ignore-scripts-disabled` present
- [x] backlog.md with locked decisions + rev log
</dod>

<ac>
- ac(gates): `bash backlog/checks.sh` → 0 failures; `bash backlog/checks.sh --full` → 0 failures.
</ac>

<changelog>
- backlog/checks.sh — gate (fast: tsc --noEmit + bun test; full: build + CLI smoke)
- backlog/backlog.md — index, locked decisions, rev log

Behavior/AC proof:
```
▶ typecheck        ✓
▶ unit tests       5 pass 0 fail  ✓
▶ build            ✓
▶ cli smoke (bad home → exit 1 + JSON)  ✓
✓ all checks passed
```

Ceilings (named): smoke asserts bad-home→exit-1 only; clean-home→exit-0 assertion deferred to
TASK-02/03 (today a clean home still trips high-severity rules like no-strict-dep-builds via the
~/.npmrc pnpm fallback, so the assertion would encode behavior TASK-03 is about to change).
</changelog>
