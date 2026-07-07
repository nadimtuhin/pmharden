# TASK-05 [checks] — global-audit + publish-check tests

Owner: sonnet executor · Wave: rev.3 · Deps: TASK-02 · Footprint: src/checks/global-audit.ts,
src/checks/publish-check.ts, test/global-audit.test.ts, test/publish-check.test.ts only

<context>
Both checks had zero tests. TASK-02 already migrated execSync→execFileSync behind the injected
`exec` seam; this task proves the behavior: rules fire on fake exec output, hostile package names
stay a single argv element (no shell), publish-check fixtures cover private/allowlist/glob paths.
</context>

<tdd>
global-audit via injected exec (records every (cmd,args) call, returns canned outputs):
known-risky-global (create-react-app), severely-outdated-global (≥2 majors), outdated-global,
global-with-install-scripts (postinstall present), skipped when no globals. Hostile-name canary:
dependency named `; touch /tmp/pwned; $(id) "x"` — assert it reaches exec as ONE args element,
verbatim, and cmd is "npm" (argv array = no shell interpretation).
publish-check via ctx.cwd tmp dirs: private:true → none; no files + no .npmignore →
no-publish-allowlist; files:["*"] → files-glob-too-broad; .npmignore only → npmignore-over-files-allowlist
(and no no-publish-allowlist); missing package.json → no findings.
</tdd>

<dod>
- [x] hostile-name test proves argv isolation
- [x] delete-the-code canary spot-checked (one rule per file)
- [x] gate green (scoped to this task's footprint — see below)
</dod>

<changelog>
Files touched: test/global-audit.test.ts (new), test/publish-check.test.ts (new),
backlog/TASK-05-global-publish-tests.md (this changelog). No changes to
src/checks/global-audit.ts or src/checks/publish-check.ts — no genuine bug was
exposed; both files behave exactly as spec'd, so left untouched (git diff on both
is empty after the canary round-trip).

Scoped test run (green):
  bun test test/global-audit.test.ts test/publish-check.test.ts
  -> 17 pass, 0 fail, 41 expect() calls

global-audit.test.ts covers: known-risky-global (create-react-app), the three
outdated-version bands (severely-outdated-global >=2 majors / outdated-global
1 major / neither when equal), global-with-install-scripts (postinstall),
skipped="No global packages found" when all three list commands return null,
the hostile-name argv-isolation canary (name `; touch /tmp/pwned; $(id) "x"`
reaches exec as one argv element, cmd is always "npm", no shell string
concatenation, and existsSync("/tmp/pwned") stays false), and dedupe (same
package name from npm+pnpm lists is only exec'd once for view/scripts calls).

publish-check.test.ts covers: private:true -> no findings; no files + no
.npmignore -> no-publish-allowlist (high); files:["*"|"."|"**"] (table-tested)
-> files-glob-too-broad (medium); no files + .npmignore present ->
npmignore-over-files-allowlist (low) and NOT no-publish-allowlist; safe
files:["dist","README.md"] -> no findings; missing package.json -> no
findings; malformed/invalid JSON package.json -> no findings today (silent,
documented in-test as current behavior — TASK-06 is expected to surface this
via `skipped` instead of silently returning clean).

Delete-the-code canary proof (both stubs applied one at a time, then reverted
— confirmed via `git diff --stat` showing no residual changes):

1. global-audit.ts: changed `if (KNOWN_RISKY_GLOBALS[pkg.name])` to
   `if (false && KNOWN_RISKY_GLOBALS[pkg.name])`.
   Ran `bun test test/global-audit.test.ts`:
     7 pass, 1 fail — failure was exactly
     "global-audit known-risky-global > flags create-react-app by name"
     (expect(finding).toBeDefined() received undefined). All other 7 tests
     stayed green, confirming test isolation. Reverted the stub; re-ran ->
     8 pass, 0 fail.

2. publish-check.ts: changed `if (hasFiles) {` to `if (false && hasFiles) {`
   (guarding the files-glob-too-broad loop).
   Ran `bun test test/publish-check.test.ts`:
     6 pass, 3 fail — the 3 failures were exactly the table-tested
     "publish-check overly broad files glob" cases for "*", ".", and "**"
     (all three expect(finding).toBeDefined() received undefined). Reverted
     the stub; re-ran -> 9 pass, 0 fail.

Final combined scoped run after both reverts: 17 pass, 0 fail (shown above).
`git diff --stat src/checks/global-audit.ts src/checks/publish-check.ts` is
empty — no production code was modified by this task.

Deviations from spec: none of substance. Test 4 in global-audit spec ("all
three list commands return null") is satisfied by an empty fake-exec config
object (pnpm/yarn default to null already); no separate hostile hostile-name
finding-shape assertion was added beyond "findings is defined" since the
task's ask was specifically argv isolation, not rule-firing behavior for
malicious names.
</changelog>
