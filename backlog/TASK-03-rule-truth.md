# TASK-03 [rules] — rule-truth audit: config keys vs official docs

Owner: sonnet executor · Wave: rev.3 · Deps: TASK-02

<context>
Research pass (document-specialist, 2026-07-07) verified every recommended key against current
official docs. Net: the tool's entire pnpm strategy is inert (targets ~/.pnpmrc, a file pnpm never
reads; two keys never had INI forms at all), npm's release-age key is misnamed, unsafe-perm has
been a no-op since npm 7, and yarn's release-age key is a pnpm name pasted onto yarn. A security
tool recommending placebo settings is the worst kind of bug — users believe they're protected.
</context>

<verdicts (researched, cited in run log)>
| key | tool | verdict | correct form |
|---|---|---|---|
| ignore-scripts | npm | REAL | keep |
| audit | npm | REAL | keep (message: it disables the automatic install-time audit report) |
| allow-git | npm | REAL | values all/none/root; npm 11 default is `all` (none planned for npm 12) |
| unsafe-perm | npm | OBSOLETE | no-op since npm 7 — message claiming privilege escalation is false |
| registry | npm | REAL | keep |
| minimum-release-age | npm | WRONG NAME+SYNTAX | real key: `min-release-age=7` (bare integer days) |
| strict-dep-builds | pnpm | WRONG LOCATION | pnpm 10.x: project .npmrc; pnpm ≥11: pnpm-workspace.yaml `strictDepBuilds: true` |
| minimum-release-age | pnpm | WRONG LOCATION | pnpm 10.x: project .npmrc (minutes); ≥11: workspace yaml / ~/.config/pnpm/config.yaml `minimumReleaseAge: 1440` |
| block-exotic-subdeps | pnpm | NEVER-INI | pnpm ≥11 only, `blockExoticSubdeps: true` in pnpm-workspace.yaml (default true on 11) |
| only-built-dependencies[] | pnpm | NEVER-VALID | pre-11: `onlyBuiltDependencies:` in workspace yaml / package.json pnpm key; ≥11: `allowBuilds` map |
| ~/.pnpmrc | pnpm | FAKE FILE | pnpm reads ~/.config/pnpm/rc (INI, auth) + ~/.config/pnpm/config.yaml (settings) |
| enableScripts | yarn | REAL, DEFAULT FLIPPED | current Berry docs: default false (verified 2026-07-07); older Berry defaulted true |
| minimumReleaseAge | yarn | WRONG KEY | yarn's key is `npmMinimalAgeGate` (duration string, default "1w"; known day-suffix parsing bug) |
| [install] registry | bun | REAL | keep |
| bun blocks scripts by default | bun | TRUE | trustedDependencies opt-in |
</verdicts>

<decisions>
- Fix in place, keep the four-tool structure. pnpm audit rewritten to check the files pnpm actually
  reads: pnpm-workspace.yaml (project), ~/.config/pnpm/config.yaml (global, XDG_CONFIG_HOME-aware
  via ctx.home for tests), project .npmrc for the 10.x kebab keys. No version detection — messages
  name which pnpm version each location applies to.
- unsafe-perm rule: deleted (flags a no-op; its message is factually false).
- allow-git: absent key → medium finding with HONEST message (npm ≤11 default is `all`, so unset
  means git installs allowed; recommend explicit `allow-git=none`); `=all` → high; `=none`/`root` → clean.
  (TASK-02 made absent→no-finding as a stopgap for the lying message; this supersedes it.)
- npm release-age: recommend `min-release-age=7` everywhere (no-npmrc fix text included).
- yarn: enable-scripts-missing downgraded critical→low, message: explicit false protects older
  Berry versions where the default was true. minimumReleaseAge rule → npmMinimalAgeGate, low
  severity (gated by default now), recommend minutes/plain duration due to the parsing bug.
- Every fix/agentPrompt string updated to match — placebo text in prompts is the same bug.
</decisions>

<tdd>
test/config-audit.test.ts extended: pnpm fixture home with ~/.config/pnpm/config.yaml present/absent;
project pnpm-workspace.yaml with/without strictDepBuilds+minimumReleaseAge; allow-git absent →
finding fires with message NOT claiming "set to all"; unsafe-perm fixture line produces NO finding;
yarn .yarnrc.yml without npmMinimalAgeGate → low finding naming npmMinimalAgeGate.
</tdd>

<dod>
- [x] every changed rule has a red-first test
- [x] no fix/agentPrompt text recommends a key/location the docs don't support
- [ ] gate green (fast + --full) — not run here (concurrent agents editing other files); scoped `bun test test/config-audit.test.ts` is green
</dod>

<changelog>
Files touched: src/checks/config-audit.ts, test/config-audit.test.ts.

Changes:
- npm: deleted the unsafe-perm rule (no-op since npm 7). allow-git absent now fires a new
  medium `allow-git-unset` finding with an honest message (no "set to all" claim); `=all`
  still fires `allow-git-all` (high); `=none`/`=root` fire neither. audit-disabled message
  softened to describe the install-time report only. no-npmrc fix/agentPrompt now recommend
  `min-release-age=7` instead of `minimum-release-age=7 days`.
- pnpm: `auditPnpmrc` (which only ever read the non-existent ~/.pnpmrc, falling back to
  ~/.npmrc) replaced with `auditPnpm(findings, home, cwd)`, which checks
  cwd/pnpm-workspace.yaml, home/.config/pnpm/config.yaml, and cwd/.npmrc — concatenated into
  `combined` for key detection. New/changed rules: `no-pnpm-config` (info, neither yaml
  source exists), `no-strict-dep-builds` (high), `no-minimum-release-age` (medium),
  `block-exotic-subdeps-disabled` (medium, only fires if `blockExoticSubdeps: false` is
  explicit — absent is safe on pnpm >=11 default). Deleted `no-block-exotic-subdeps` and
  `no-only-built-dependencies` (recommended INI syntax never existed).
- yarn: `enable-scripts-missing` severity critical -> low, message corrected (current Berry
  defaults enableScripts to false; older Berry versions did not). Renamed the release-age
  rule to `no-npm-minimal-age-gate`, checking `npmMinimalAgeGate` (yarn's real key, not
  pnpm's `minimumReleaseAge`), severity low, recommending a plain minutes integer
  (yarnpkg/berry#6899 day-suffix parsing bug).
- bun: unchanged.

Red evidence (bun test test/config-audit.test.ts, before source changes — 6 failing):
  - bad-home ... unsafe-perm: expected undefined, received "high"
  - allow-git-unset: expected defined, received undefined
  - no-npmrc fix text: expected to contain "min-release-age=7", received
    "...minimum-release-age=7 days..."
  - pnpm empty home+cwd: expected no-pnpm-config/no-strict-dep-builds/no-minimum-release-age
    to fire, none did (old code only reads ~/.pnpmrc or ~/.npmrc fallback)
  - blockExoticSubdeps: false in pnpm-workspace.yaml: expected block-exotic-subdeps-disabled,
    old code never reads cwd, so it never fired
  - yarn enable-scripts-missing: expected severity "low", received "critical"
  8 pass / 6 fail / 29 expect() calls, 14 tests.

Green evidence (bun test test/config-audit.test.ts, after source changes):
  bun test v1.3.14 (0d9b296a)
   14 pass
   0 fail
   40 expect() calls
  Ran 14 tests across 1 file. [135.00ms]

Deviations: none from the locked decisions. `npx tsc --noEmit` shows no errors for
config-audit.ts or config-audit.test.ts (grepped for "config-audit" in output; other
in-flight files from concurrent agents were not evaluated, per task scope).
</changelog>
