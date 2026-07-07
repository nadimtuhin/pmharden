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
- [ ] every changed rule has a red-first test
- [ ] no fix/agentPrompt text recommends a key/location the docs don't support
- [ ] gate green (fast + --full)
</dod>

<changelog>
(filled by executor)
</changelog>
