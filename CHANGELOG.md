# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **Breaking for library callers:** `runGlobalAudit` is now async and returns `Promise<CheckResult>`; `await` it. The `exec` test seam may return a Promise. Global audit now runs `npm view` lookups 4 at a time.

### Added
- `--json` flag on all subcommands for machine-readable CI output
- `pmharden all` now includes publish safety check
- pnpm `onlyBuiltDependencies` check (medium severity)
- Token scope check: legacy UUID tokens flagged as high, modern npm_ tokens flagged as info
- New `publish-check` module: detects missing `files` allowlist, overly broad globs, `.npmignore` denylist risk

### Fixed
- `.npmrc` values are read the way npm reads them: quoted values (`ignore-scripts="true"`) and trailing `;`/`#` comments no longer cause false findings or hide real ones.
- pnpm: `strictDepBuilds: false`, `strict-dep-builds=false`, commented-out keys and `minimumReleaseAge: 0` no longer count as "set"; `blockExoticSubdeps:false` is caught regardless of spacing.
- yarn/bun: commented-out `enableScripts`, `npmMinimalAgeGate` and `registry` lines no longer satisfy the checks.
- secrets: the git-tracked check now runs for projects that live under `$HOME`; a secret scan no longer misses tokens after an earlier scan in the same process; running from `$HOME` no longer reports each finding twice.
- Windows: permission findings (`npmrc-permissions`, `config-file-permissions`) are skipped, since Windows reports every file as mode 666.

## [0.1.5] - 2026-06-21

### Added
- Initial public release
- `audit` subcommand: config linter for npm, pnpm, yarn, bun
- `secrets` subcommand: plaintext token detection, file permission checks, git tracking check
- `global` subcommand: stale/risky globally installed package audit
- `all` subcommand: runs all checks in sequence
- Agent prompt generation for one-shot fixes via Claude/OpenCode
