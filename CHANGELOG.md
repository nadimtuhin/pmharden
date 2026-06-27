# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `--json` flag on all subcommands for machine-readable CI output
- `pmharden all` now includes publish safety check
- pnpm `onlyBuiltDependencies` check (medium severity)
- Token scope check: legacy UUID tokens flagged as high, modern npm_ tokens flagged as info
- New `publish-check` module: detects missing `files` allowlist, overly broad globs, `.npmignore` denylist risk

## [0.1.5] - 2025-01-01

### Added
- Initial public release
- `audit` subcommand: config linter for npm, pnpm, yarn, bun
- `secrets` subcommand: plaintext token detection, file permission checks, git tracking check
- `global` subcommand: stale/risky globally installed package audit
- `all` subcommand: runs all checks in sequence
- Agent prompt generation for one-shot fixes via Claude/OpenCode
