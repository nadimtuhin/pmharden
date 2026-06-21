# pmharden

Security hardening CLI for **npm, pnpm, yarn, and bun** — the gap that no existing tool fills.

## What it does

| Command | What it checks |
|---------|---------------|
| `pmharden audit` | Config linter: `.npmrc`, `.pnpmrc`, `.yarnrc.yml`, `bunfig.toml` against a security baseline |
| `pmharden secrets` | Scans config files for plaintext tokens, bad file permissions, git-tracked secrets |
| `pmharden global` | Audits globally installed packages for stale versions, known-risky packages, and install-script risks |
| `pmharden all` | Runs all three checks (default) |

## Why this exists

The npm ecosystem has **no automated tool** that:
- Lints your package manager config files against a security baseline
- Scans `.npmrc` and `.yarnrc` for exposed tokens and wrong permissions
- Audits globally installed packages for CVEs and stale versions

`ringfence`, `npq`, Socket.dev — they all focus on *per-install* interception. `pmharden` covers the *environment* that all your installs happen in.

## Install

```bash
npm install -g pmharden
```

## Usage

```bash
# Run all checks
pmharden

# Config files only
pmharden audit

# Secret/token exposure
pmharden secrets

# Global packages
pmharden global
```

## Example output

```
✖  CRITICAL  [npm] ~/.npmrc (plaintext-npm-token)
  Plaintext secret found: //registry.npmjs.org/:_authToken=***REDACTED***
  Fix: Replace with env var reference: //registry.npmjs.org/:_authToken=${NPM_TOKEN}

✖  HIGH  [npm] ~/.npmrc (allow-git-all)
  allow-git=all permits installing packages directly from git. Supply-chain risk.
  Fix: npm config set allow-git=none

⚠  MEDIUM  [npm] ~/.npmrc (no-minimum-release-age)
  No minimum-release-age set. Packages published in the last 7 days are a common zero-day vector.
  Fix: Add minimum-release-age=7 days to ~/.npmrc
```

## What it checks (config audit)

### npm
- `ignore-scripts` not set to `true`
- `audit` disabled
- `allow-git=all` (git dependency risk)
- No `minimum-release-age` (freshly-published package risk)
- `unsafe-perm=true`
- Custom registry pointing away from npmjs.org

### pnpm
- `strict-dep-builds` not enabled
- `minimumReleaseAge` not set
- `blockExoticSubdeps` not set

### yarn
- Yarn v1 classic (no script blocking)
- `enableScripts: false` missing (v2+)
- `minimumReleaseAge` missing

### bun
- No `bunfig.toml` registry pin (bun blocks scripts by default — already safe)

## CI integration

```yaml
# GitHub Actions
- name: Security check package managers
  run: npx pmharden all
```

Exit code `1` on critical/high findings — suitable for CI gates.

## Contributing

PRs welcome. Key areas:
- `binding.gyp` anomaly detection (pure-JS packages with native build files)
- Token scope checking (publish vs read-only)
- pnpm `onlyBuiltDependencies` enforcement

## License

MIT
