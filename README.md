# pmharden

Security hardening CLI for **npm, pnpm, yarn, and bun** package managers.

Audits the *environment* your installs run in — not just individual packages.

```bash
npx pmharden
```

---

## Why this matters

Most supply-chain attacks exploit **misconfigured package manager settings**, not just malicious packages.
The three most common attack paths:

**1. Postinstall script execution** — malicious packages run arbitrary code during `npm install`

| Incident | Year | What happened |
|----------|------|---------------|
| [event-stream](https://github.com/dominictarr/event-stream/issues/116) | 2018 | Hijacked dependency ran postinstall to steal Bitcoin wallet data |
| [eslint-scope](https://eslint.org/blog/2018/07/postmortem-for-malicious-packages-published-on-July-12th-2018-targeting-eslint-users/) | 2018 | Compromised credentials → malicious postinstall read `~/.npmrc` tokens → published more malicious packages |
| [ua-parser-js](https://github.com/advisories/GHSA-pjwm-rvh2-c87w) | 2021 | Account hijack → preinstall dropped crypto miners + password stealers on millions of machines |
| [coa](https://github.com/advisories/GHSA-73qr-pfmq-6rp8) | 2021 | Same wave — postinstall info-stealer in widely used CLI package |
| [node-ipc](https://nvd.nist.gov/vuln/detail/CVE-2022-23812) | 2022 | Maintainer added postinstall payload that wiped files on Russian/Belarusian IPs (CVE-2022-23812) |
| [Ledger Connect Kit](https://www.ledger.com/blog/a-letter-from-ledger-chairman-ceo-pascal-gauthier-regarding-ledger-connect-kit-exploit) | 2023 | Malicious version published; build scripts drained crypto wallets |

**Fix:** `npm config set ignore-scripts=true` — what `pmharden audit` checks for.

---

**2. Newly-published packages (zero-day window)** — malicious packages often get pulled within days

| Incident | Year | What happened |
|----------|------|---------------|
| [crossenv + 36 typosquats](https://blog.npmjs.org/post/163723642530/crossenv-malware-on-the-npm-registry) | 2017 | 36 packages published and immediately malicious; users hit within hours |
| [ua-parser-js](https://github.com/advisories/GHSA-pjwm-rvh2-c87w) | 2021 | Hijacked version pulled within hours; a 7-day hold catches this |
| [IconBurst](https://www.reversinglabs.com/blog/iconburst-npm-software-supply-chain-attack-grabs-data-from-apps-and-websites) | 2022 | Typosquat packages (ionicio, ajax-libs, etc.) scraped form data from apps |
| [LofyGang](https://www.reversinglabs.com/blog/lofygang-disrupting-open-source-ecosystem) | 2022 | 200+ newly-published packages exfiltrated Discord tokens |

**Fix:** `minimum-release-age=7 days` in `~/.npmrc` — blocks packages published in the last 7 days.
What `pmharden audit` checks for.

---

**3. Plaintext tokens in config files** — postinstall scripts actively hunt for them

The eslint-scope attack (2018) is the canonical example: malicious postinstall read `~/.npmrc`,
sent the auth token to an attacker server, then used it to publish more malicious packages.
The attack chained *install-script execution + plaintext token* into a self-propagating supply-chain worm.

GitGuardian's [State of Secrets Sprawl](https://www.gitguardian.com/state-of-secrets-sprawl) reports
that npm tokens are among the most commonly leaked secrets found in public GitHub repos.

**Fix:** Replace `_authToken=abc123` with `_authToken=${NPM_TOKEN}` — what `pmharden secrets` checks for.

---

## What it checks

| Command | What it audits |
|---------|---------------|
| `pmharden audit` | Config linter: `.npmrc`, `.pnpmrc`, `.yarnrc.yml`, `bunfig.toml` |
| `pmharden secrets` | Plaintext tokens, overly-permissive file modes (644 vs 600) |
| `pmharden global` | Globally installed packages: stale versions, known-risky tools |
| `pmharden all` | All three (default) |

### Config checks: npm

| Setting | Risk | Severity |
|---------|------|----------|
| `ignore-scripts` not `true` | Allows postinstall/preinstall execution | HIGH |
| `allow-git=all` | Installs from unreviewed git commits — bypasses registry audit | HIGH |
| No `minimum-release-age` | Packages published in last 7 days are a common zero-day vector | MEDIUM |
| `unsafe-perm=true` | Runs scripts as root | HIGH |
| `audit=false` | Disables built-in CVE checks | MEDIUM |

### Config checks: pnpm

| Setting | Risk | Severity |
|---------|------|----------|
| `strict-dep-builds` not set | Build scripts run silently without review | HIGH |
| No `minimumReleaseAge` | Same 7-day zero-day window as npm | MEDIUM |
| `blockExoticSubdeps` not set | Allows non-registry sub-dependencies | MEDIUM |

### Config checks: yarn

| Setting | Risk | Severity |
|---------|------|----------|
| yarn v1 (classic) | No config-level script blocking — architectural gap | HIGH |
| `enableScripts: false` missing (v2+) | Allows postinstall execution | HIGH |

yarn v1 has no equivalent of `ignore-scripts` that can be enforced via `.yarnrc`.
See [yarnpkg/yarn#5335](https://github.com/yarnpkg/yarn/issues/5335).
Every postinstall-based attack above hit yarn users with no mitigation path.

### Secrets checks

| Pattern | Risk | Severity |
|---------|------|----------|
| Plaintext `_authToken=` | Token theft via postinstall (eslint-scope attack) | CRITICAL |
| `.npmrc` / `.yarnrc` permissions 644 | World-readable auth tokens | HIGH |
| `NPM_TOKEN=` in config | Leaked env var pattern | CRITICAL |

### Global package checks

| Check | Risk |
|-------|------|
| Stale versions | Old globals (e.g. `npm` itself) miss security patches — see [netmask CVE-2021-28918](https://nvd.nist.gov/vuln/detail/CVE-2021-28918) |
| `create-react-app` installed globally | Stale scaffold pulls hundreds of pinned-old vulnerable deps at project creation |
| `node-gyp` / build tools | Native build tools in postinstall chains; version confusion attacks |

---

## Install

```bash
# Global (run anywhere)
npm install -g pmharden

# Or npx (no install)
npx pmharden
```

## Usage

```bash
# Run all checks (default)
pmharden

# Config files only
pmharden audit

# Token / secret exposure
pmharden secrets

# Global packages
pmharden global
```

## Example output

```
Config Audit

✖  CRITICAL  [npm] ~/.npmrc (plaintext-npm-token)
  Plaintext secret found: //registry.npmjs.org/:_authToken=***REDACTED***
  Fix: Replace with env var: //registry.npmjs.org/:_authToken=${NPM_TOKEN}

✖  HIGH  [npm] ~/.npmrc (allow-git-all)
  allow-git=all permits installing packages from unreviewed git commits. Supply-chain risk.
  Fix: npm config set allow-git=none

✖  HIGH  [yarn] ~/.yarnrc (yarn-v1-no-script-control)
  yarn v1 has no config-level script blocking. All postinstall attacks apply with no mitigation.
  Fix: yarn set version berry  OR  migrate to pnpm/bun

⚠  MEDIUM  [npm] ~/.npmrc (no-minimum-release-age)
  Packages published in the last 7 days are a common zero-day supply-chain vector.
  Fix: Add to ~/.npmrc:  minimum-release-age=7 days
```

## CI integration

```yaml
# .github/workflows/security.yml
- name: Harden package manager config
  run: npx pmharden all
```

Exit code `1` on CRITICAL/HIGH findings — suitable for CI gates.

## The gap this fills

| Tool | What it does | What it misses |
|------|-------------|----------------|
| `npm audit` | CVEs in installed packages | Config hardening, secrets, global packages |
| [Socket.dev](https://socket.dev) | Per-install package analysis | Your environment config |
| [npq](https://github.com/lirantal/npq) | Install-time interception | Existing config risks, secrets in files |
| [Snyk](https://snyk.io) | Dependency CVEs | PM config audit, plaintext tokens |
| **pmharden** | **Config + secrets + globals** | Per-package CVE database (use alongside npm audit) |

`pmharden` is not a replacement for `npm audit` or Socket.dev — it's the missing layer that audits
the *environment* all your installs happen in.

## Further reading

- [npm security best practices](https://cheatsheetseries.owasp.org/cheatsheets/NPM_Security_Cheat_Sheet.html) — OWASP
- [Avoiding npm substitution attacks](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610) — Alex Birsan (2021)
- [The State of Open Source Security](https://snyk.io/reports/open-source-security/) — Snyk annual report
- [pnpm security options](https://pnpm.io/npmrc#ignore-scripts) — pnpm docs
- [npm provenance](https://docs.npmjs.com/generating-provenance-statements) — npm docs (build attestation)

## Contributing

PRs welcome. Key areas:
- `binding.gyp` anomaly detection (pure-JS packages with native build files)
- Token scope checking (publish vs read-only tokens)
- pnpm `onlyBuiltDependencies` enforcement
- Bun lockfile integrity checks

## License

MIT
