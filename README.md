# pmharden

Audits the environment your npm/pnpm/yarn/bun installs run in — not just the packages.

```bash
npx pmharden
```

[![CI](https://github.com/nadimtuhin/pmharden/actions/workflows/ci.yml/badge.svg)](https://github.com/nadimtuhin/pmharden/actions/workflows/ci.yml)
[![npm version](https://badge.fury.io/js/pmharden.svg)](https://www.npmjs.com/package/pmharden)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security Policy](https://img.shields.io/badge/security-policy-blue.svg)](SECURITY.md)

---

## The problem

I ran this on my own machine and found a plaintext npm token in `~/.npmrc` — readable by any `postinstall` script on any package I'd ever installed.

That's the same attack that hit eslint-scope in 2018. A compromised maintainer account pushed a malicious version. The postinstall script read `~/.npmrc`, sent the auth token to an attacker server, then used it to publish more malicious packages. Self-propagating.

The token had been sitting there for years. `npm audit` never flagged it. Socket.dev never flagged it. Neither tool looks at your config files.

---

## What it does

Three checks, one command:

```
pmharden audit    — config linter (.npmrc, .pnpmrc, .yarnrc.yml, bunfig.toml)
pmharden secrets  — plaintext tokens, file permissions
pmharden global   — stale or risky globally installed packages
pmharden          — all three
```

Example output:

```
Config Audit

✖  CRITICAL  [npm] ~/.npmrc (plaintext-npm-token)
  Plaintext secret: //registry.npmjs.org/:_authToken=npm_***REDACTED***
  Fix: Replace with ${NPM_TOKEN}

✖  HIGH  [npm] ~/.npmrc (allow-git-all)
  allow-git=all permits installs from unreviewed git commits.
  Fix: npm config set allow-git=none

✖  HIGH  [yarn] ~/.yarnrc (yarn-v1-no-script-control)
  yarn v1 has no config-level script blocking. Every postinstall attack
  applies with no mitigation path.
  Fix: yarn set version berry

─── Summary ────────────────────────────────
 1 critical   2 high  1 medium

Action required: Fix critical/high issues before your next install.

⚡ Fix all with one command:

  claude -p 'You are fixing package manager security issues...'
  opencode run '...'
```

When it finds issues, it generates a single prompt you can paste into Claude or OpenCode to fix everything in one shot.

---

## Why existing tools don't catch this

| Tool | What it checks | What it misses |
|------|---------------|----------------|
| `npm audit` | CVEs in installed packages | Your config, your secrets, your globals |
| [Socket.dev](https://socket.dev) | Per-package behavior analysis | Config files, ~/.npmrc tokens |
| [npq](https://github.com/lirantal/npq) | Install-time interception | Existing misconfig risks |
| [Snyk](https://snyk.io) | Dependency CVEs | PM environment audit |
| **pmharden** | Config + secrets + globals | Per-package CVE database |

Use it alongside `npm audit`, not instead of it.

---

## The attacks this prevents

### postinstall execution

Every package you install can run arbitrary code during `npm install` unless `ignore-scripts=true` is set.

| Attack | Year | What happened |
|--------|------|---------------|
| [eslint-scope](https://eslint.org/blog/2018/07/postmortem-for-malicious-packages-published-on-July-12th-2018-targeting-eslint-users/) | 2018 | Malicious postinstall read `~/.npmrc` tokens, published more malicious packages |
| [ua-parser-js](https://github.com/advisories/GHSA-pjwm-rvh2-c87w) | 2021 | Hijacked account, preinstall dropped crypto miners on millions of machines |
| [node-ipc](https://nvd.nist.gov/vuln/detail/CVE-2022-23812) | 2022 | Maintainer added postinstall that wiped files on Russian/Belarusian IPs (CVE-2022-23812) |
| [Ledger Connect Kit](https://www.ledger.com/blog/a-letter-from-ledger-chairman-ceo-pascal-gauthier-regarding-ledger-connect-kit-exploit) | 2023 | Malicious build scripts drained crypto wallets |
| [Mastra — 140+ packages](https://socket.dev/blog/mastra-npm-packages-compromised) | 2026 | Typosquatted dependency `easy-day-js` injected into 140+ `@mastra/*` packages via a hijacked npm account. Postinstall fetched a second-stage cross-platform infostealer that stole browser history, 160+ crypto wallet extensions, and CI secrets. `@mastra/core` alone has 918K weekly downloads. |
| [Mini Shai-Hulud / Miasma / Hades](https://socket.dev/supply-chain-attacks/miasma-mini-shai-hulud-supply-chain-attack) | 2026 | Ongoing worm campaign: 471+ artifacts across npm and PyPI. Payloads staged through Bun, targeting GitHub/npm/PyPI tokens, SSH keys, `.env` files, cloud credentials, and Kubernetes service accounts. Expanded to Go ecosystem and GitHub Actions. Latest wave hit `@immobiliarelabs` Backstage plugins (GitLab + LDAP auth) on June 26, 2026. |

`pmharden audit` checks that `ignore-scripts=true` is set.

### zero-day window

Malicious packages often get reported and pulled within days. If you install the day they're published, you're in the window.

| Attack | Year | Notes |
|--------|------|-------|
| [crossenv + 36 typosquats](https://blog.npmjs.org/post/163723642530/crossenv-malware-on-the-npm-registry) | 2017 | 36 packages, all immediately malicious |
| [IconBurst](https://www.reversinglabs.com/blog/iconburst-npm-software-supply-chain-attack-grabs-data-from-apps-and-websites) | 2022 | Typosquat packages scraped form data from live apps |
| [LofyGang](https://www.reversinglabs.com/blog/lofygang-disrupting-open-source-ecosystem) | 2022 | 200+ packages, exfiltrated Discord tokens |
| [Mastra `easy-day-js`](https://socket.dev/blog/mastra-npm-packages-compromised) | 2026 | Typosquat published clean, then updated the next day to deliver malware — same pattern as the axios campaign. Socket flagged it 6 minutes after publication. |

`pmharden audit` checks that `minimum-release-age=7 days` is set — blocks packages published in the last 7 days.

### plaintext tokens

[GitGuardian's annual report](https://www.gitguardian.com/state-of-secrets-sprawl) consistently puts npm tokens among the top leaked secrets in public repos. Once a postinstall script has your publish token, it can push new versions of any package you own.

`pmharden secrets` checks for plaintext tokens and overly-permissive file modes.

---

## AI scanner evasion (2026)

Attackers are now actively targeting AI-based malware scanners, not just human reviewers.

The Mini Shai-Hulud / Miasma campaign began [prepending fake prompt-injection headers](https://socket.dev/blog/npm-package-uses-prompt-injection-and-token-flooding-to-disrupt-ai-malware-scanners) to obfuscated payloads — comments designed to trigger AI safety filters, flood token context windows, or convince LLM-based scanners to misclassify the file before reaching the actual malicious code. One package (`shai_hulululud@1.0.48596`) shipped a 9MB `index.js` consisting almost entirely of safety-triggering Japanese-language bioweapon content in block comments, with the actual obfuscated stealer appended at the end.

This does not affect `pmharden`. Static config auditing and token scanning read structured files (`.npmrc`, `.pnpmrc`, etc.), not arbitrary JavaScript. But it is a signal that AI-assisted review tooling in your pipeline needs adversarial testing.

---

## Config checks

### npm

| Setting | Risk | Severity |
|---------|------|----------|
| `ignore-scripts` not `true` | Allows postinstall execution | HIGH |
| `allow-git=all` | Installs from unreviewed git commits | HIGH |
| No `minimum-release-age` | Zero-day window open | MEDIUM |
| `unsafe-perm=true` | Scripts run as root | HIGH |
| `audit=false` | Disables built-in CVE checks | MEDIUM |

### pnpm

| Setting | Risk | Severity |
|---------|------|----------|
| `strict-dep-builds` not set | Build scripts run without review | HIGH |
| No `minimumReleaseAge` | Zero-day window open | MEDIUM |
| `blockExoticSubdeps` not set | Non-registry sub-dependencies allowed | MEDIUM |

### yarn

| Setting | Risk | Severity |
|---------|------|----------|
| yarn v1 (classic) | No config-level script blocking — architectural gap | HIGH |
| `enableScripts: false` missing (v2+) | Allows postinstall execution | HIGH |

yarn v1 has no `ignore-scripts` equivalent that works via `.yarnrc`. See [yarnpkg/yarn#5335](https://github.com/yarnpkg/yarn/issues/5335). Every attack in the table above hit yarn v1 users with no mitigation available.

---

## Install

```bash
npm install -g pmharden   # global
npx pmharden              # no install
```

## CI

```yaml
- name: pmharden self-audit
  run: node dist/cli.js audit   # or: npx pmharden@latest audit
```

Exit code `1` on CRITICAL/HIGH. Suitable for blocking merges.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add a new check, run tests, and submit a PR.

Good first issues:
- `binding.gyp` detection — pure-JS packages with native build files (typosquat signal)
- Bun lockfile integrity checks
- `--fix` flag — auto-apply safe remediations to config files

See [SECURITY.md](SECURITY.md) for how to report vulnerabilities privately.

---

## Further reading

- [OWASP npm Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/NPM_Security_Cheat_Sheet.html)
- [Dependency Confusion](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610) — Alex Birsan, 2021
- [State of Secrets Sprawl](https://www.gitguardian.com/state-of-secrets-sprawl) — GitGuardian annual report
- [pnpm security options](https://pnpm.io/npmrc#ignore-scripts)
- [npm provenance](https://docs.npmjs.com/generating-provenance-statements)
- [Mastra npm supply chain attack (2026)](https://socket.dev/blog/mastra-npm-packages-compromised) — Socket Research
- [Mini Shai-Hulud / Miasma / Hades campaign tracker](https://socket.dev/supply-chain-attacks/miasma-mini-shai-hulud-supply-chain-attack) — 471+ artifacts, ongoing
- [AI scanner evasion via prompt injection in npm packages (2026)](https://socket.dev/blog/npm-package-uses-prompt-injection-and-token-flooding-to-disrupt-ai-malware-scanners) — Socket Research

---

MIT
