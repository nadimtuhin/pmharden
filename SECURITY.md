# Security Policy

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Email: security reports → open a [GitHub Security Advisory](https://github.com/nadimtuhin/pmharden/security/advisories/new) (private disclosure).

Expected response time: within 7 days.

## Supported versions

Only the latest release on npm receives security fixes.

## Scope

pmharden reads local config files and runs `npm audit` / `npm list -g`. It does not make outbound network requests except through those commands. It does not store or transmit any data.

False positives in detection rules are in scope. Supply-chain issues in pmharden's own dependencies are in scope.
