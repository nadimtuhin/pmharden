# TASK-04 [secrets] — secrets check fixtures + regex-statefulness canary

Owner: sonnet executor · Wave: rev.3 · Deps: TASK-02 · Footprint: src/checks/secrets.ts, test/secrets.test.ts only

<context>
runSecretsCheck has zero positive-case tests. SECRET_PATTERNS are shared module-level /g regexes —
matchAll is lastIndex-safe but .test() in checkGitTracked mutates state; a canary proves repeated
calls yield identical findings. Fixtures built in tmp dirs at test time (control over mode bits),
not committed (never commit a token-shaped string).
</context>

<tdd>
test/secrets.test.ts — tmp home via mkdtempSync: (1) .npmrc with fake token
`//registry.npmjs.org/:_authToken=npm_` + 40 filler chars, mode 644 → plaintext-npm-token critical
+ config-file-permissions high, message redacts the token value; (2) clean policy-only .npmrc mode
600 → no findings; (3) canary: same ctx scanned twice → deep-equal findings; (4) env-var-ref token
`${NPM_TOKEN}` → no plaintext finding; (5) legacy UUID token → legacy-publish-token high.
</tdd>

<dod>
- [x] delete-the-code canary: at least one test fails when scanFileForSecrets body is stubbed out
- [x] no real-looking secrets committed anywhere
- [x] gate green (scoped to test/secrets.test.ts — full gate not run per task footprint)
</dod>

<changelog>
Files touched:
- test/secrets.test.ts (new) — 6 hermetic tests, fixtures built at test time under mkdtempSync
  dirs, tokens constructed via string concatenation (never committed as literal token-shaped
  strings).
- src/checks/secrets.ts — inspected only; no bug found, no changes. All 6 fixtures matched
  existing implementation behavior with no logic defects. Temporarily stubbed
  scanFileForSecrets to a no-op for the delete-the-code canary, then reverted
  (git diff confirms zero net change to this file).

Findings encoded per fixture:
1. npm_-prefixed token, mode 0644 -> plaintext-npm-token (critical), config-file-permissions
   (high); message contains "***REDACTED***", never the raw token. (Also fires
   plaintext-npm-token-generic and plaintext-generic-secret critical, and
   token-scope-unverified info — not asserted, since scanFileForSecrets has 5 overlapping
   SECRET_PATTERNS and "findings include" was the spec, not an exhaustive set.)
2. Clean policy-only .npmrc (ignore-scripts/audit), mode 0600 -> zero findings.
3. Statefulness canary: two runSecretsCheck(ctx) calls on the same token fixture ->
   deep-equal findings arrays (guards shared module-level /g regexes / matchAll semantics).
4. `${NPM_TOKEN}` env-var reference, mode 0600 -> no rule starting with "plaintext-".
5. Legacy UUID token -> legacy-publish-token (high). Encoded actual overlap: the generic
   plaintext pattern (`npm-token-generic`) also matches a bare UUID token since it has no
   npm_ prefix requirement, so plaintext-npm-token-generic (critical) fires too — asserted
   explicitly rather than assumed away.
6. Empty `_authToken=` line (nothing after `=`), mode 0600 -> empty-token-line (medium).

No genuine bug found in secrets.ts. The pattern overlap in test 1 and test 5 (a single
token line tripping 3-4 SECRET_PATTERNS rules) is existing, intentional-looking defense-in-depth
behavior, not a defect — tests encode "includes" rather than asserting an exhaustive finding set.

Delete-the-code canary proof (scanFileForSecrets stubbed to `return;` before its body):
  bun test v1.3.14 (0d9b296a)
  ...
  error: expect(received).toBe(expected)
  Expected: "critical"
  Received: undefined
    at <anonymous> (test/secrets.test.ts:29:36)
  (fail) secrets check > plaintext npm token fires plaintext-npm-token critical + config-file-permissions high, redacts value [9.31ms]
  ...
  error: expect(received).toBe(expected)
  Expected: "critical"
  Received: undefined
    at <anonymous> (test/secrets.test.ts:80:38)
  (fail) secrets check > legacy UUID token fires legacy-publish-token high (and plaintext-npm-token-generic critical) [1.11ms]

   4 pass
   2 fail
   7 expect() calls
  Ran 6 tests across 1 file. [127.00ms]

Final green run (scoped to this file, after restoring secrets.ts):
  bun test v1.3.14 (0d9b296a)

   6 pass
   0 fail
   10 expect() calls
  Ran 6 tests across 1 file. [68.00ms]
</changelog>
