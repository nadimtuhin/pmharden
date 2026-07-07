#!/usr/bin/env bash
# Repo gate — 0 failures required before "done".
#   bash backlog/checks.sh          # fast inner loop: bun test + tsc --noEmit
#   bash backlog/checks.sh --full   # + build + real CLI smoke against fixture homes
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"

FULL=0
[ "${1:-}" = "--full" ] || [ "${CHECKS_FULL:-0}" = "1" ] && FULL=1

fail=0
run() { local name="$1"; shift; echo "▶ $name"; if "$@"; then echo "  ✓ $name"; else echo "  ✗ FAIL: $name"; fail=$((fail+1)); fi; }

# --- inner loop ---
run "typecheck"  npx tsc --noEmit
run "unit tests" bun test

# --- slow tier: build + drive the real CLI ---
if [ "$FULL" = "1" ]; then
  run "build" npx tsc

  cli_smoke() {
    local tmp out code
    tmp="$(mktemp -d)"
    mkdir -p "$tmp/bad" "$tmp/cwd"

    # known-bad home: scripts enabled, audit off
    printf 'audit=false\n' > "$tmp/bad/.npmrc"
    chmod 644 "$tmp/bad/.npmrc"

    out="$(cd "$tmp/cwd" && HOME="$tmp/bad" node "$OLDPWD/dist/cli.js" audit --json 2>&1)"
    code=$?
    rm -rf "$tmp"

    # must be valid JSON
    echo "$out" | node -e 'JSON.parse(require("fs").readFileSync(0,"utf8"))' || { echo "  not valid JSON: $out"; return 1; }
    # must exit 1 (critical/high present) and fire the script-execution rule
    [ "$code" = "1" ] || { echo "  expected exit 1, got $code"; return 1; }
    echo "$out" | grep -q '"ignore-scripts-disabled"' || { echo "  missing rule ignore-scripts-disabled"; return 1; }
    return 0
  }
  run "cli smoke (bad home → exit 1 + JSON)" cli_smoke
fi

echo
if [ "$fail" -eq 0 ]; then echo "✓ all checks passed"; else echo "✗ $fail check(s) failed"; exit 1; fi
