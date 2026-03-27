#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
TEST_PATHS_FILE="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config/test-paths.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

[ -f "$TEST_PATHS_FILE" ] || exit 0

test_hits="$(printf '%s\n' "$INPUT" | grep -Eif "$TEST_PATHS_FILE" || true)"
skip_hits="$(printf '%s\n' "$INPUT" | grep -Eo '(\.skip\(|\.only\(|xdescribe\(|xit\(|xtest\(|@pytest\.mark\.(skip|xfail)|pytest\.skip\(|unittest\.skip|describe\.only\(|test\.only\()' || true)"
disable_hits="$(printf '%s\n' "$INPUT" | grep -Eo '(eslint-disable|biome-ignore|@ts-ignore|@ts-expect-error|noqa|ruff:[[:space:]]*noqa|nolint|istanbul ignore|c8 ignore|coverage:[[:space:]]*ignore|type:[[:space:]]*ignore|pragma:[[:space:]]*no cover)' || true)"

if [ -z "$test_hits" ] && [ -z "$skip_hits" ] && [ -z "$disable_hits" ]; then
  exit 0
fi

shield_audit "protect-tests" "warn" "test-integrity warning emitted" "$INPUT"
printf '%s\n' '[runwall] warning: test integrity touched' >&2
printf '%s\n' 'reason: the change touches tests or uses a pattern that can silently weaken coverage' >&2
if [ -n "$test_hits" ]; then
  printf '%s\n' 'test-path matches:' >&2
  printf '%s\n' "$test_hits" | sed 's/^/  - /' >&2
fi
if [ -n "$skip_hits" ]; then
  printf '%s\n' 'skip or focus markers:' >&2
  printf '%s\n' "$skip_hits" | sed 's/^/  - /' >&2
fi
if [ -n "$disable_hits" ]; then
  printf '%s\n' 'security or quality suppression markers:' >&2
  printf '%s\n' "$disable_hits" | sed 's/^/  - /' >&2
fi
printf '%s\n' 'next: confirm test edits are intentional and re-run the affected test suite before merging' >&2
exit 0
