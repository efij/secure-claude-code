#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

if printf '%s' "$INPUT" | grep -Eqi '(^|[[:space:]])(git[[:space:]]+rm|rm|del|erase|rmdir|Remove-Item)([[:space:]]|$)' &&
  printf '%s' "$INPUT" | grep -Eqi '((^|/|\\)(test|tests|__tests__|spec|specs)(/|\\)|(_test|_spec)\.|\.test\.|\.spec\.)'; then
  shield_audit "protect-tests" "block" "test deletion command detected" "$INPUT"
  printf '%s\n' '[runwall] blocked test deletion' >&2
  printf '%s\n' 'reason: the command appears to remove test files or test directories' >&2
  printf '%s\n' 'next: delete tests only as a reviewed manual change with explicit justification' >&2
  exit 2
fi

exit 0

