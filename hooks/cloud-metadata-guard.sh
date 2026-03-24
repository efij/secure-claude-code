#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
PATTERN_FILE="${SECURE_CLAUDE_CODE_HOME:-$HOME/.secure-claude-code}/config/cloud-metadata-patterns.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

[ -f "$PATTERN_FILE" ] || exit 0

set +e
printf '%s\n' "$INPUT" | grep -Eif "$PATTERN_FILE" >/dev/null 2>&1
pattern_status=$?
set -e
if [ "$pattern_status" -eq 2 ]; then
  printf '%s\n' '[secure-claude-code] error: invalid cloud metadata rule pattern' >&2
  exit 1
fi
if [ "$pattern_status" -ne 0 ]; then
  exit 0
fi

shield_audit "cloud-metadata-guard" "block" "cloud metadata service access detected" "$INPUT"
printf '%s\n' '[secure-claude-code] blocked cloud metadata access' >&2
printf '%s\n' 'reason: the command targets instance metadata endpoints that commonly expose cloud credentials or identity context' >&2
printf '%s\n' 'next: use reviewed credentials or mocked metadata instead of reaching into instance metadata services' >&2
exit 2
