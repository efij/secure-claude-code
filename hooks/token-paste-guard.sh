#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
PATTERN_FILE="${SECURE_CLAUDE_CODE_HOME:-$HOME/.secure-claude-code}/config/live-token-patterns.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

[ -f "$PATTERN_FILE" ] || exit 0

if ! printf '%s\n' "$INPUT" | grep -Eif "$PATTERN_FILE" >/dev/null 2>&1; then
  exit 0
fi

shield_audit "token-paste-guard" "block" "likely live token or private key material detected in tool input" "$INPUT"
printf '%s\n' '[secure-claude-code] blocked likely live token paste' >&2
printf '%s\n' 'reason: the input contains a high-confidence token or private key pattern' >&2
printf '%s\n' 'next: replace it with a fake value, a redacted sample, or an environment variable reference' >&2
exit 2
