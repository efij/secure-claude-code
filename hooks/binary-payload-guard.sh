#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
PATTERN_FILE="${SECURE_CLAUDE_CODE_HOME:-$HOME/.secure-claude-code}/config/binary-payload-patterns.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

[ -f "$PATTERN_FILE" ] || exit 0

if ! printf '%s\n' "$INPUT" | grep -Eif "$PATTERN_FILE" >/dev/null 2>&1; then
  exit 0
fi

if ! printf '%s' "$INPUT" | grep -Eqi '(curl|wget|Invoke-WebRequest|certutil|base64|openssl|chmod[[:space:]]+\+x|Start-Process|bash[[:space:]]|sh[[:space:]])'; then
  exit 0
fi

shield_audit "binary-payload-guard" "block" "downloaded or decoded binary payload looks ready for execution" "$INPUT"
printf '%s\n' '[secure-claude-code] blocked binary payload staging' >&2
printf '%s\n' 'reason: the command fetches or decodes an executable payload and appears to stage or run it locally' >&2
printf '%s\n' 'next: review the binary outside the agent workflow before any execution or install step' >&2
exit 2
