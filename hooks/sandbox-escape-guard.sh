#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
PATTERN_FILE="${SECURE_CLAUDE_CODE_HOME:-$HOME/.secure-claude-code}/config/sandbox-escape-patterns.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

[ -f "$PATTERN_FILE" ] || exit 0

if ! printf '%s\n' "$INPUT" | grep -Eif "$PATTERN_FILE" >/dev/null 2>&1; then
  exit 0
fi

shield_audit "sandbox-escape-guard" "block" "sandbox escape or host-boundary breakout pattern detected" "$INPUT"
printf '%s\n' '[secure-claude-code] blocked sandbox escape pattern' >&2
printf '%s\n' 'reason: the command references host mounts, namespace escape, or privileged runtime flags' >&2
printf '%s\n' 'next: keep execution inside the sandbox boundary and avoid host-level mounts or privilege escalation flags' >&2
exit 2
