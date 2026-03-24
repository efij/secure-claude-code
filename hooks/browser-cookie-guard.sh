#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
PATTERN_FILE="${SECURE_CLAUDE_CODE_HOME:-$HOME/.secure-claude-code}/config/browser-cookie-paths.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$PATTERN_FILE" ] || exit 0

if ! shield_match_pattern_file "$INPUT" "$PATTERN_FILE"; then
  exit 0
fi

if printf '%s' "$INPUT" | grep -Eqi '(cat|cp|copy|sqlite3|type|Get-Content|Select-String|grep|tar|zip|7z|Compress-Archive)'; then
  shield_audit "browser-cookie-guard" "block" "browser session store access detected" "$INPUT"
  printf '%s\n' '[secure-claude-code] blocked browser session store access' >&2
  printf '%s\n' 'reason: the command touches browser cookie or login stores that can contain active sessions' >&2
  printf '%s\n' 'next: use documented test credentials or synthetic profiles instead of live browser state' >&2
  exit 2
fi

exit 0
