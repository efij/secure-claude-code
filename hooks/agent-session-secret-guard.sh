#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
PATTERN_FILE="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config/agent-session-paths.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$PATTERN_FILE" ] || exit 0

if ! shield_match_pattern_file "$INPUT" "$PATTERN_FILE"; then
  exit 0
fi

if printf '%s' "$INPUT" | grep -Eqi '(^|[[:space:]])(cat|less|more|head|tail|cp|copy|tar|zip|7z|scp|sftp|curl|aws[[:space:]]+s3[[:space:]]+cp|sqlite3|strings|jq)([[:space:]]|$)|"(path|file_path|filepath|filePath)"'; then
  shield_audit "agent-session-secret-guard" "block" "agent auth or session material is being read or exported" "$INPUT"
  printf '%s\n' '[runwall] blocked agent session credential access' >&2
  printf '%s\n' 'reason: the command targets local auth, token, or session stores used by coding agents' >&2
  printf '%s\n' 'next: avoid direct reads of agent auth stores and use reviewed login or token rotation flows instead' >&2
  exit 2
fi

exit 0
