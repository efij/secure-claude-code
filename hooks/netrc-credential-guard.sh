#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
PATTERN_FILE="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config/netrc-paths.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$PATTERN_FILE" ] || exit 0

if ! shield_match_pattern_file "$INPUT" "$PATTERN_FILE"; then
  exit 0
fi

if printf '%s' "$INPUT" | grep -Eqi '(^|[[:space:]])(cat|less|more|head|tail|cp|copy|tar|zip|7z|scp|sftp|curl|aws[[:space:]]+s3[[:space:]]+cp|jq|python[[:space:]]+-c|node[[:space:]]+-e)([[:space:]]|$)|"(path|file_path|filepath|filePath)"'; then
  shield_audit "netrc-credential-guard" "block" ".netrc credential material is being read or exported" "$INPUT"
  printf '%s\n' '[runwall] blocked .netrc credential access' >&2
  printf '%s\n' 'reason: the command targets machine credentials stored in .netrc or _netrc files' >&2
  printf '%s\n' 'next: avoid direct reads of .netrc material and rotate credentials through reviewed secret workflows instead' >&2
  exit 2
fi

exit 0
