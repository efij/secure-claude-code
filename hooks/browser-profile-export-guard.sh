#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
PATTERN_FILE="${SECURE_CLAUDE_CODE_HOME:-$HOME/.secure-claude-code}/config/browser-profile-paths.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$PATTERN_FILE" ] || exit 0

if ! shield_match_pattern_file "$INPUT" "$PATTERN_FILE"; then
  exit 0
fi

if printf '%s' "$INPUT" | grep -Eqi '(cp|copy|rsync|tar|zip|7z|Compress-Archive|scp|curl|aws[[:space:]]+s3[[:space:]]+cp)'; then
  shield_audit "browser-profile-export-guard" "block" "browser profile export detected" "$INPUT"
  printf '%s\n' '[secure-claude-code] blocked browser profile export' >&2
  printf '%s\n' 'reason: the command copies or archives a full browser profile that may contain sessions, cookies, and saved credentials' >&2
  printf '%s\n' 'next: use a test profile or synthetic fixture instead of a live browser profile' >&2
  exit 2
fi

exit 0
