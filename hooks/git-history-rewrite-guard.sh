#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
PATTERN_FILE="${SECURE_CLAUDE_CODE_HOME:-$HOME/.secure-claude-code}/config/git-history-rewrite-patterns.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$PATTERN_FILE" ] || exit 0

if shield_match_pattern_file "$INPUT" "$PATTERN_FILE"; then
  shield_audit "git-history-rewrite-guard" "block" "broad git history rewrite detected" "$INPUT"
  printf '%s\n' '[secure-claude-code] blocked broad git history rewrite' >&2
  printf '%s\n' 'reason: the command rewrites or purges git history in a way that can destroy provenance or hide prior state' >&2
  printf '%s\n' 'next: use a reviewed manual recovery or migration process for history surgery' >&2
  exit 2
fi

exit 0
