#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
CONFIG_HOME="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config"
PATTERN_FILE="$CONFIG_HOME/mass-delete-patterns.regex"
SAFE_FILE="$CONFIG_HOME/mass-delete-safe-paths.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$PATTERN_FILE" ] || exit 0

if ! shield_match_pattern_file "$INPUT" "$PATTERN_FILE"; then
  exit 0
fi

if [ -f "$SAFE_FILE" ] && shield_match_pattern_file "$INPUT" "$SAFE_FILE"; then
  exit 0
fi

shield_audit "mass-delete-guard" "block" "broad destructive delete pattern detected" "$INPUT"
printf '%s\n' '[runwall] blocked broad destructive delete' >&2
printf '%s\n' 'reason: the command removes a large path set outside the normal generated-file cleanup lanes' >&2
printf '%s\n' 'next: narrow the delete target or use a reviewed manual cleanup instead' >&2
exit 2
