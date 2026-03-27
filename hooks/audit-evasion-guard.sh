#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
PATTERN_FILE="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config/audit-evasion-patterns.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$PATTERN_FILE" ] || exit 0

if ! shield_match_pattern_file "$INPUT" "$PATTERN_FILE"; then
  exit 0
fi

if printf '%s' "$INPUT" | grep -Eqi '(history[[:space:]]+-c|Clear-History|rm|del|erase|truncate|Set-Content|Clear-Content|wevtutil[[:space:]]+cl|journalctl[[:space:]]+--vacuum-time=0s)'; then
  shield_audit "audit-evasion-guard" "block" "audit or shell history clearing behavior detected" "$INPUT"
  printf '%s\n' '[runwall] blocked audit evasion behavior' >&2
  printf '%s\n' 'reason: the command clears shell history, event logs, or Runwall audit evidence' >&2
  printf '%s\n' 'next: keep audit trails intact and investigate why history or log deletion is being attempted' >&2
  exit 2
fi

exit 0
