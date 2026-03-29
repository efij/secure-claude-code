#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
PATTERN_FILE="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config/scheduled-task-patterns.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$PATTERN_FILE" ] || exit 0

if ! shield_match_pattern_file "$INPUT" "$PATTERN_FILE"; then
  exit 0
fi

shield_audit "scheduled-task-persistence-guard" "block" "scheduled task or service persistence detected" "$INPUT"
printf '%s\n' '[runwall] blocked scheduled task persistence' >&2
printf '%s\n' 'reason: the command creates or enables a recurring job, service, or launch item that can be abused for persistence' >&2
printf '%s\n' 'next: keep automation inside reviewed project tooling instead of OS-level task or service registration' >&2
exit 2
