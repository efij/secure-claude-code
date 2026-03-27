#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
CONFIG_HOME="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config"
FILES_FILE="$CONFIG_HOME/instruction-files.regex"
TAMPER_FILE="$CONFIG_HOME/skill-tamper-phrases.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$FILES_FILE" ] || exit 0
[ -f "$TAMPER_FILE" ] || exit 0

if ! shield_match_pattern_file "$INPUT" "$FILES_FILE"; then
  exit 0
fi

if ! shield_match_pattern_file "$INPUT" "$TAMPER_FILE"; then
  exit 0
fi

shield_audit "skill-trust-boundary-tamper-guard" "block" "trusted instruction files contain prompt-override or guard-bypass language" "$INPUT"
printf '%s\n' '[runwall] blocked trust-boundary tampering in skill or command instructions' >&2
printf '%s\n' 'reason: the change adds classic prompt-override, jailbreak, or hook-bypass language into files that shape future agent behavior' >&2
printf '%s\n' 'next: keep skill and command docs narrow, local, and free of instruction-overwrite language' >&2
exit 2
