#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
CONFIG_HOME="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config"
FILES_FILE="$CONFIG_HOME/ssh-trust-files.regex"
RISK_FILE="$CONFIG_HOME/ssh-trust-downgrade.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$RISK_FILE" ] || exit 0

if [ -f "$FILES_FILE" ] && shield_match_pattern_file "$INPUT" "$FILES_FILE" && shield_match_pattern_file "$INPUT" "$RISK_FILE"; then
  shield_audit "ssh-trust-downgrade-guard" "block" "SSH trust configuration is being weakened" "$INPUT"
  printf '%s\n' '[runwall] blocked SSH trust downgrade' >&2
  printf '%s\n' 'reason: the change weakens host verification or known-host trust boundaries' >&2
  printf '%s\n' 'next: keep host key verification enabled and use reviewed host key management instead of disabling checks' >&2
  exit 2
fi

if shield_match_pattern_file "$INPUT" "$RISK_FILE"; then
  shield_audit "ssh-trust-downgrade-guard" "block" "SSH command disables host verification" "$INPUT"
  printf '%s\n' '[runwall] blocked SSH trust downgrade' >&2
  printf '%s\n' 'reason: the command disables host key verification or known-host checks' >&2
  printf '%s\n' 'next: connect with normal host verification and fix host trust issues instead of bypassing them' >&2
  exit 2
fi

exit 0
