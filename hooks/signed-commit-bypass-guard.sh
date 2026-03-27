#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
CONFIG_HOME="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config"
FILES_FILE="$CONFIG_HOME/signed-commit-files.regex"
RISKY_FILE="$CONFIG_HOME/signed-commit-risky.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$FILES_FILE" ] || exit 0
[ -f "$RISKY_FILE" ] || exit 0

if shield_match_pattern_file "$INPUT" "$FILES_FILE" && shield_match_pattern_file "$INPUT" "$RISKY_FILE"; then
  shield_audit "signed-commit-bypass-guard" "block" "commit-signing or tag-signing bypass detected" "$INPUT"
  printf '%s\n' '[runwall] blocked signing bypass change' >&2
  printf '%s\n' 'reason: the command weakens git signing or verification settings that protect provenance' >&2
  printf '%s\n' 'next: keep signing enabled and update trust settings through a reviewed manual flow only' >&2
  exit 2
fi

exit 0
