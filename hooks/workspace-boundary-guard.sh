#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
PATTERN_FILE="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config/external-boundary-paths.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

[ -f "$PATTERN_FILE" ] || exit 0

if ! shield_match_file "$INPUT" "$PATTERN_FILE"; then
  exit 0
fi

shield_audit "workspace-boundary-guard" "block" "tool input reaches outside normal workspace boundaries into system or deeply parent paths" "$INPUT"
printf '%s\n' '[runwall] blocked workspace-boundary escape' >&2
printf '%s\n' 'reason: the input references system paths or deep parent traversal outside normal workspace scope' >&2
printf '%s\n' 'next: copy only the minimum reviewed data into the workspace first, then operate on the local copy' >&2
exit 2
