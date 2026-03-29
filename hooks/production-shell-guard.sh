#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
PATTERN_FILE="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config/production-shell-patterns.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$PATTERN_FILE" ] || exit 0

if ! shield_match_pattern_file "$INPUT" "$PATTERN_FILE"; then
  exit 0
fi

if printf '%s' "$INPUT" | grep -Eqi '(kubectl.*exec.*(-it|-i).*(sh|bash|ash)|kubectl.*attach.*(-it|-i)|docker[[:space:]]+exec[[:space:]]+-it.*(sh|bash|ash))'; then
  shield_audit "production-shell-guard" "block" "interactive shell against a production-like target detected" "$INPUT"
  printf '%s\n' '[runwall] blocked production shell access' >&2
  printf '%s\n' 'reason: the command opens an interactive shell into a production-like workload or target' >&2
  printf '%s\n' 'next: use reviewed break-glass or incident workflows for prod shell access instead of autonomous agent execution' >&2
  exit 2
fi

exit 0
