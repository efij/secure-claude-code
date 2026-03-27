#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
PATTERN_FILE="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config/trusted-config-targets.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$PATTERN_FILE" ] || exit 0

if ! shield_match_pattern_file "$INPUT" "$PATTERN_FILE"; then
  exit 0
fi

if printf '%s' "$INPUT" | grep -Eqi '(^|[[:space:]])(ln[[:space:]]+-s|ln[[:space:]]+-sf|mklink|New-Item[[:space:]].*SymbolicLink)([[:space:]]|$)'; then
  shield_audit "trusted-config-symlink-guard" "block" "trusted config or policy target is being symlinked" "$INPUT"
  printf '%s\n' '[runwall] blocked trusted config symlink hijack' >&2
  printf '%s\n' 'reason: the command redirects a trusted config or policy file through a symlink instead of a normal reviewed file edit' >&2
  printf '%s\n' 'next: edit trusted files directly under source control instead of redirecting them to external or scratch locations' >&2
  exit 2
fi

exit 0
