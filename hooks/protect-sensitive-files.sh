#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
PATTERN_FILE="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config/protected-paths.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

[ -f "$PATTERN_FILE" ] || exit 0

matches=''
while IFS= read -r pattern; do
  [ -n "$pattern" ] || continue
  if printf '%s' "$INPUT" | grep -Eq "$pattern"; then
    matches="${matches}${pattern}"$'\n'
  fi
done <"$PATTERN_FILE"

if [ -n "$matches" ]; then
  shield_audit "protect-sensitive-files" "warn" "sensitive file category touched" "$INPUT"
  printf '%s\n' '[runwall] warning: sensitive file category touched' >&2
  printf '%s\n' 'reason: this edit may affect auth, deploy, dependency, or environment boundaries' >&2
  printf '%s' "$matches" | sed 's/^/  - matched rule: /' >&2
  printf '%s\n' 'next: review the diff carefully before commit or deploy' >&2
fi

exit 0
