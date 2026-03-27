#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
PATTERN_FILE="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config/tunnel-beacon-patterns.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

[ -f "$PATTERN_FILE" ] || exit 0

if ! printf '%s\n' "$INPUT" | grep -Eif "$PATTERN_FILE" >/dev/null 2>&1; then
  exit 0
fi

shield_audit "tunnel-beacon-guard" "block" "reverse tunnel or beaconing pattern detected" "$INPUT"
printf '%s\n' '[runwall] blocked tunnel or beacon setup' >&2
printf '%s\n' 'reason: the command creates an external access path or reverse tunnel that bypasses normal review boundaries' >&2
printf '%s\n' 'next: avoid exposing the environment through tunnels and move remote access into a reviewed infrastructure path' >&2
exit 2
