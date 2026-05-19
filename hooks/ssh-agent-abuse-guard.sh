#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
PATTERN_FILE="${STALLION_HOME:-$HOME/.stallion}/config/ssh-agent-patterns.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

[ -f "$PATTERN_FILE" ] || exit 0

if ! shield_match_file "$INPUT" "$PATTERN_FILE"; then
  exit 0
fi

shield_audit "ssh-agent-abuse-guard" "block" "SSH agent forwarding or key-agent extraction pattern detected" "$INPUT"
printf '%s\n' '[stallion] blocked SSH agent abuse pattern' >&2
printf '%s\n' 'reason: the command exposes agent-backed keys or forwards agent access across trust boundaries' >&2
printf '%s\n' 'next: avoid agent forwarding and handle key use through a separate reviewed manual step' >&2
exit 2
