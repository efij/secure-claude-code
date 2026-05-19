#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
PATTERN_FILE="${STALLION_HOME:-$HOME/.stallion}/config/sandbox-escape-patterns.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

[ -f "$PATTERN_FILE" ] || exit 0

if ! shield_match_file "$INPUT" "$PATTERN_FILE"; then
  exit 0
fi

shield_audit "sandbox-escape-guard" "block" "sandbox escape or host-boundary breakout pattern detected" "$INPUT"
printf '%s\n' '[stallion] blocked sandbox escape pattern' >&2
printf '%s\n' 'reason: the command references host mounts, namespace escape, or privileged runtime flags' >&2
printf '%s\n' 'next: keep execution inside the sandbox boundary and avoid host-level mounts or privilege escalation flags' >&2
exit 2
