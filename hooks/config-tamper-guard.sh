#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
CONFIG_HOME="${STALLION_HOME:-$HOME/.stallion}/config"
CONTROL_FILE="$CONFIG_HOME/security-control-files.regex"
TAMPER_FILE="$CONFIG_HOME/tamper-phrases.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

[ -f "$CONTROL_FILE" ] || exit 0
[ -f "$TAMPER_FILE" ] || exit 0

touches_control() {
  shield_match_file "$INPUT" "$CONTROL_FILE"
}

if ! touches_control; then
  exit 0
fi

if ! shield_match_file "$INPUT" "$TAMPER_FILE"; then
  exit 0
fi

shield_audit "config-tamper-guard" "block" "security control files are being weakened or broadly opened" "$INPUT"
printf '%s\n' '[stallion] blocked security-control tampering' >&2
printf '%s\n' 'reason: the edit targets a control file and includes patterns that commonly weaken hooks, permissions, or review boundaries' >&2
printf '%s\n' 'next: make the smallest reviewed change possible and avoid wildcard permissions, hook removal, or bypass-oriented text' >&2
exit 2
