#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
CONFIG_HOME="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config"
CONTROL_FILE="$CONFIG_HOME/security-control-files.regex"
TAMPER_FILE="$CONFIG_HOME/tamper-phrases.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

[ -f "$CONTROL_FILE" ] || exit 0
[ -f "$TAMPER_FILE" ] || exit 0

touches_control() {
  printf '%s\n' "$INPUT" | grep -Eif "$CONTROL_FILE" >/dev/null 2>&1
}

if ! touches_control; then
  exit 0
fi

if ! printf '%s\n' "$INPUT" | grep -Eif "$TAMPER_FILE" >/dev/null 2>&1; then
  exit 0
fi

shield_audit "config-tamper-guard" "block" "security control files are being weakened or broadly opened" "$INPUT"
printf '%s\n' '[runwall] blocked security-control tampering' >&2
printf '%s\n' 'reason: the edit targets a control file and includes patterns that commonly weaken hooks, permissions, or review boundaries' >&2
printf '%s\n' 'next: make the smallest reviewed change possible and avoid wildcard permissions, hook removal, or bypass-oriented text' >&2
exit 2
