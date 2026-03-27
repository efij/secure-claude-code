#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
CONFIG_HOME="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config"
FILES_FILE="$CONFIG_HOME/dependency-script-files.regex"
RISK_FILE="$CONFIG_HOME/dependency-script-risky.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

[ -f "$FILES_FILE" ] || exit 0
[ -f "$RISK_FILE" ] || exit 0

if ! printf '%s\n' "$INPUT" | grep -Eif "$FILES_FILE" >/dev/null 2>&1; then
  exit 0
fi

if ! printf '%s\n' "$INPUT" | grep -Eif "$RISK_FILE" >/dev/null 2>&1; then
  exit 0
fi

shield_audit "dependency-script-guard" "block" "dependency metadata is adding install-time script execution or remote fetch behavior" "$INPUT"
printf '%s\n' '[runwall] blocked risky dependency script change' >&2
printf '%s\n' 'reason: dependency or package metadata now appears to execute code at install or build time in a risky way' >&2
printf '%s\n' 'next: remove install-time execution and keep dependency metadata free of remote command fetches' >&2
exit 2
