#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
CONFIG_HOME="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config"
FILES_FILE="$CONFIG_HOME/ci-release-files.regex"
RISK_FILE="$CONFIG_HOME/ci-release-risky.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

[ -f "$FILES_FILE" ] || exit 0
[ -f "$RISK_FILE" ] || exit 0

if ! printf '%s\n' "$INPUT" | grep -Eif "$FILES_FILE" >/dev/null 2>&1; then
  exit 0
fi

if ! printf '%s\n' "$INPUT" | grep -Eif "$RISK_FILE" >/dev/null 2>&1; then
  exit 0
fi

shield_audit "ci-secret-release-guard" "block" "CI or release automation is being changed to expose secrets or widen release power" "$INPUT"
printf '%s\n' '[runwall] blocked risky CI or release change' >&2
printf '%s\n' 'reason: the edit would widen workflow trust, token exposure, or release privileges' >&2
printf '%s\n' 'next: keep workflow permissions narrow and avoid printing, inheriting, or uploading secret-backed release material' >&2
exit 2
