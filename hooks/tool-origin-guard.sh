#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
CONFIG_HOME="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config"
FILES_FILE="$CONFIG_HOME/tool-origin-files.regex"
RISK_FILE="$CONFIG_HOME/tool-origin-risky.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

[ -f "$FILES_FILE" ] || exit 0
[ -f "$RISK_FILE" ] || exit 0

if ! printf '%s\n' "$INPUT" | grep -Eif "$FILES_FILE" >/dev/null 2>&1; then
  exit 0
fi

if ! printf '%s\n' "$INPUT" | grep -Eif "$RISK_FILE" >/dev/null 2>&1; then
  exit 0
fi

shield_audit "tool-origin-guard" "block" "tool or MCP origin looks untrusted or ephemeral" "$INPUT"
printf '%s\n' '[runwall] blocked risky tool origin' >&2
printf '%s\n' 'reason: the change points Claude tooling at an untrusted URL, temp path, or shell-wrapper origin' >&2
printf '%s\n' 'next: use a reviewed release source or a stable local binary path under source control' >&2
exit 2
