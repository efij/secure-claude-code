#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
CONFIG_HOME="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config"
FILES_FILE="$CONFIG_HOME/git-hook-files.regex"
RISK_FILE="$CONFIG_HOME/git-hook-risky.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

[ -f "$FILES_FILE" ] || exit 0
[ -f "$RISK_FILE" ] || exit 0

if ! printf '%s\n' "$INPUT" | grep -Eif "$FILES_FILE" >/dev/null 2>&1; then
  exit 0
fi

if ! printf '%s\n' "$INPUT" | grep -Eif "$RISK_FILE" >/dev/null 2>&1; then
  exit 0
fi

shield_audit "git-hook-persistence-guard" "block" "git hook persistence path is being modified with risky execution behavior" "$INPUT"
printf '%s\n' '[runwall] blocked risky git hook persistence change' >&2
printf '%s\n' 'reason: the edit adds executable or network-capable behavior to a git hook persistence path' >&2
printf '%s\n' 'next: keep git hooks minimal, reviewed, and free of remote fetch or covert execution logic' >&2
exit 2
