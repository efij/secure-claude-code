#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
CONFIG_HOME="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config"
FILES_FILE="$CONFIG_HOME/instruction-files.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$FILES_FILE" ] || exit 0

if ! shield_match_pattern_file "$INPUT" "$FILES_FILE"; then
  exit 0
fi

if printf '%s' "$INPUT" | grep -Eqi '(curl|wget|iwr|irm|Invoke-WebRequest)[^[:cntrl:]]*(\||&&|;)[^[:cntrl:]]*(bash|sh|zsh|pwsh|powershell)'; then
  :
elif printf '%s' "$INPUT" | grep -Eqi 'powershell[[:space:]]+-enc'; then
  :
elif printf '%s' "$INPUT" | grep -Eqi 'python[[:space:]]+-c'; then
  :
elif printf '%s' "$INPUT" | grep -Eqi 'node[[:space:]]+-e'; then
  :
elif printf '%s' "$INPUT" | grep -Eqi '(sh|bash)[[:space:]]+-c[^[:cntrl:]]*(curl|wget|iwr|irm|Invoke-WebRequest)'; then
  :
else
  exit 0
fi

shield_audit "skill-exec-chain-guard" "block" "trusted skill or command instructions embed dangerous execution chains" "$INPUT"
printf '%s\n' '[runwall] blocked dangerous skill execution chain' >&2
printf '%s\n' 'reason: the skill or Claude command text embeds download-and-execute or inline interpreter behavior that can be replayed later' >&2
printf '%s\n' 'next: keep skills and command docs reviewable, local, and free of inline fetch-and-exec patterns' >&2
exit 2
