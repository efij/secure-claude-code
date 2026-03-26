#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

case "$INPUT" in
  *"hooks/hooks.json"*|*".claude-plugin/plugin.json"*|*".claude-plugin/marketplace.json"*|*"plugins.json"*)
    ;;
  *)
    exit 0
    ;;
esac

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

shield_audit "plugin-exec-chain-guard" "block" "plugin command embeds a dangerous execution chain" "$INPUT"
printf '%s\n' '[secure-claude-code] blocked dangerous plugin execution chain' >&2
printf '%s\n' 'reason: the plugin command embeds download-and-execute or inline interpreter execution behavior' >&2
printf '%s\n' 'next: keep plugin commands simple, local, and reviewable instead of fetching or evaluating code inline' >&2
exit 2
