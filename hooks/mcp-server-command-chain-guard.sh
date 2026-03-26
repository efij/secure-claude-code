#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
CONFIG_HOME="${SECURE_CLAUDE_CODE_HOME:-$HOME/.secure-claude-code}/config"
FILES_FILE="$CONFIG_HOME/mcp-server-files.regex"
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
elif printf '%s' "$INPUT" | grep -Eqi '(bash|sh)[^[:cntrl:]]+-c[^[:cntrl:]]*(curl|wget|iwr|irm|Invoke-WebRequest)'; then
  :
else
  exit 0
fi

shield_audit "mcp-server-command-chain-guard" "block" "MCP server definition embeds a dangerous execution chain" "$INPUT"
printf '%s\n' '[secure-claude-code] blocked dangerous MCP server execution chain' >&2
printf '%s\n' 'reason: the MCP server command uses download-and-execute or inline interpreter behavior instead of a stable reviewed binary' >&2
printf '%s\n' 'next: point MCP servers at a reviewed local executable or source-controlled wrapper instead of inline fetched code' >&2
exit 2
