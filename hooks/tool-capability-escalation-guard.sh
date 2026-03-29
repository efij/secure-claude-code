#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
CONFIG_HOME="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config"
SENSITIVE_FILE="$CONFIG_HOME/mcp-sensitive-tool-names.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$SENSITIVE_FILE" ] || exit 0
printf '%s' "$INPUT" | grep -q '"tool"' || exit 0
shield_match_pattern_file "$INPUT" "$SENSITIVE_FILE" || exit 0

if printf '%s' "$INPUT" | grep -Eqi '(command|path|url|network|upload|download)'; then
  :
else
  exit 0
fi

if printf '%s' "$INPUT" | grep -Eq '"additionalProperties"[[:space:]]*:[[:space:]]*true|"properties"[[:space:]]*:[[:space:]]*\{'; then
  :
else
  exit 0
fi

shield_audit "tool-capability-escalation-guard" "block" "A tool definition now combines broad shell, file, or network reach" "$INPUT"
printf '%s\n' '[runwall] blocked broad MCP tool capability escalation' >&2
printf '%s\n' 'reason: the tool definition now mixes sensitive file, execution, or network capability in a way that widens the runtime blast radius' >&2
printf '%s\n' 'next: split the capability into smaller reviewed tools or narrow the schema and scope before exposing it through the gateway' >&2
exit 2
