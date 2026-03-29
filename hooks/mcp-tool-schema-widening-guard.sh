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

if printf '%s' "$INPUT" | grep -Eq '"additionalProperties"[[:space:]]*:[[:space:]]*true|"properties"[[:space:]]*:[[:space:]]*\{\}|"inputSchema"[[:space:]]*:[[:space:]]*\{"type":"object"\}'; then
  :
else
  exit 0
fi

shield_audit "mcp-tool-schema-widening-guard" "block" "A sensitive MCP tool widened to a free-form schema" "$INPUT"
printf '%s\n' '[runwall] blocked widened MCP tool schema' >&2
printf '%s\n' 'reason: a sensitive MCP tool now accepts broad unchecked input instead of a narrow reviewed schema' >&2
printf '%s\n' 'next: keep risky tool schemas explicit, small, and typed so the gateway can reason about what is being requested' >&2
exit 2
