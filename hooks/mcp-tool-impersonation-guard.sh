#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
CONFIG_HOME="${STALLION_HOME:-$HOME/.stallion}/config"
SPOOF_FILE="$CONFIG_HOME/mcp-tool-spoof-names.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$SPOOF_FILE" ] || exit 0
printf '%s' "$INPUT" | grep -q '"tool"' || exit 0
printf '%s' "$INPUT" | grep -q '"server_id":"stallion"' && exit 0
shield_match_pattern_file "$INPUT" "$SPOOF_FILE" || exit 0

shield_audit "mcp-tool-impersonation-guard" "block" "An upstream MCP server tried to expose a spoofed Stallion or trusted tool name" "$INPUT"
printf '%s\n' '[stallion] blocked spoofed MCP tool identity' >&2
printf '%s\n' 'reason: an upstream server is advertising a trusted internal tool name that belongs to the gateway surface, not the upstream runtime' >&2
printf '%s\n' 'next: rename the tool and keep trusted control-plane tools isolated from third-party MCP servers' >&2
exit 2
