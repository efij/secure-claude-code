#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
CONFIG_HOME="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config"
SOURCES_FILE="$CONFIG_HOME/gateway-risky-sources.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

printf '%s' "$INPUT" | grep -q '"server_id"' || exit 0
[ -f "$SOURCES_FILE" ] || exit 0
shield_match_pattern_file "$INPUT" "$SOURCES_FILE" || exit 0

shield_audit "mcp-upstream-swap-guard" "block" "Gateway upstream definition points to an unreviewed source or scratch path" "$INPUT"
printf '%s\n' '[runwall] blocked risky MCP upstream source' >&2
printf '%s\n' 'reason: the inline gateway registry points an upstream server at a remote, sideloaded, or scratch location instead of a stable reviewed executable' >&2
printf '%s\n' 'next: pin the upstream to a reviewed local executable or source-controlled wrapper under a trusted path' >&2
exit 2
