#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
CONFIG_HOME="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config"
PATTERNS_FILE="$CONFIG_HOME/mcp-parameter-smuggling.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$PATTERNS_FILE" ] || exit 0
printf '%s' "$INPUT" | grep -q '"arguments"' || exit 0
shield_match_pattern_file "$INPUT" "$PATTERNS_FILE" || exit 0

shield_audit "mcp-parameter-smuggling-guard" "block" "An MCP tool call payload looks like command or prompt smuggling instead of normal tool input" "$INPUT"
printf '%s\n' '[runwall] blocked smuggled MCP tool parameters' >&2
printf '%s\n' 'reason: the tool call payload contains encoded blobs, hidden prompt overrides, or inline execution chains that do not look like normal arguments' >&2
printf '%s\n' 'next: send only the minimum structured arguments the tool actually needs and move opaque blobs into reviewed local files if they are legitimate' >&2
exit 2
