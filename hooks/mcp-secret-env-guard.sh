#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
CONFIG_HOME="${SECURE_CLAUDE_CODE_HOME:-$HOME/.secure-claude-code}/config"
FILES_FILE="$CONFIG_HOME/mcp-server-files.regex"
ENV_FILE="$CONFIG_HOME/mcp-secret-env.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$FILES_FILE" ] || exit 0
[ -f "$ENV_FILE" ] || exit 0

if ! shield_match_pattern_file "$INPUT" "$FILES_FILE"; then
  exit 0
fi

if ! printf '%s' "$INPUT" | grep -Eqi '(\\"env\\"|"env"|env[[:space:]]*:)'; then
  exit 0
fi

if ! shield_match_pattern_file "$INPUT" "$ENV_FILE"; then
  exit 0
fi

shield_audit "mcp-secret-env-guard" "warn" "MCP config passes high-value secret environment variables into a server" "$INPUT"
printf '%s\n' '[secure-claude-code] warning: MCP server receives high-value secret env vars' >&2
printf '%s\n' 'reason: the MCP config forwards credentials or trust-boundary variables that can expand what the server can read or do' >&2
printf '%s\n' 'next: keep MCP env narrow, prefer scoped service credentials, and avoid passing workstation or cloud-wide secrets unless the server is fully reviewed' >&2
exit 0
