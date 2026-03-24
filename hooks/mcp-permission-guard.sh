#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
CONFIG_HOME="${SECURE_CLAUDE_CODE_HOME:-$HOME/.secure-claude-code}/config"
CONTROL_FILE="$CONFIG_HOME/mcp-control-files.regex"
RISK_FILE="$CONFIG_HOME/mcp-risky-permissions.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

[ -f "$CONTROL_FILE" ] || exit 0
[ -f "$RISK_FILE" ] || exit 0

touches_mcp_control() {
  printf '%s\n' "$INPUT" | grep -Eif "$CONTROL_FILE" >/dev/null 2>&1
}

if ! touches_mcp_control; then
  exit 0
fi

if ! printf '%s\n' "$INPUT" | grep -Eif "$RISK_FILE" >/dev/null 2>&1; then
  exit 0
fi

shield_audit "mcp-permission-guard" "block" "broad or high-risk MCP permissions detected in a control-file change" "$INPUT"
printf '%s\n' '[secure-claude-code] blocked risky MCP permission change' >&2
printf '%s\n' 'reason: the change touches an MCP or tool control file and appears to grant wildcard or high-risk capabilities' >&2
printf '%s\n' 'next: reduce the permissions to the minimum required set and avoid wildcard grants or always-on shell/network/write access' >&2
exit 2
