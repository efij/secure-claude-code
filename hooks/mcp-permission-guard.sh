#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
CONFIG_HOME="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config"
CONTROL_FILE="$CONFIG_HOME/mcp-control-files.regex"
RISK_FILE="$CONFIG_HOME/mcp-risky-permissions.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

[ -f "$CONTROL_FILE" ] || exit 0
[ -f "$RISK_FILE" ] || exit 0

touches_mcp_control() {
  shield_match_file "$INPUT" "$CONTROL_FILE"
}

if ! touches_mcp_control; then
  exit 0
fi

if ! shield_match_file "$INPUT" "$RISK_FILE"; then
  exit 0
fi

shield_audit "mcp-permission-guard" "block" "broad or high-risk MCP permissions detected in a control-file change" "$INPUT"
printf '%s\n' '[runwall] blocked risky MCP permission change' >&2
printf '%s\n' 'reason: the change touches an MCP or tool control file and appears to grant wildcard or high-risk capabilities' >&2
printf '%s\n' 'next: reduce the permissions to the minimum required set and avoid wildcard grants or always-on shell/network/write access' >&2
exit 2
