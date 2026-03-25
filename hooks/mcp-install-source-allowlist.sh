#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
CONFIG_HOME="${SECURE_CLAUDE_CODE_HOME:-$HOME/.secure-claude-code}/config"
ALLOW_FILE="$CONFIG_HOME/mcp-source-allowlist.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

if ! printf '%s' "$INPUT" | grep -Eqi '(mcp|plugin)'; then
  exit 0
fi

if ! printf '%s' "$INPUT" | grep -Eqi '(install|add|source|marketplace)'; then
  exit 0
fi

if [ -f "$ALLOW_FILE" ] && shield_match_pattern_file "$INPUT" "$ALLOW_FILE"; then
  exit 0
fi

case "$INPUT" in
  *http://*|*file://*|*/tmp/*|*Downloads/*|*AppData\\Local\\Temp\\*|*gist.githubusercontent.com*|*raw.githubusercontent.com*)
    ;;
  *)
    exit 0
    ;;
esac

shield_audit "mcp-install-source-allowlist" "block" "unapproved MCP or plugin install source detected" "$INPUT"
printf '%s\n' '[secure-claude-code] blocked unapproved MCP or plugin source' >&2
printf '%s\n' 'reason: the install source points at a raw, temp, or sideloaded location outside the current allowlist' >&2
printf '%s\n' 'next: use a reviewed repository or update the source allowlist through code review' >&2
exit 2
