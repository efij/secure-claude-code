#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
CONFIG_HOME="${SECURE_CLAUDE_CODE_HOME:-$HOME/.secure-claude-code}/config"
FILES_FILE="$CONFIG_HOME/plugin-trust-boundary-files.regex"
TAMPER_FILE="$CONFIG_HOME/plugin-trust-boundary-tamper.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

case "$INPUT" in
  *"hooks/hooks.json"*|*".claude-plugin/plugin.json"*|*".claude-plugin/marketplace.json"*|*"plugins.json"*|*"/plugin install"*|*"/plugin marketplace add"*)
    ;;
  *)
    exit 0
    ;;
esac

[ -f "$FILES_FILE" ] || exit 0
[ -f "$TAMPER_FILE" ] || exit 0

if ! shield_match_pattern_file "$INPUT" "$FILES_FILE"; then
  exit 0
fi

if ! shield_match_pattern_file "$INPUT" "$TAMPER_FILE"; then
  exit 0
fi

shield_audit "plugin-trust-boundary-tamper-guard" "block" "plugin attempts to tamper with Claude or Secure Claude Code trust boundaries" "$INPUT"
printf '%s\n' '[secure-claude-code] blocked plugin trust-boundary tampering' >&2
printf '%s\n' 'reason: the plugin tries to weaken Claude, MCP, or Secure Claude Code control files after install' >&2
printf '%s\n' 'next: keep plugins away from policy files, hook config, and trusted control surfaces unless the change is explicitly reviewed' >&2
exit 2
