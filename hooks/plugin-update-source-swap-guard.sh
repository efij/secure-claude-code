#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
CONFIG_HOME="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config"
FIELDS_FILE="$CONFIG_HOME/plugin-update-fields.regex"
SOURCES_FILE="$CONFIG_HOME/gateway-risky-sources.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$FIELDS_FILE" ] || exit 0
[ -f "$SOURCES_FILE" ] || exit 0
case "$INPUT" in
  *".claude-plugin/"*|*".codex-plugin/"*|*"plugin.json"*|*"marketplace.json"*|*"plugins.json"*)
    ;;
  *)
    exit 0
    ;;
esac

shield_match_pattern_file "$INPUT" "$FIELDS_FILE" || exit 0
shield_match_pattern_file "$INPUT" "$SOURCES_FILE" || exit 0

shield_audit "plugin-update-source-swap-guard" "block" "Plugin update metadata now points at a risky remote or scratch source" "$INPUT"
printf '%s\n' '[runwall] blocked risky plugin update source swap' >&2
printf '%s\n' 'reason: plugin update metadata now points at a raw, remote, or scratch-path source outside the reviewed release path' >&2
printf '%s\n' 'next: keep plugin updates pinned to reviewed repository or release URLs and avoid raw or sideloaded update channels' >&2
exit 2
