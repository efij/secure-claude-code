#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
CONFIG_HOME="${SECURE_CLAUDE_CODE_HOME:-$HOME/.secure-claude-code}/config"
FILES_FILE="$CONFIG_HOME/plugin-manifest-files.regex"
RISKY_FILE="$CONFIG_HOME/plugin-manifest-risky.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$FILES_FILE" ] || exit 0
[ -f "$RISKY_FILE" ] || exit 0

if shield_match_pattern_file "$INPUT" "$FILES_FILE" && shield_match_pattern_file "$INPUT" "$RISKY_FILE"; then
  shield_audit "plugin-manifest-guard" "block" "risky plugin or extension manifest source detected" "$INPUT"
  printf '%s\n' '[secure-claude-code] blocked risky plugin manifest source' >&2
  printf '%s\n' 'reason: the command adds an untrusted plugin or extension source through a manifest file' >&2
  printf '%s\n' 'next: keep plugin sources on reviewed repositories and avoid temp, raw, or sideloaded sources' >&2
  exit 2
fi

exit 0
