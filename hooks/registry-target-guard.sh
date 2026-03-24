#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
CONFIG_HOME="${SECURE_CLAUDE_CODE_HOME:-$HOME/.secure-claude-code}/config"
COMMAND_FILE="$CONFIG_HOME/registry-command-patterns.regex"
ALLOW_FILE="$CONFIG_HOME/registry-allowlist.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$COMMAND_FILE" ] || exit 0

if ! shield_match_pattern_file "$INPUT" "$COMMAND_FILE"; then
  exit 0
fi

if [ -f "$ALLOW_FILE" ] && shield_match_pattern_file "$INPUT" "$ALLOW_FILE"; then
  exit 0
fi

if printf '%s' "$INPUT" | grep -Eqi '(https?://|[[:space:]])([A-Za-z0-9.-]+\.[A-Za-z]{2,})([:/]|[[:space:]]|$)'; then
  shield_audit "registry-target-guard" "block" "unexpected registry target detected" "$INPUT"
  printf '%s\n' '[secure-claude-code] blocked unexpected registry target' >&2
  printf '%s\n' 'reason: the command publishes or logs in to a registry endpoint outside the default allowlist' >&2
  printf '%s\n' 'next: use an approved registry target or update the allowlist through review' >&2
  exit 2
fi

exit 0
