#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
CONFIG_HOME="${SECURE_CLAUDE_CODE_HOME:-$HOME/.secure-claude-code}/config"
ALLOW_FILE="$CONFIG_HOME/skill-source-allowlist.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

if ! printf '%s' "$INPUT" | grep -Eqi '(/skill[[:space:]]+install|skill[[:space:]]+install)'; then
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

shield_audit "skill-install-source-guard" "block" "unapproved skill install source detected" "$INPUT"
printf '%s\n' '[secure-claude-code] blocked unapproved skill install source' >&2
printf '%s\n' 'reason: the skill install points at a raw, temp, or sideloaded location outside the reviewed allowlist' >&2
printf '%s\n' 'next: install skills from a reviewed repository path or update the skill allowlist through code review' >&2
exit 2
