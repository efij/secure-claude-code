#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
PATTERN_FILE="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config/ssh-authorized-keys-targets.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$PATTERN_FILE" ] || exit 0

if ! shield_match_pattern_file "$INPUT" "$PATTERN_FILE"; then
  exit 0
fi

if printf '%s' "$INPUT" | grep -Eqi '(ssh-copy-id|tee|Add-Content|Set-Content|Out-File|copy|cp|mv|install|sed[[:space:]]+-i|perl[[:space:]]+-pi|python[[:space:]]+-c|node[[:space:]]+-e|echo|printf|>>|>|Write-Output)'; then
  shield_audit "ssh-authorized-keys-guard" "block" "SSH authorized keys or daemon auth config is being changed" "$INPUT"
  printf '%s\n' '[runwall] blocked SSH authorization persistence' >&2
  printf '%s\n' 'reason: the command adds or rewrites SSH login trust material that can grant durable remote access' >&2
  printf '%s\n' 'next: review SSH access changes manually instead of allowing agent-driven key injection or daemon auth edits' >&2
  exit 2
fi

exit 0
