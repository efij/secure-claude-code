#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
PATTERN_FILE="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config/shell-profile-targets.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$PATTERN_FILE" ] || exit 0

if ! shield_match_pattern_file "$INPUT" "$PATTERN_FILE"; then
  exit 0
fi

if printf '%s' "$INPUT" | grep -Eqi '((curl|wget).*(\||>|>>).*(bash|sh|zsh|python|node|pwsh|powershell))|(base64[^[:space:]]*[[:space:]]*(-d|--decode).*(\||>|>>).*(bash|sh|zsh))|/tmp/|/var/tmp/|nohup|nc[[:space:]].*-e|python[[:space:]]+-c|node[[:space:]]+-e|powershell[[:space:]]+-enc|pwsh[[:space:]]+-enc'; then
  shield_audit "shell-profile-persistence-guard" "block" "suspicious persistence payload targets a shell profile" "$INPUT"
  printf '%s\n' '[runwall] blocked shell profile persistence' >&2
  printf '%s\n' 'reason: the change tries to stash suspicious execution logic inside a shell or PowerShell profile' >&2
  printf '%s\n' 'next: keep shell profiles for reviewed environment setup only and remove hidden execution or downloader payloads' >&2
  exit 2
fi

exit 0
