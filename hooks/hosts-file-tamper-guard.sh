#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
PATTERN_FILE="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config/hosts-sensitive-domains.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$PATTERN_FILE" ] || exit 0

if ! printf '%s' "$INPUT" | grep -Eqi '(/etc/hosts\b|System32[/\\]drivers[/\\]etc[/\\]hosts\b)'; then
  exit 0
fi

if ! shield_match_pattern_file "$INPUT" "$PATTERN_FILE"; then
  exit 0
fi

if printf '%s' "$INPUT" | grep -Eqi '(tee|Add-Content|Set-Content|Out-File|copy|cp|mv|sed[[:space:]]+-i|perl[[:space:]]+-pi|echo|printf|>>|>)'; then
  shield_audit "hosts-file-tamper-guard" "block" "hosts file tampering targets trusted infrastructure domains" "$INPUT"
  printf '%s\n' '[runwall] blocked hosts file tampering' >&2
  printf '%s\n' 'reason: the change remaps high-trust infrastructure domains through the local hosts file' >&2
  printf '%s\n' 'next: use normal DNS and certificate trust paths instead of overriding trusted domains locally' >&2
  exit 2
fi

exit 0
