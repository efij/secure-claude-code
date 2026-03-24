#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
PATTERN_FILE="${SECURE_CLAUDE_CODE_HOME:-$HOME/.secure-claude-code}/config/remote-script-drop-targets.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

[ -f "$PATTERN_FILE" ] || exit 0

if ! printf '%s' "$INPUT" | grep -Eqi '(curl|wget|Invoke-WebRequest|iwr|irm|fetch)'; then
  exit 0
fi

if ! printf '%s\n' "$INPUT" | grep -Eif "$PATTERN_FILE" >/dev/null 2>&1; then
  exit 0
fi

if ! printf '%s' "$INPUT" | grep -Eqi '(>|>>|tee|Out-File|Set-Content|Add-Content|chmod[[:space:]]+\+x|Start-Process|bash[[:space:]]|sh[[:space:]]|python[[:space:]])'; then
  exit 0
fi

shield_audit "remote-script-dropper-guard" "block" "remote content is being dropped as a script or executable payload" "$INPUT"
printf '%s\n' '[secure-claude-code] blocked remote script dropper behavior' >&2
printf '%s\n' 'reason: the command fetches remote content into a script or executable path and appears ready to persist or execute it' >&2
printf '%s\n' 'next: download the artifact manually, verify it out of band, and only then place a reviewed copy locally' >&2
exit 2
