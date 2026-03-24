#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
CONFIG_HOME="${SECURE_CLAUDE_CODE_HOME:-$HOME/.secure-claude-code}/config"
CLIPBOARD_FILE="$CONFIG_HOME/clipboard-commands.regex"
TOKEN_FILE="$CONFIG_HOME/live-token-patterns.regex"
SECRET_PATHS_FILE="$CONFIG_HOME/secret-paths.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

[ -f "$CLIPBOARD_FILE" ] || exit 0

if ! printf '%s\n' "$INPUT" | grep -Eif "$CLIPBOARD_FILE" >/dev/null 2>&1; then
  exit 0
fi

if [ -f "$TOKEN_FILE" ] && printf '%s\n' "$INPUT" | grep -Eif "$TOKEN_FILE" >/dev/null 2>&1; then
  :
elif [ -f "$SECRET_PATHS_FILE" ] && printf '%s\n' "$INPUT" | grep -Eif "$SECRET_PATHS_FILE" >/dev/null 2>&1; then
  :
elif printf '%s' "$INPUT" | grep -Eqi '(printenv|gh[[:space:]]+auth[[:space:]]+token|gcloud[[:space:]]+auth[[:space:]]+print-access-token|aws[[:space:]]+configure[[:space:]]+export-credentials|kubectl[[:space:]]+config[[:space:]]+view[[:space:]]+--raw)'; then
  :
else
  exit 0
fi

shield_audit "clipboard-exfiltration-guard" "block" "secret or credential material is being copied to the clipboard" "$INPUT"
printf '%s\n' '[secure-claude-code] blocked clipboard exfiltration' >&2
printf '%s\n' 'reason: the command routes likely secrets or tokens into the system clipboard' >&2
printf '%s\n' 'next: keep secret handling out of clipboard flows and use redacted placeholders when sharing values' >&2
exit 2
