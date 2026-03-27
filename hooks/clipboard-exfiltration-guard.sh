#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
CONFIG_HOME="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config"
CLIPBOARD_FILE="$CONFIG_HOME/clipboard-commands.regex"
TOKEN_FILE="$CONFIG_HOME/live-token-patterns.regex"
SECRET_PATHS_FILE="$CONFIG_HOME/secret-paths.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"

[ -f "$CLIPBOARD_FILE" ] || exit 0

clipboard_match="false"
case "$INPUT" in
  *pbcopy*|*clip.exe*|*Set-Clipboard*|*xclip*|*xsel*|*wl-copy*)
    clipboard_match="true"
    ;;
esac

if [ "$clipboard_match" != "true" ]; then
  CLEAN_CLIPBOARD_FILE="$(shield_prepare_pattern_file "$CLIPBOARD_FILE")" || exit 1
  trap 'rm -f "${CLEAN_CLIPBOARD_FILE:-}" "${CLEAN_TOKEN_FILE:-}" "${CLEAN_SECRET_PATHS_FILE:-}"' EXIT
  if ! printf '%s\n' "$INPUT" | grep -Eif "$CLEAN_CLIPBOARD_FILE" >/dev/null 2>&1; then
    exit 0
  fi
else
  trap 'rm -f "${CLEAN_CLIPBOARD_FILE:-}" "${CLEAN_TOKEN_FILE:-}" "${CLEAN_SECRET_PATHS_FILE:-}"' EXIT
fi

if [ -f "$TOKEN_FILE" ]; then
  CLEAN_TOKEN_FILE="$(shield_prepare_pattern_file "$TOKEN_FILE")" || exit 1
fi
if [ -f "$SECRET_PATHS_FILE" ]; then
  CLEAN_SECRET_PATHS_FILE="$(shield_prepare_pattern_file "$SECRET_PATHS_FILE")" || exit 1
fi

if [ -n "${CLEAN_TOKEN_FILE:-}" ] && printf '%s\n' "$INPUT" | grep -Eif "$CLEAN_TOKEN_FILE" >/dev/null 2>&1; then
  :
elif [ -n "${CLEAN_SECRET_PATHS_FILE:-}" ] && printf '%s\n' "$INPUT" | grep -Eif "$CLEAN_SECRET_PATHS_FILE" >/dev/null 2>&1; then
  :
elif printf '%s' "$INPUT" | grep -Eqi '(printenv|gh[[:space:]]+auth[[:space:]]+token|gcloud[[:space:]]+auth[[:space:]]+print-access-token|aws[[:space:]]+configure[[:space:]]+export-credentials|kubectl[[:space:]]+config[[:space:]]+view[[:space:]]+--raw)'; then
  :
else
  exit 0
fi

shield_audit "clipboard-exfiltration-guard" "block" "secret or credential material is being copied to the clipboard" "$INPUT"
printf '%s\n' '[runwall] blocked clipboard exfiltration' >&2
printf '%s\n' 'reason: the command routes likely secrets or tokens into the system clipboard' >&2
printf '%s\n' 'next: keep secret handling out of clipboard flows and use redacted placeholders when sharing values' >&2
exit 2
