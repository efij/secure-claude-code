#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
CONFIG_HOME="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config"
SECRET_PATHS_FILE="$CONFIG_HOME/secret-paths.regex"
ALLOWLIST_FILE="$CONFIG_HOME/secret-allowlist.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

[ -f "$SECRET_PATHS_FILE" ] || exit 0

is_bash_like=0
if printf '%s' "$INPUT" | grep -Eqi '(^|[[:space:]])(cat|less|more|head|tail|grep|sed|awk|cp|tar|zip|unzip|base64|xxd|strings|find|rg|fd)([[:space:]]|$)'; then
  is_bash_like=1
fi

looks_like_read_request=0
if printf '%s' "$INPUT" | grep -Eqi '"(path|file_path|filepath|filePath)"|(^|[[:space:]])(~|/|\./|\.\./)'; then
  looks_like_read_request=1
fi

scan_sensitive_tokens() {
  local payload="${1:-}"
  local hits=''
  local raw=''
  local clean=''

  for raw in $(printf '%s\n' "$payload" | tr '\n' ' '); do
    clean="$(printf '%s' "$raw" | sed "s/^[\"'()\`\\[]*//; s/[\"'()\`\\],;]*$//")"
    [ -n "$clean" ] || continue
    case "$clean" in
      *://*) continue ;;
    esac
    if printf '%s\n' "$clean" | grep -Eif "$SECRET_PATHS_FILE" >/dev/null 2>&1; then
      hits="${hits}${clean}"$'\n'
    fi
  done

  if [ -n "$hits" ]; then
    printf '%s' "$hits" | sort -u
  fi
}

matches="$(scan_sensitive_tokens "$INPUT")"

if [ -s "$ALLOWLIST_FILE" ]; then
  filtered="$(printf '%s\n' "$matches" | grep -Ev -f "$ALLOWLIST_FILE" || true)"
else
  filtered="$matches"
fi

if [ -z "$filtered" ]; then
  exit 0
fi

if [ "$is_bash_like" -eq 1 ] || [ "$looks_like_read_request" -eq 1 ]; then
  :
else
  exit 0
fi

shield_audit "protect-secrets-read" "block" "sensitive secret-file access requested" "$INPUT"
printf '%s\n' '[runwall] blocked sensitive secret-file access' >&2
printf '%s\n' 'reason: the requested tool input references local credential or secret material' >&2
printf '%s\n' 'matched paths:' >&2
printf '%s\n' "$filtered" | sed 's/^/  - /' >&2
printf '%s\n' 'next: use redacted examples, environment variables, or add a narrow allowlist rule if this is intentional' >&2
exit 2
