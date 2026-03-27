#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
CONFIG_HOME="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config"
SECRET_PATHS_FILE="$CONFIG_HOME/secret-paths.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

[ -f "$SECRET_PATHS_FILE" ] || exit 0

has_transfer=0
if printf '%s' "$INPUT" | grep -Eqi '(^|[[:space:]])(scp|sftp|ftp|rsync|rclone|nc|netcat|curl|wget|aws[[:space:]]+s3[[:space:]]+cp|gsutil[[:space:]]+cp)([[:space:]]|$)'; then
  has_transfer=1
fi

if [ "$has_transfer" -eq 0 ]; then
  exit 0
fi

if ! printf '%s' "$INPUT" | grep -Eqi '(-T|--upload-file|-F|--form|--data|--data-binary|-X[[:space:]]+POST|:[^[:space:]]|s3://|gs://)'; then
  exit 0
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

sensitive_hits="$(scan_sensitive_tokens "$INPUT")"
archive_hits="$(printf '%s\n' "$INPUT" | grep -Eo '([^[:space:]]+\.(sql|sqlite3?|db|dump|bak|backup|zip|tar|tgz|gz))' || true)"

if [ -z "$sensitive_hits" ] && [ -z "$archive_hits" ]; then
  exit 0
fi

shield_audit "network-exfiltration" "block" "suspicious outbound transfer with sensitive material" "$INPUT"
printf '%s\n' '[runwall] blocked suspicious outbound transfer' >&2
printf '%s\n' 'reason: a network transfer command appears to include secret or database material' >&2
if [ -n "$sensitive_hits" ]; then
  printf '%s\n' 'sensitive matches:' >&2
  printf '%s\n' "$sensitive_hits" | sed 's/^/  - /' >&2
fi
if [ -n "$archive_hits" ]; then
  printf '%s\n' 'archive or dump matches:' >&2
  printf '%s\n' "$archive_hits" | sed 's/^/  - /' >&2
fi
printf '%s\n' 'next: remove the sensitive paths, use a sanitized artifact, or move the transfer to a reviewed manual step' >&2
exit 2
