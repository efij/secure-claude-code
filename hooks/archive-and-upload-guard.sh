#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
CONFIG_HOME="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config"
SECRET_PATHS_FILE="$CONFIG_HOME/secret-paths.regex"
SENSITIVE_SOURCES_FILE="$CONFIG_HOME/archive-sensitive-sources.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

has_archive=0
has_transfer=0

if printf '%s' "$INPUT" | grep -Eqi '(^|[[:space:]])(tar|zip|7z|7za|gzip|gunzip|bzip2|xz)([[:space:]]|$)|\.(zip|tar|tgz|gz|bz2|xz)'; then
  has_archive=1
fi

if printf '%s' "$INPUT" | grep -Eqi '(^|[[:space:]])(scp|sftp|ftp|rsync|rclone|nc|netcat|curl|wget|aws[[:space:]]+s3[[:space:]]+cp|gsutil[[:space:]]+cp)([[:space:]]|$)'; then
  has_transfer=1
fi

if [ "$has_archive" -eq 0 ] || [ "$has_transfer" -eq 0 ]; then
  exit 0
fi

sensitive_hits=''
if [ -f "$SECRET_PATHS_FILE" ]; then
  sensitive_hits="$(printf '%s\n' "$INPUT" | grep -Eiof "$SECRET_PATHS_FILE" | sort -u || true)"
fi

source_hits=''
if [ -f "$SENSITIVE_SOURCES_FILE" ]; then
  source_hits="$(printf '%s\n' "$INPUT" | grep -Eiof "$SENSITIVE_SOURCES_FILE" | sort -u || true)"
fi

if [ -z "$sensitive_hits" ] && [ -z "$source_hits" ]; then
  exit 0
fi

shield_audit "archive-and-upload-guard" "block" "archive creation is chained with a transfer of sensitive or high-value material" "$INPUT"
printf '%s\n' '[runwall] blocked archive-and-upload chain' >&2
printf '%s\n' 'reason: the command combines archiving with outbound transfer while referencing secret, repo-control, or dump material' >&2
if [ -n "$sensitive_hits" ]; then
  printf '%s\n' 'secret-related matches:' >&2
  printf '%s\n' "$sensitive_hits" | sed 's/^/  - /' >&2
fi
if [ -n "$source_hits" ]; then
  printf '%s\n' 'sensitive archive sources:' >&2
  printf '%s\n' "$source_hits" | sed 's/^/  - /' >&2
fi
printf '%s\n' 'next: create sanitized artifacts only, and move any reviewed transfer to a deliberate manual step' >&2
exit 2
