#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
PATTERN_FILE="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config/registry-credential-paths.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$PATTERN_FILE" ] || exit 0

if ! shield_match_pattern_file "$INPUT" "$PATTERN_FILE"; then
  exit 0
fi

if printf '%s' "$INPUT" | grep -Eqi '(^|[[:space:]])(cat|less|more|head|tail|cp|copy|tar|zip|7z|scp|sftp|curl|aws[[:space:]]+s3[[:space:]]+cp|jq|python[[:space:]]+-c|node[[:space:]]+-e)([[:space:]]|$)|"(path|file_path|filepath|filePath)"'; then
  shield_audit "registry-credential-guard" "block" "package or container registry credential material is being read or exported" "$INPUT"
  printf '%s\n' '[runwall] blocked registry credential access' >&2
  printf '%s\n' 'reason: the command targets package, container, or publish credentials stored in local config files' >&2
  printf '%s\n' 'next: keep registry auth in reviewed secret stores and avoid direct agent access to publish credentials' >&2
  exit 2
fi

exit 0
