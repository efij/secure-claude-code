#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
PATTERN_FILE="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config/git-credential-store-patterns.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$PATTERN_FILE" ] || exit 0

if ! shield_match_pattern_file "$INPUT" "$PATTERN_FILE"; then
  exit 0
fi

if printf '%s' "$INPUT" | grep -Eqi '(credential\.helper[[:space:]]+store|git[[:space:]]+credential[[:space:]]+fill|(cat|less|more|head|tail|cp|copy|tar|zip|7z|scp|sftp|curl|aws[[:space:]]+s3[[:space:]]+cp|jq|python[[:space:]]+-c|node[[:space:]]+-e)[[:space:]])'; then
  shield_audit "git-credential-store-guard" "block" "git credential store access or enablement detected" "$INPUT"
  printf '%s\n' '[runwall] blocked git credential store access' >&2
  printf '%s\n' 'reason: the command reads stored git credentials or enables plaintext credential storage' >&2
  printf '%s\n' 'next: keep git auth in reviewed keychains or credential brokers instead of plaintext credential stores' >&2
  exit 2
fi

exit 0
