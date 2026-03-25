#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
PATTERN_FILE="${SECURE_CLAUDE_CODE_HOME:-$HOME/.secure-claude-code}/config/release-key-patterns.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$PATTERN_FILE" ] || exit 0

if ! shield_match_pattern_file "$INPUT" "$PATTERN_FILE"; then
  exit 0
fi

if printf '%s' "$INPUT" | grep -Eqi '(cat|cp|copy|tar|zip|7z|scp|sftp|curl|aws[[:space:]]+s3[[:space:]]+cp|security[[:space:]]+export|gpg[[:space:]]+--export-secret-keys)'; then
  shield_audit "release-key-guard" "block" "release signing key access detected" "$INPUT"
  printf '%s\n' '[secure-claude-code] blocked release signing key access' >&2
  printf '%s\n' 'reason: the command reads or exports signing key material used for releases or package provenance' >&2
  printf '%s\n' 'next: keep release keys in reviewed key-management flows instead of local export paths' >&2
  exit 2
fi

exit 0
