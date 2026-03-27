#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
CONFIG_HOME="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config"
FILES_FILE="$CONFIG_HOME/test-fixture-files.regex"
TOKEN_FILE="$CONFIG_HOME/live-token-patterns.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"

[ -f "$FILES_FILE" ] || exit 0
[ -f "$TOKEN_FILE" ] || exit 0

CLEAN_FILES_FILE="$(shield_prepare_pattern_file "$FILES_FILE")" || exit 1
CLEAN_TOKEN_FILE="$(shield_prepare_pattern_file "$TOKEN_FILE")" || exit 1
trap 'rm -f "$CLEAN_FILES_FILE" "$CLEAN_TOKEN_FILE"' EXIT

set +e
printf '%s\n' "$INPUT" | grep -Eif "$CLEAN_FILES_FILE" >/dev/null 2>&1
files_status=$?
set -e
if [ "$files_status" -eq 2 ]; then
  printf '%s\n' '[runwall] error: invalid test-fixture rule pattern' >&2
  exit 1
fi
if [ "$files_status" -ne 0 ]; then
  exit 0
fi

set +e
printf '%s\n' "$INPUT" | grep -Eif "$CLEAN_TOKEN_FILE" >/dev/null 2>&1
token_status=$?
set -e
if [ "$token_status" -eq 2 ]; then
  printf '%s\n' '[runwall] error: invalid live-token rule pattern' >&2
  exit 1
fi
if [ "$token_status" -ne 0 ]; then
  exit 0
fi

shield_audit "test-fixture-secret-guard" "block" "live tokens or secrets are being introduced into tests, fixtures, or snapshots" "$INPUT"
printf '%s\n' '[runwall] blocked secret in tests or fixtures' >&2
printf '%s\n' 'reason: the edit touches test data and contains a live token or private key pattern' >&2
printf '%s\n' 'next: replace it with a fake fixture value or a clearly redacted sample' >&2
exit 2
