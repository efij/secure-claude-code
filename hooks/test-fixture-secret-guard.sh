#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
CONFIG_HOME="${SECURE_CLAUDE_CODE_HOME:-$HOME/.secure-claude-code}/config"
FILES_FILE="$CONFIG_HOME/test-fixture-files.regex"
TOKEN_FILE="$CONFIG_HOME/live-token-patterns.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

[ -f "$FILES_FILE" ] || exit 0
[ -f "$TOKEN_FILE" ] || exit 0

set +e
printf '%s\n' "$INPUT" | grep -Eif "$FILES_FILE" >/dev/null 2>&1
files_status=$?
set -e
if [ "$files_status" -eq 2 ]; then
  printf '%s\n' '[secure-claude-code] error: invalid test-fixture rule pattern' >&2
  exit 1
fi
if [ "$files_status" -ne 0 ]; then
  exit 0
fi

set +e
printf '%s\n' "$INPUT" | grep -Eif "$TOKEN_FILE" >/dev/null 2>&1
token_status=$?
set -e
if [ "$token_status" -eq 2 ]; then
  printf '%s\n' '[secure-claude-code] error: invalid live-token rule pattern' >&2
  exit 1
fi
if [ "$token_status" -ne 0 ]; then
  exit 0
fi

shield_audit "test-fixture-secret-guard" "block" "live tokens or secrets are being introduced into tests, fixtures, or snapshots" "$INPUT"
printf '%s\n' '[secure-claude-code] blocked secret in tests or fixtures' >&2
printf '%s\n' 'reason: the edit touches test data and contains a live token or private key pattern' >&2
printf '%s\n' 'next: replace it with a fake fixture value or a clearly redacted sample' >&2
exit 2
