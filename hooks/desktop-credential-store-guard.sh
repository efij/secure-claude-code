#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
PATTERN_FILE="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config/desktop-credential-store.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$PATTERN_FILE" ] || exit 0

if ! shield_match_pattern_file "$INPUT" "$PATTERN_FILE"; then
  exit 0
fi

shield_audit "desktop-credential-store-guard" "block" "desktop credential store access detected" "$INPUT"
printf '%s\n' '[runwall] blocked desktop credential store access' >&2
printf '%s\n' 'reason: the command touches OS-backed credential stores such as Keychain, libsecret, or Windows Credential Manager' >&2
printf '%s\n' 'next: keep workstation credential stores out of agent workflows and use scoped reviewed credentials instead' >&2
exit 2
