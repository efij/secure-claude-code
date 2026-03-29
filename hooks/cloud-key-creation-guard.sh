#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
PATTERN_FILE="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config/cloud-key-creation-patterns.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$PATTERN_FILE" ] || exit 0

if ! shield_match_pattern_file "$INPUT" "$PATTERN_FILE"; then
  exit 0
fi

shield_audit "cloud-key-creation-guard" "block" "cloud access key or service-account credential creation detected" "$INPUT"
printf '%s\n' '[runwall] blocked cloud key creation' >&2
printf '%s\n' 'reason: the command creates new long-lived cloud credentials or service-account key material' >&2
printf '%s\n' 'next: keep credential issuance inside manual approved IAM workflows instead of agent-driven shell actions' >&2
exit 2
