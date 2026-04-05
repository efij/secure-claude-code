#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
TOKEN_FILE="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config/live-token-patterns.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$TOKEN_FILE" ] || exit 0

if ! printf '%s\n' "$INPUT" | grep -Eqi '(\.env\.(example|sample)|README|docs/|examples?/|demo/)'; then
  exit 0
fi

if ! shield_match_pattern_file "$INPUT" "$TOKEN_FILE" \
  && ! printf '%s\n' "$INPUT" | grep -Eqi '((DATABASE_URL|REDIS_URL|AMQP_URL|MONGODB_URI|POSTGRES_URL)[[:space:]]*[:=][[:space:]]*["'"'"'][^"'"'"']+["'"'"']|postgres(ql)?://[^[:space:]"]+:[^[:space:]"]+@|mysql://[^[:space:]"]+:[^[:space:]"]+@|mongodb(\+srv)?://[^[:space:]"]+:[^[:space:]"]+@|amqp://[^[:space:]"]+:[^[:space:]"]+@)'; then
  exit 0
fi

shield_audit "env-sample-secret-guard" "block" "real secret material is being written into sample or demo content" "$INPUT"
printf '%s\n' '[runwall] blocked real secret in sample content' >&2
printf '%s\n' 'reason: the example or sample file contains a live token or connection string instead of a fake or redacted placeholder' >&2
printf '%s\n' 'next: replace it with a clearly fake value or a documented secret reference pattern' >&2
exit 2
