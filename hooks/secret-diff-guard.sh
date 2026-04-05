#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
TOKEN_FILE="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config/live-token-patterns.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$TOKEN_FILE" ] || exit 0

if printf '%s\n' "$INPUT" | grep -Eqi '(\.example|\.sample|README|docs/|examples?/|fixtures?/|tests?/)'; then
  exit 0
fi

if ! shield_match_pattern_file "$INPUT" "$TOKEN_FILE" \
  && ! printf '%s\n' "$INPUT" | grep -Eqi '((DATABASE_URL|REDIS_URL|AMQP_URL|MONGODB_URI|POSTGRES_URL)[[:space:]]*[:=][[:space:]]*["'"'"'][^"'"'"']+["'"'"']|postgres(ql)?://[^[:space:]"]+:[^[:space:]"]+@|mysql://[^[:space:]"]+:[^[:space:]"]+@|mongodb(\+srv)?://[^[:space:]"]+:[^[:space:]"]+@|amqp://[^[:space:]"]+:[^[:space:]"]+@|Authorization[[:space:]]*:[[:space:]]*Bearer[[:space:]]+[A-Za-z0-9._-]{16,})'; then
  exit 0
fi

shield_audit "secret-diff-guard" "block" "live secret or auth-bearing config content detected in edit input" "$INPUT"
printf '%s\n' '[runwall] blocked live secret entering the working diff' >&2
printf '%s\n' 'reason: the edit contains a live token, connection string, or bearer credential that should not be introduced into source files' >&2
printf '%s\n' 'next: replace it with a redacted sample or a secret reference before the change is written' >&2
exit 2
