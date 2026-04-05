#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

if ! printf '%s\n' "$INPUT" | grep -Eqi '(^|[[:space:]])(pg_dump|mysqldump|mongodump|redis-cli)([[:space:]]|$)'; then
  exit 0
fi

if ! printf '%s\n' "$INPUT" | grep -Eqi '(^|[[:space:]])(--host|-h|--uri|--db|--database|-d)(=|[[:space:]])[^[:space:]]*(prod|production|live|customer|billing|primary)|\b(prod|production|live|customer|billing|primary)([-_a-z0-9]*)\b'; then
  exit 0
fi

shield_audit "prod-db-dump-guard" "block" "production-like database dump or export detected" "$INPUT"
printf '%s\n' '[runwall] blocked production database dump' >&2
printf '%s\n' 'reason: the command attempts to dump or export a production-like data store, which can expose large amounts of customer or live data' >&2
printf '%s\n' 'next: use reviewed backup procedures or approved redacted snapshots instead of direct agent-driven dumps' >&2
exit 2
