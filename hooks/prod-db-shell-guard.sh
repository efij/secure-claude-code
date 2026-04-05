#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

if ! printf '%s\n' "$INPUT" | grep -Eqi '(^|[[:space:]])(psql|mysql|mongosh|mongo|redis-cli|sqlcmd|snowsql|clickhouse-client)([[:space:]]|$)'; then
  exit 0
fi

if ! printf '%s\n' "$INPUT" | grep -Eqi '(^|[[:space:]])(--host|-h|--uri|--database|-d|--cluster|--instance)([=[:space:]])[^[:space:]]*(prod|production|live|primary|customer|billing)|\b(prod|production|live|primary|customer|billing)([-_a-z0-9]*)\b'; then
  exit 0
fi

shield_audit "prod-db-shell-guard" "block" "direct production database shell access detected" "$INPUT"
printf '%s\n' '[runwall] blocked direct production database shell access' >&2
printf '%s\n' 'reason: the command opens an interactive database client against what looks like a production or customer-data target' >&2
printf '%s\n' 'next: use reviewed read-only access paths or a human-approved break-glass workflow instead of direct agent shell access' >&2
exit 2
