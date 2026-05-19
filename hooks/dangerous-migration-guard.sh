#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
FILES_FILE="${STALLION_HOME:-$HOME/.stallion}/config/migration-files.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

destructive=0

if printf '%s' "$INPUT" | grep -Eqi '(DROP[[:space:]]+TABLE|DROP[[:space:]]+DATABASE|TRUNCATE[[:space:]]+TABLE|DELETE[[:space:]]+FROM|ALTER[[:space:]]+TABLE[^[:cntrl:]]+DROP[[:space:]]+COLUMN|--accept-data-loss|db[[:space:]]+push[[:space:]]+--accept-data-loss|migrate[[:space:]]+reset|flyway[[:space:]]+clean|db:migrate:undo:all)'; then
  destructive=1
fi

if [ "$destructive" -eq 0 ]; then
  exit 0
fi

if [ -f "$FILES_FILE" ] && shield_match_file "$INPUT" "$FILES_FILE"; then
  :
elif printf '%s' "$INPUT" | grep -Eqi '(prisma|sequelize|alembic|flyway|liquibase|psql|mysql|sqlite3|db[[:space:]]+push|migrate)'; then
  :
else
  exit 0
fi

shield_audit "dangerous-migration-guard" "block" "destructive schema or data-loss migration behavior detected" "$INPUT"
printf '%s\n' '[stallion] blocked dangerous migration change' >&2
printf '%s\n' 'reason: the input contains destructive schema or data-loss patterns in a migration or database command' >&2
printf '%s\n' 'next: use additive migrations or handle destructive steps in a separately reviewed manual change' >&2
exit 2
