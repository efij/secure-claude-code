#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
PATTERN_FILE="${SECURE_CLAUDE_CODE_HOME:-$HOME/.secure-claude-code}/config/repo-harvest-risky.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

[ -f "$PATTERN_FILE" ] || exit 0

if ! printf '%s\n' "$INPUT" | grep -Eif "$PATTERN_FILE" >/dev/null 2>&1; then
  exit 0
fi

if ! printf '%s' "$INPUT" | grep -Eqi '(\.git|\.claude|\.github|src/|app/|lib/|>|>>|tee|tar|zip|scp|rsync|curl|wget|aws[[:space:]]+s3[[:space:]]+cp|gsutil[[:space:]]+cp)'; then
  exit 0
fi

shield_audit "repo-mass-harvest-guard" "block" "command pattern suggests bulk repo harvesting or packing for export" "$INPUT"
printf '%s\n' '[secure-claude-code] blocked bulk repo harvest pattern' >&2
printf '%s\n' 'reason: the command packages or enumerates large repo content in a way that looks ready for export or staging' >&2
printf '%s\n' 'next: narrow the scope to the minimum reviewed files instead of collecting the repo wholesale' >&2
exit 2
