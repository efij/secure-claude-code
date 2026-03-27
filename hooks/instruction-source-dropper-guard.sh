#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
CONFIG_HOME="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config"
FILES_FILE="$CONFIG_HOME/instruction-files.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$FILES_FILE" ] || exit 0

if ! shield_match_pattern_file "$INPUT" "$FILES_FILE"; then
  exit 0
fi

if ! printf '%s' "$INPUT" | grep -Eqi '(curl|wget|Invoke-WebRequest|iwr|irm|fetch)'; then
  exit 0
fi

if ! printf '%s' "$INPUT" | grep -Eqi '(>|>>|tee|Out-File|Set-Content|Add-Content|cp[[:space:]]|copy[[:space:]])'; then
  exit 0
fi

shield_audit "instruction-source-dropper-guard" "block" "remote content is being written directly into trusted instruction files" "$INPUT"
printf '%s\n' '[runwall] blocked remote instruction-file overwrite' >&2
printf '%s\n' 'reason: the command writes fetched content into AGENTS, CLAUDE, skill, or Claude command files that shape future agent behavior' >&2
printf '%s\n' 'next: review the content offline first and make minimal local edits instead of piping remote text into trusted instruction files' >&2
exit 2
