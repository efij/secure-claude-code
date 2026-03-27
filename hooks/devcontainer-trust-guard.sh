#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
CONFIG_HOME="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config"
FILES_FILE="$CONFIG_HOME/devcontainer-trust-files.regex"
RISKY_FILE="$CONFIG_HOME/devcontainer-trust-risky.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$FILES_FILE" ] || exit 0
[ -f "$RISKY_FILE" ] || exit 0

if shield_match_pattern_file "$INPUT" "$FILES_FILE" && shield_match_pattern_file "$INPUT" "$RISKY_FILE"; then
  shield_audit "devcontainer-trust-guard" "block" "devcontainer trust-boundary weakening detected" "$INPUT"
  printf '%s\n' '[runwall] blocked risky devcontainer trust change' >&2
  printf '%s\n' 'reason: the command weakens devcontainer isolation or injects remote setup execution into the dev environment' >&2
  printf '%s\n' 'next: keep devcontainer changes minimal and reviewed, especially around mounts, privilege, and startup commands' >&2
  exit 2
fi

exit 0
