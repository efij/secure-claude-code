#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
CONFIG_HOME="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config"
FILES_FILE="$CONFIG_HOME/artifact-target-files.regex"
RISKY_FILE="$CONFIG_HOME/artifact-risky.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$FILES_FILE" ] || exit 0
[ -f "$RISKY_FILE" ] || exit 0

if ! shield_match_pattern_file "$INPUT" "$FILES_FILE"; then
  exit 0
fi

if printf '%s' "$INPUT" | grep -Eq 'scripts/package-release\.sh|shasum[[:space:]]+-a[[:space:]]+256|sha256sum'; then
  exit 0
fi

if shield_match_pattern_file "$INPUT" "$RISKY_FILE"; then
  shield_audit "artifact-poisoning-guard" "block" "release artifact or checksum tampering detected" "$INPUT"
  printf '%s\n' '[runwall] blocked artifact or checksum tampering' >&2
  printf '%s\n' 'reason: the command edits release artifacts or checksum material outside the normal packaging flow' >&2
  printf '%s\n' 'next: regenerate release assets through the packaging script instead of editing them by hand' >&2
  exit 2
fi

exit 0
