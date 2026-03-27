#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
PATTERN_FILE="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config/publish-commands.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

[ -f "$PATTERN_FILE" ] || exit 0

if ! printf '%s\n' "$INPUT" | grep -Eif "$PATTERN_FILE" >/dev/null 2>&1; then
  exit 0
fi

shield_audit "package-publish-guard" "warn" "package or release publishing command detected" "$INPUT"
printf '%s\n' '[runwall] warning: publish command detected' >&2
printf '%s\n' 'reason: publishing pushes artifacts outside the local review boundary and should be deliberate' >&2
printf '%s\n' 'next: verify the package contents, version, changelog, and destination registry before continuing' >&2
exit 0
