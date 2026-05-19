#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
PATTERN_FILE="${STALLION_HOME:-$HOME/.stallion}/config/publish-commands.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

[ -f "$PATTERN_FILE" ] || exit 0

if ! shield_match_file "$INPUT" "$PATTERN_FILE"; then
  exit 0
fi

shield_audit "package-publish-guard" "warn" "package or release publishing command detected" "$INPUT"
printf '%s\n' '[stallion] warning: publish command detected' >&2
printf '%s\n' 'reason: publishing pushes artifacts outside the local review boundary and should be deliberate' >&2
printf '%s\n' 'next: verify the package contents, version, changelog, and destination registry before continuing' >&2
exit 0
