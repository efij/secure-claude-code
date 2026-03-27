#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
PATTERN_FILE="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config/cloud-metadata-patterns.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"

[ -f "$PATTERN_FILE" ] || exit 0

case "$INPUT" in
  *169.254.169.254*|*metadata.google.internal*|*169.254.170.2*|*/latest/meta-data/*|*/metadata/instance*|*Metadata:true*|*computeMetadata/v1*)
    matched="true"
    ;;
  *)
    matched="false"
    ;;
esac

if [ "$matched" != "true" ]; then
CLEAN_PATTERN_FILE="$(shield_prepare_pattern_file "$PATTERN_FILE")" || exit 1
trap 'rm -f "$CLEAN_PATTERN_FILE"' EXIT

set +e
printf '%s\n' "$INPUT" | grep -Eif "$CLEAN_PATTERN_FILE" >/dev/null 2>&1
pattern_status=$?
set -e
if [ "$pattern_status" -eq 2 ]; then
  printf '%s\n' '[runwall] error: invalid cloud metadata rule pattern' >&2
  exit 1
fi
if [ "$pattern_status" -ne 0 ]; then
  exit 0
fi
fi

shield_audit "cloud-metadata-guard" "block" "cloud metadata service access detected" "$INPUT"
printf '%s\n' '[runwall] blocked cloud metadata access' >&2
printf '%s\n' 'reason: the command targets instance metadata endpoints that commonly expose cloud credentials or identity context' >&2
printf '%s\n' 'next: use reviewed credentials or mocked metadata instead of reaching into instance metadata services' >&2
exit 2
