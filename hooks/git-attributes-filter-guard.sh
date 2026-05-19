#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

if ! printf '%s\n' "$INPUT" | grep -Eqi '(\.gitattributes|git[[:space:]]+config[^[:cntrl:]]+filter\.)'; then
  exit 0
fi

if ! printf '%s\n' "$INPUT" | grep -Eqi '(filter\.[^.]+\.((clean|smudge|process)|required)|filter=[^[:space:]]+)'; then
  exit 0
fi

shield_audit "git-attributes-filter-guard" "block" "git attributes or config introduces command-driven filter hooks" "$INPUT"
printf '%s\n' '[stallion] blocked git filter hook injection' >&2
printf '%s\n' 'reason: the change adds smudge, clean, or process filters that execute automatically during git operations' >&2
printf '%s\n' 'next: keep git attributes declarative and avoid command-executing filters in unreviewed repos' >&2
exit 2
