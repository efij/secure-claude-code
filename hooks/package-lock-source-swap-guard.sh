#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
REGISTRY_FILE="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config/approved-registries.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$REGISTRY_FILE" ] || exit 0

if ! printf '%s\n' "$INPUT" | grep -Eqi '(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb|poetry\.lock|uv\.lock|requirements\.txt|Pipfile\.lock|\.npmrc|\.yarnrc(\.yml)?)'; then
  exit 0
fi

if ! printf '%s\n' "$INPUT" | grep -Eqi 'https?://|[A-Za-z0-9.-]+\.[A-Za-z]{2,}'; then
  exit 0
fi

if shield_match_pattern_file "$INPUT" "$REGISTRY_FILE"; then
  exit 0
fi

shield_audit "package-lock-source-swap-guard" "prompt" "package source or lockfile points at an unreviewed host" "$INPUT"
shield_emit_metadata '{"prompt":{"review_required":true},"reason":"The package lock or source config now references an unreviewed registry or raw artifact host."}'
printf '%s\n' '[runwall] review required for package source swap' >&2
printf '%s\n' 'reason: the change rewires package resolution to an unreviewed registry or raw artifact host, which expands supply-chain risk' >&2
printf '%s\n' 'next: keep dependencies on reviewed registries or approve the host manually if a private source is expected' >&2
exit 0
