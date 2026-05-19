#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
REMOTE_FILE="${STALLION_HOME:-$HOME/.stallion}/config/approved-git-remotes.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$REMOTE_FILE" ] || exit 0

if ! printf '%s\n' "$INPUT" | grep -Eqi '(\.gitmodules|git[[:space:]]+submodule[[:space:]]+(add|set-url|sync))'; then
  exit 0
fi

if shield_match_pattern_file "$INPUT" "$REMOTE_FILE"; then
  exit 0
fi

shield_audit "git-submodule-source-swap-guard" "prompt" "git submodule source moved to an unreviewed host" "$INPUT"
shield_emit_metadata '{"prompt":{"review_required":true},"reason":"The change points a git submodule at an unreviewed remote host or URL."}'
printf '%s\n' '[stallion] review required for git submodule source swap' >&2
printf '%s\n' 'reason: the submodule source now points outside the reviewed forge set, which changes supply-chain trust' >&2
printf '%s\n' 'next: keep submodules on reviewed hosts or approve the new source manually if it is expected' >&2
exit 0
