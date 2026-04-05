#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
REMOTE_FILE="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config/approved-git-remotes.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$REMOTE_FILE" ] || exit 0

if ! printf '%s\n' "$INPUT" | grep -Eqi '(^|[[:space:]])git[[:space:]]+remote[[:space:]]+(set-url|add)|(^|[[:space:]])git[[:space:]]+push[[:space:]]+(https?://|ssh://|git@)'; then
  exit 0
fi

if shield_match_pattern_file "$INPUT" "$REMOTE_FILE"; then
  exit 0
fi

shield_audit "git-remote-rewire-guard" "prompt" "git remote is being repointed to an unreviewed host" "$INPUT"
shield_emit_metadata '{"prompt":{"review_required":true},"reason":"The command changes or uses a git remote outside the reviewed host set."}'
printf '%s\n' '[runwall] review required for git remote rewire' >&2
printf '%s\n' 'reason: the command repoints git traffic to an unreviewed host or direct URL, which changes the code and credential trust boundary' >&2
printf '%s\n' 'next: keep remotes on reviewed hosts or approve the destination manually if a private forge is expected' >&2
exit 0
