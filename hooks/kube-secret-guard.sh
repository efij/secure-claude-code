#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
PATTERN_FILE="${SECURE_CLAUDE_CODE_HOME:-$HOME/.secure-claude-code}/config/kube-secret-patterns.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$PATTERN_FILE" ] || exit 0

if ! printf '%s' "$INPUT" | grep -Eqi 'kubectl'; then
  exit 0
fi

if shield_match_pattern_file "$INPUT" "$PATTERN_FILE"; then
  shield_audit "kube-secret-guard" "block" "kubernetes secret access detected" "$INPUT"
  printf '%s\n' '[secure-claude-code] blocked kubernetes secret access' >&2
  printf '%s\n' 'reason: the command reads or mutates live Kubernetes secrets that may expose production credentials' >&2
  printf '%s\n' 'next: use approved secret-management workflows or fake manifests for local testing' >&2
  exit 2
fi

exit 0
