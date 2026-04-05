#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
REGISTRY_FILE="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config/approved-registries.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$REGISTRY_FILE" ] || exit 0

if ! printf '%s\n' "$INPUT" | grep -Eqi '(^|[[:space:]])((npm|pnpm|yarn)[[:space:]]+(login|config[[:space:]]+set[[:space:]]+registry)|docker[[:space:]]+login|podman[[:space:]]+login|twine[[:space:]]+upload|poetry[[:space:]]+config[[:space:]]+repositories|pip[[:space:]]+config[[:space:]]+set[[:space:]]+global\.index-url|uv[[:space:]]+publish)'; then
  exit 0
fi

if ! printf '%s\n' "$INPUT" | grep -Eqi 'https?://|[A-Za-z0-9.-]+\.[A-Za-z]{2,}'; then
  exit 0
fi

if shield_match_pattern_file "$INPUT" "$REGISTRY_FILE"; then
  exit 0
fi

shield_audit "unexpected-registry-login-guard" "prompt" "login or registry reconfiguration targets an unreviewed host" "$INPUT"
shield_emit_metadata '{"prompt":{"review_required":true},"reason":"The command logs into or reconfigures a package registry outside the reviewed default set."}'
printf '%s\n' '[runwall] review required for unreviewed registry login' >&2
printf '%s\n' 'reason: the command points package or container credentials at a registry host that is not in the reviewed allowlist' >&2
printf '%s\n' 'next: keep credentials on approved registries or approve the target manually if the host is expected' >&2
exit 0
