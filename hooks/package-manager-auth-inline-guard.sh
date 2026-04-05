#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
TOKEN_FILE="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config/live-token-patterns.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$TOKEN_FILE" ] || exit 0

if ! printf '%s\n' "$INPUT" | grep -Eqi '(\.npmrc|\.yarnrc(\.yml)?|\.pypirc|pip\.conf|poetry\.toml|\.gem/credentials|config\.json)'; then
  exit 0
fi

if ! shield_match_pattern_file "$INPUT" "$TOKEN_FILE" \
  && ! printf '%s\n' "$INPUT" | grep -Eqi '(_authToken|npmAuthToken|(^|[[:space:]])password[[:space:]]*=|(^|[[:space:]])username[[:space:]]*=|(^|[[:space:]])auth[[:space:]]*=|\/\/[^[:space:]]+:_password=)' \
  && ! printf '%s\n' "$INPUT" | grep -Eq -- '-----BEGIN [A-Z ]+PRIVATE KEY-----'; then
  exit 0
fi

shield_audit "package-manager-auth-inline-guard" "block" "live package-manager credentials are being written inline" "$INPUT"
printf '%s\n' '[runwall] blocked inline package-manager credentials' >&2
printf '%s\n' 'reason: the edit writes live registry or package-manager credentials directly into local auth config' >&2
printf '%s\n' 'next: use a reviewed secret store or env-based credential flow instead of committing or echoing auth material into config files' >&2
exit 2
