#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

if ! printf '%s\n' "$INPUT" | grep -Eqi '(credential\.helper[[:space:]]+store|(^|[[:space:]])credsStore[[:space:]]*[:=][[:space:]]*["'"'"']?["'"'"']?|(^|[[:space:]])credHelpers[[:space:]]*[:=][[:space:]]*\{\}|keyring-provider[[:space:]]*[:=][[:space:]]*(disabled|subprocess)|password-store[[:space:]]*[:=][[:space:]]*false)'; then
  exit 0
fi

shield_audit "credential-helper-downgrade-guard" "block" "credential helper downgraded to plaintext or insecure storage" "$INPUT"
printf '%s\n' '[runwall] blocked credential helper downgrade' >&2
printf '%s\n' 'reason: the change disables a secure helper or falls back to plaintext credential storage' >&2
printf '%s\n' 'next: keep auth in reviewed keychains or broker-backed helpers instead of file-based or disabled secure storage' >&2
exit 2
