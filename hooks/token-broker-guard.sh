#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

if ! printf '%s\n' "$INPUT" | grep -Eqi '(gh[[:space:]]+auth[[:space:]]+token|gcloud[[:space:]]+auth[[:space:]]+print-access-token|az[[:space:]]+account[[:space:]]+get-access-token|aws[[:space:]]+codeartifact[[:space:]]+get-authorization-token|oidc[^[:cntrl:]]+token|oauth[^[:cntrl:]]+/token|kinit([^[:alnum:]]|$)|security[[:space:]]+find-generic-password[[:space:]]+-w)'; then
  exit 0
fi

shield_audit "token-broker-guard" "prompt" "live token broker or delegated session minting flow detected" "$INPUT"
shield_emit_metadata '{"prompt":{"review_required":true},"reason":"The command requests a live access token or delegated session through a broker or auth helper."}'
printf '%s\n' '[runwall] review required for live token minting' >&2
printf '%s\n' 'reason: the command requests a fresh token or delegated session outside the current runtime trust boundary' >&2
printf '%s\n' 'next: prefer reviewed service identities or approve token issuance only when a human explicitly intends it' >&2
exit 0
