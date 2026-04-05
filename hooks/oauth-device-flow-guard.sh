#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

if ! printf '%s\n' "$INPUT" | grep -Eqi '(^|[[:space:]])(gh[[:space:]]+auth[[:space:]]+login([^[:alnum:]]|$).*--web|az[[:space:]]+login([^[:alnum:]]|$).*--use-device-code|gcloud[[:space:]]+auth[[:space:]]+login([^[:alnum:]]|$).*--no-launch-browser|aws[[:space:]]+sso[[:space:]]+login|oauth/device/code|device/code|github\.com/login/device|microsoft\.com/devicelogin)'; then
  exit 0
fi

shield_audit "oauth-device-flow-guard" "prompt" "delegated OAuth device login flow detected" "$INPUT"
shield_emit_metadata '{"prompt":{"review_required":true},"reason":"The command starts a browserless or device-code login flow that can mint delegated user access."}'
printf '%s\n' '[runwall] review required for delegated device login flow' >&2
printf '%s\n' 'reason: the command starts a browserless OAuth or device-code flow that can create fresh user access outside the normal runtime trust boundary' >&2
printf '%s\n' 'next: use a reviewed service identity or approve the flow manually if a human login is really intended' >&2
exit 0
