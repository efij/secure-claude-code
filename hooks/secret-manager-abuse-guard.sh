#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

if ! printf '%s\n' "$INPUT" | grep -Eqi '(^|[[:space:]])(op[[:space:]]+(read|item[[:space:]]+get|document[[:space:]]+get)|vault[[:space:]]+(kv[[:space:]]+get|read)|aws[[:space:]]+secretsmanager[[:space:]]+get-secret-value|gcloud[[:space:]]+secrets[[:space:]]+versions[[:space:]]+access|az[[:space:]]+keyvault[[:space:]]+secret[[:space:]]+show|pass[[:space:]]+show|security[[:space:]]+find-generic-password)'; then
  exit 0
fi

shield_audit "secret-manager-abuse-guard" "prompt" "live secret manager read detected" "$INPUT"
shield_emit_metadata '{"prompt":{"review_required":true},"reason":"The command reads live secret material from a secret manager or password vault."}'
printf '%s\n' '[runwall] review required for secret manager access' >&2
printf '%s\n' 'reason: the command pulls live secrets from a vault, secret manager, or password store into the current runtime' >&2
printf '%s\n' 'next: prefer reviewed secret injection paths and only approve interactive secret reads when a human intentionally needs them' >&2
exit 0
