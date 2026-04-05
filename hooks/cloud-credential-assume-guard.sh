#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

if ! printf '%s\n' "$INPUT" | grep -Eqi '(^|[[:space:]])(aws[[:space:]]+sts[[:space:]]+assume-role|aws[[:space:]]+sts[[:space:]]+assume-role-with-web-identity|gcloud([^[:alnum:]]|$).*(--impersonate-service-account|workload-identity-pools[[:space:]]+create-cred-config)|az[[:space:]]+login([^[:alnum:]]|$).*--service-principal|az[[:space:]]+account[[:space:]]+get-access-token([^[:alnum:]]|$).*(--resource|--scope))'; then
  exit 0
fi

shield_audit "cloud-credential-assume-guard" "prompt" "cloud role assumption or service-account impersonation detected" "$INPUT"
shield_emit_metadata '{"prompt":{"review_required":true},"reason":"The command attempts to assume a cloud role or impersonate a service identity for fresh credentials."}'
printf '%s\n' '[runwall] review required for cloud credential assumption' >&2
printf '%s\n' 'reason: the command tries to assume a cloud role or impersonate a service account, which expands live cloud access in the current session' >&2
printf '%s\n' 'next: keep runtime access scoped to reviewed identities and approve impersonation only when it is explicitly required' >&2
exit 0
