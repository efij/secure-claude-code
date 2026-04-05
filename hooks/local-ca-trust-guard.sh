#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

if ! printf '%s\n' "$INPUT" | grep -Eqi '(security[[:space:]]+add-trusted-cert|update-ca-certificates|trust[[:space:]]+anchor|certutil[[:space:]]+-A|Import-Certificate([^[:alnum:]]|$).*Cert:\\\\LocalMachine\\\\Root|keytool[[:space:]]+-importcert([^[:alnum:]]|$).*(cacerts|truststore))'; then
  exit 0
fi

shield_audit "local-ca-trust-guard" "prompt" "local CA trust store modification detected" "$INPUT"
shield_emit_metadata '{"prompt":{"review_required":true},"reason":"The command adds a certificate to a local or system trust store."}'
printf '%s\n' '[runwall] review required for CA trust store change' >&2
printf '%s\n' 'reason: the command modifies a root or trust-anchor store, which can silently expand what the machine treats as trusted TLS or code-signing material' >&2
printf '%s\n' 'next: only approve reviewed certificates and prefer scoped trust where possible instead of changing the machine-wide root store' >&2
exit 0
