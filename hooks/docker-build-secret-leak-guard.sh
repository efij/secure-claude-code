#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

if ! printf '%s\n' "$INPUT" | grep -Eqi '(^|[[:space:]])(docker|podman|nerdctl)([[:space:]]+buildx)?[[:space:]]+build([[:space:]]|$)'; then
  exit 0
fi

if ! printf '%s\n' "$INPUT" | grep -Eqi '(--build-arg[=[:space:]][^[:space:]]*(TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE_KEY|ACCESS_KEY|API_KEY)=|--secret([^[:alnum:]]|$).*(src=)?[^[:space:]]*(\.env|\.aws/credentials|id_rsa|id_ed25519|\.npmrc|\.pypirc|config\.json))'; then
  exit 0
fi

shield_audit "docker-build-secret-leak-guard" "block" "secret-bearing build input detected" "$INPUT"
printf '%s\n' '[runwall] blocked secret-bearing container build input' >&2
printf '%s\n' 'reason: the build command passes live secret material through build args or mounts secret files directly into the build context' >&2
printf '%s\n' 'next: switch to a reviewed secret mount flow or a redacted sample instead of embedding live credentials in the build invocation' >&2
exit 2
