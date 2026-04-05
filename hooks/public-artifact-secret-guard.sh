#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

if ! printf '%s\n' "$INPUT" | grep -Eqi '(^|[[:space:]])(cp|mv|rsync|install|tar|zip)([[:space:]]|$)'; then
  exit 0
fi

if ! printf '%s\n' "$INPUT" | grep -Eqi '(\.env|\.npmrc|\.pypirc|\.aws|\.ssh|id_rsa|id_ed25519|kubeconfig|credentials)'; then
  exit 0
fi

if ! printf '%s\n' "$INPUT" | grep -Eqi '(^|[[:space:][:punct:]])(public|dist|build|out|static|www|release|artifacts?)(/|[[:space:][:punct:]]|$)'; then
  exit 0
fi

shield_audit "public-artifact-secret-guard" "block" "secret material is being copied into a public or build artifact path" "$INPUT"
printf '%s\n' '[runwall] blocked secret material entering a public artifact path' >&2
printf '%s\n' 'reason: the command moves secret-bearing files into a build, release, static, or otherwise distributable directory' >&2
printf '%s\n' 'next: keep secrets outside artifact roots and inject them only at reviewed runtime boundaries' >&2
exit 2
