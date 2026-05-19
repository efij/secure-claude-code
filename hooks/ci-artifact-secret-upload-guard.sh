#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

if ! printf '%s\n' "$INPUT" | grep -Eqi '(upload-artifact|actions/upload-artifact|gh[[:space:]]+run[[:space:]]+upload-artifact|artifacts?:)'; then
  exit 0
fi

if ! printf '%s\n' "$INPUT" | grep -Eqi '(\.env|\.npmrc|\.pypirc|\.aws|\.ssh|id_rsa|id_ed25519|kubeconfig|credentials|secrets?)'; then
  exit 0
fi

shield_audit "ci-artifact-secret-upload-guard" "block" "secret-bearing file is being uploaded as a CI artifact" "$INPUT"
printf '%s\n' '[stallion] blocked secret-bearing CI artifact upload' >&2
printf '%s\n' 'reason: the artifact path includes environment, key, or credential material that should not be uploaded to CI storage' >&2
printf '%s\n' 'next: keep artifact uploads limited to reviewed build outputs and exclude secret-bearing files' >&2
exit 2
