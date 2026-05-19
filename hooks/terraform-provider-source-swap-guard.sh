#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
PROVIDER_FILE="${STALLION_HOME:-$HOME/.stallion}/config/approved-terraform-provider-sources.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$PROVIDER_FILE" ] || exit 0

if ! printf '%s\n' "$INPUT" | grep -Eqi '(required_providers|provider[[:space:]]+"|source[[:space:]]*=|terraform[^[:cntrl:]]+init)'; then
  exit 0
fi

if shield_match_pattern_file "$INPUT" "$PROVIDER_FILE"; then
  exit 0
fi

shield_audit "terraform-provider-source-swap-guard" "prompt" "Terraform provider source moved to an unreviewed registry or namespace" "$INPUT"
shield_emit_metadata '{"prompt":{"review_required":true},"reason":"The provider source now points outside the reviewed Terraform/OpenTofu registry set."}'
printf '%s\n' '[stallion] review required for Terraform provider source swap' >&2
printf '%s\n' 'reason: the change rewires infrastructure providers to an unreviewed source, which shifts supply-chain trust' >&2
printf '%s\n' 'next: keep providers on reviewed registries or approve the new source manually if a private provider is expected' >&2
exit 0
