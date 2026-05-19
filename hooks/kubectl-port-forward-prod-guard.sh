#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

if ! printf '%s\n' "$INPUT" | grep -Eqi '(^|[[:space:]])kubectl([^[:alnum:]]|$).*[[:space:]]port-forward([[:space:]]|$)'; then
  exit 0
fi

if ! printf '%s\n' "$INPUT" | grep -Eqi '(^|[[:space:]])(--context|--namespace|-n)(=|[[:space:]])[^[:space:]]*(prod|production|live|customer|billing|primary)|\b(prod|production|live|customer|billing|primary)([-_a-z0-9]*)\b'; then
  exit 0
fi

shield_audit "kubectl-port-forward-prod-guard" "block" "port-forward against a production-like Kubernetes target detected" "$INPUT"
printf '%s\n' '[stallion] blocked production Kubernetes port-forward' >&2
printf '%s\n' 'reason: the command opens local access into a production-like cluster target, which bypasses normal service boundaries' >&2
printf '%s\n' 'next: use reviewed diagnostics or a human-approved access path instead of direct port-forwarding into prod workloads' >&2
exit 2
