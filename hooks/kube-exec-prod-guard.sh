#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

if ! printf '%s\n' "$INPUT" | grep -Eqi '(^|[[:space:]])kubectl([^[:alnum:]]|$).*[[:space:]](exec|attach|debug)([[:space:]]|$)'; then
  exit 0
fi

if ! printf '%s\n' "$INPUT" | grep -Eqi '(^|[[:space:]])(--context|--namespace|-n)(=|[[:space:]])[^[:space:]]*(prod|production|live|customer|billing|primary)|\b(prod|production|live|customer|billing|primary)([-_a-z0-9]*)\b'; then
  exit 0
fi

shield_audit "kube-exec-prod-guard" "block" "direct Kubernetes exec against a production-like target detected" "$INPUT"
printf '%s\n' '[runwall] blocked direct production Kubernetes exec' >&2
printf '%s\n' 'reason: the command opens an exec, attach, or debug session against a production-like cluster target' >&2
printf '%s\n' 'next: use reviewed read-only diagnostics or a human-approved break-glass workflow instead of direct agent shell access inside prod workloads' >&2
exit 2
