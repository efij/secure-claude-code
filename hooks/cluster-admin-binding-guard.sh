#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

if ! printf '%s\n' "$INPUT" | grep -Eqi '(ClusterRoleBinding|cluster-admin|roleRef:[^[:cntrl:]]+cluster-admin|kubectl[^[:cntrl:]]+(apply|create)[^[:cntrl:]]+clusterrolebinding)'; then
  exit 0
fi

shield_audit "cluster-admin-binding-guard" "block" "cluster-admin RBAC grant detected" "$INPUT"
printf '%s\n' '[runwall] blocked cluster-admin binding change' >&2
printf '%s\n' 'reason: the change creates or applies a cluster-admin style RBAC grant, which gives broad privileged access to the cluster' >&2
printf '%s\n' 'next: use the narrowest reviewed role possible instead of introducing cluster-wide admin rights' >&2
exit 2
