#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

if ! printf '%s\n' "$INPUT" | grep -Eqi '(^|[[:space:]])(terraform|tofu|opentofu|terragrunt|pulumi)([[:space:]]+|.*[[:space:]])destroy([[:space:]]|$)'; then
  exit 0
fi

shield_audit "terraform-destroy-guard" "block" "destructive infra teardown detected" "$INPUT"
printf '%s\n' '[runwall] blocked destructive infrastructure teardown' >&2
printf '%s\n' 'reason: the command runs a destroy-style infrastructure action that can remove live resources and state' >&2
printf '%s\n' 'next: use a reviewed change plan or an explicit human-approved teardown workflow instead of direct destroy commands' >&2
exit 2
