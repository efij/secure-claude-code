#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

if ! printf '%s\n' "$INPUT" | grep -Eqi '(ProxyCommand|LocalCommand|PermitLocalCommand[[:space:]]+yes|ssh[[:space:]]+-o[[:space:]]*(ProxyCommand|LocalCommand)=)'; then
  exit 0
fi

shield_audit "ssh-proxycommand-guard" "block" "SSH ProxyCommand or LocalCommand execution hook detected" "$INPUT"
printf '%s\n' '[runwall] blocked SSH command-hook injection' >&2
printf '%s\n' 'reason: the change adds ProxyCommand or LocalCommand behavior, which creates covert execution and traffic redirection paths inside SSH flows' >&2
printf '%s\n' 'next: keep SSH config declarative and reviewed instead of adding command hooks that execute side effects or proxy chains' >&2
exit 2
