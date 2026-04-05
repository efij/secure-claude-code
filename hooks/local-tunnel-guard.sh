#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

if ! printf '%s\n' "$INPUT" | grep -Eqi '(^|[[:space:]])(ngrok|cloudflared|lt|localtunnel|chisel|serveo|ssh)([[:space:]]|$)'; then
  exit 0
fi

if ! printf '%s\n' "$INPUT" | grep -Eqi '(http[[:space:]]+[0-9]{2,5}|tcp[[:space:]]+[0-9]{2,5}|tunnel([^[:alnum:]]|$)|--url[=[:space:]]|--hostname[=[:space:]]|--remote-addr[=[:space:]]|(^|[[:space:]])share([^[:alnum:]]|$)|(^|[[:space:]])-R[[:space:]])'; then
  exit 0
fi

shield_audit "local-tunnel-guard" "block" "local service exposure tunnel detected" "$INPUT"
printf '%s\n' '[runwall] blocked local tunnel exposure' >&2
printf '%s\n' 'reason: the command exposes a local port or service to an external endpoint through a tunnel or reverse-forward path' >&2
printf '%s\n' 'next: keep dev services local or use a reviewed infrastructure ingress path instead of ad hoc public tunnels' >&2
exit 2
