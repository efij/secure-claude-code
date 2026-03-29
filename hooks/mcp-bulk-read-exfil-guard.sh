#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

printf '%s' "$INPUT" | grep -q '"arguments"' || exit 0
count="$(printf '%s' "$INPUT" | grep -Eo '(\.env|\.aws|\.ssh|id_rsa|kubeconfig|session\.json|credentials|known_hosts|secrets?(\.[A-Za-z0-9._-]+)?)' || true)"
count="$(printf '%s' "$count" | wc -l | tr -d ' ')"
[ "${count:-0}" -ge 2 ] || exit 0

shield_audit "mcp-bulk-read-exfil-guard" "prompt" "An MCP tool call is trying to bundle multiple sensitive read targets into one request" "$INPUT"
shield_emit_metadata '{"reason":"Multiple secret-like paths are being bundled into one MCP request.","prompt":{"review_required":true}}'
printf '%s\n' '[runwall] review required for bulk sensitive MCP read' >&2
printf '%s\n' 'reason: the tool call bundles multiple secret-like paths into one request, which looks more like collection or staging than a focused read' >&2
printf '%s\n' 'next: narrow the request to the smallest reviewed file set or approve it manually through the gateway if it is intentional' >&2
exit 0
