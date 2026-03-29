#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

printf '%s' "$INPUT" | grep -q '"tool_response"' || exit 0
if printf '%s' "$INPUT" | grep -Eqi '(TVqQAAMAAAAEAAAA|f0VMRg|UEsDB|#!/bin/(bash|sh))'; then
  :
else
  exit 0
fi

shield_audit "mcp-binary-dropper-guard" "redact" "An upstream MCP response looks like an executable, archive, or scripted second-stage payload" "$INPUT"
shield_emit_metadata '{"reason":"The upstream response looks like a binary or staged script payload and should be redacted.","redactions":[{"type":"full-response","label":"binary-payload"}]}'
printf '%s\n' '[runwall] redacting binary-like MCP response content' >&2
printf '%s\n' 'reason: the upstream response resembles an executable payload, archive, or staged script content rather than ordinary data' >&2
printf '%s\n' 'next: fetch reviewed artifacts outside the runtime and do not move binary payloads through normal tool-response channels' >&2
exit 0
