#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
CONFIG_HOME="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config"
PATTERNS_FILE="$CONFIG_HOME/mcp-response-secrets.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$PATTERNS_FILE" ] || exit 0
printf '%s' "$INPUT" | grep -q '"tool_response"' || exit 0

case "$INPUT" in
  *AWS_SECRET_ACCESS_KEY*|*ghp_*|*github_pat_*|*"PRIVATE KEY"* )
    ;;
  *)
    shield_match_pattern_file "$INPUT" "$PATTERNS_FILE" || exit 0
    ;;
esac

shield_audit "mcp-response-secret-leak-guard" "redact" "An upstream MCP response contains secret-like material that should not be returned raw" "$INPUT"
shield_emit_metadata '{"reason":"The upstream response contains secret-like material and should be redacted before it reaches the client.","redactions":[{"type":"full-response","label":"secret-material"}]}'
printf '%s\n' '[runwall] redacting secret-like MCP response content' >&2
printf '%s\n' 'reason: the upstream response contains credentials, token material, or private key content that should not be handed back to the runtime as-is' >&2
printf '%s\n' 'next: use fake data, a scoped redacted response, or a manual secret workflow instead of returning live secret material through the tool path' >&2
exit 0
