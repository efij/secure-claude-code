#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
CONFIG_HOME="${STALLION_HOME:-$HOME/.stallion}/config"
PATTERNS_FILE="$CONFIG_HOME/mcp-response-prompt-smuggling.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$PATTERNS_FILE" ] || exit 0
printf '%s' "$INPUT" | grep -q '"tool_response"' || exit 0
shield_match_pattern_file "$INPUT" "$PATTERNS_FILE" || exit 0

shield_audit "mcp-response-prompt-smuggling-guard" "redact" "An upstream MCP response contains hidden prompt-injection or policy-override text" "$INPUT"
shield_emit_metadata '{"reason":"The upstream response contains hidden prompt-injection or policy-override text and should be redacted.","redactions":[{"type":"full-response","label":"prompt-smuggling"}]}'
printf '%s\n' '[stallion] redacting prompt-smuggling MCP response content' >&2
printf '%s\n' 'reason: the upstream response contains instruction-overwrite or developer-prompt bait that should not be passed through as trusted content' >&2
printf '%s\n' 'next: keep the response as data only, or review it manually in the gateway before exposing it to the runtime' >&2
exit 0
