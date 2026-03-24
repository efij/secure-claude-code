#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
CONFIG_HOME="${SECURE_CLAUDE_CODE_HOME:-$HOME/.secure-claude-code}/config"
TOKEN_FILE="$CONFIG_HOME/live-token-patterns.regex"
SECRET_FILE="$CONFIG_HOME/secret-paths.regex"
PATTERN_FILE="$CONFIG_HOME/dns-exfiltration-patterns.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

if ! printf '%s' "$INPUT" | grep -Eqi '(^|[[:space:]])(dig|nslookup|host|Resolve-DnsName|nsupdate)([[:space:]]|$)'; then
  exit 0
fi

if shield_match_pattern_file "$INPUT" "$TOKEN_FILE" \
  || shield_match_pattern_file "$INPUT" "$SECRET_FILE" \
  || shield_match_pattern_file "$INPUT" "$PATTERN_FILE"; then
  shield_audit "dns-exfiltration-guard" "block" "DNS-based exfiltration pattern detected" "$INPUT"
  printf '%s\n' '[secure-claude-code] blocked DNS exfiltration pattern' >&2
  printf '%s\n' 'reason: the command uses DNS tooling together with encoded or sensitive material' >&2
  printf '%s\n' 'next: keep secrets out of DNS lookups and use approved test domains with fake data only' >&2
  exit 2
fi

exit 0
