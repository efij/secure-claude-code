#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
CONFIG_HOME="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config"
WEBHOOK_FILE="$CONFIG_HOME/webhook-sinks.regex"
TOKEN_FILE="$CONFIG_HOME/live-token-patterns.regex"
SECRET_FILE="$CONFIG_HOME/secret-paths.regex"
ARCHIVE_FILE="$CONFIG_HOME/archive-sensitive-sources.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$WEBHOOK_FILE" ] || exit 0

webhook_match="false"
case "$INPUT" in
  *discord.com/api/webhooks*|*hooks.slack.com/services*|*webhook.office.com*|*outlook.office.com/webhook*|*chat.googleapis.com/v1/spaces/*|*api.telegram.org/bot*)
    webhook_match="true"
    ;;
esac

if [ "$webhook_match" != "true" ] && ! shield_match_pattern_file "$INPUT" "$WEBHOOK_FILE"; then
  exit 0
fi

if shield_match_pattern_file "$INPUT" "$TOKEN_FILE" \
  || shield_match_pattern_file "$INPUT" "$SECRET_FILE" \
  || shield_match_pattern_file "$INPUT" "$ARCHIVE_FILE" \
  || printf '%s' "$INPUT" | grep -Eqi '(-F[[:space:]]+file=@|--data-binary|repo\.bundle|\.git/)'; then
  shield_audit "local-webhook-guard" "block" "webhook exfiltration path detected" "$INPUT"
  printf '%s\n' '[runwall] blocked webhook exfiltration path' >&2
  printf '%s\n' 'reason: the command sends sensitive or high-value data to a webhook-style endpoint' >&2
  printf '%s\n' 'next: remove the external sink and keep review artifacts inside approved channels' >&2
  exit 2
fi

exit 0
