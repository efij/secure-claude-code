#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

case "$INPUT" in
  *"hooks/hooks.json"*|*".claude-plugin/plugin.json"*|*".claude-plugin/marketplace.json"*|*"plugins.json"*)
    ;;
  *)
    exit 0
    ;;
esac

if printf '%s' "$INPUT" | grep -Eqi '(SessionStart|SessionEnd|PreCompact|Notification|Stop|SubagentStop|UserPromptSubmit)' \
  && printf '%s' "$INPUT" | grep -Eqi '"type"[[:space:]]*:[[:space:]]*"command"'; then
  shield_audit "plugin-surface-expansion-guard" "block" "plugin expands into sensitive lifecycle command hooks" "$INPUT"
  printf '%s\n' '[secure-claude-code] blocked risky plugin surface expansion' >&2
  printf '%s\n' 'reason: the plugin adds command hooks on sensitive lifecycle events beyond normal narrow tool interception' >&2
  printf '%s\n' 'next: keep plugin hooks narrowly scoped and avoid command execution on broad session lifecycle events' >&2
  exit 2
fi

if printf '%s' "$INPUT" | grep -Eqi 'matcher[^[:cntrl:]]*(Read\|Write\|Edit\|MultiEdit\|Bash|Write\|Edit\|MultiEdit\|Bash)' \
  && printf '%s' "$INPUT" | grep -Eqi '(sh|bash)[[:space:]]+-c|python[[:space:]]+-c|node[[:space:]]+-e|powershell([[:space:]]+-enc|[[:space:]]+-Command)|cmd(\.exe)?[[:space:]]+/c'; then
  shield_audit "plugin-surface-expansion-guard" "block" "plugin widens coverage with broad mutation-plus-shell hooks" "$INPUT"
  printf '%s\n' '[secure-claude-code] blocked risky plugin surface expansion' >&2
  printf '%s\n' 'reason: the plugin combines broad mutation matchers with shell-wrapper execution in one command hook' >&2
  printf '%s\n' 'next: keep plugin hooks narrow and call stable local scripts directly instead of broad wrapper execution' >&2
  exit 2
fi

exit 0
