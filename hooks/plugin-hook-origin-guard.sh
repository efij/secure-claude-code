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

if ! printf '%s' "$INPUT" | grep -Eqi '"command"|[[:space:]](bash|sh|zsh|python|node|pwsh|powershell|cmd)([[:space:]]|$)'; then
  exit 0
fi

case "$INPUT" in
  *file://*|*/tmp/*|*/var/tmp/*|*/dev/shm/*|*Downloads/*|*AppData\\Local\\Temp\\*|*\\Users\\Public\\*)
    shield_audit "plugin-hook-origin-guard" "block" "plugin hook command points outside the plugin trust boundary" "$INPUT"
    printf '%s\n' '[runwall] blocked plugin hook origin outside plugin trust boundary' >&2
    printf '%s\n' 'reason: the plugin hook command points at temp, download, scratch, or other untrusted execution paths' >&2
    printf '%s\n' 'next: keep plugin hook commands under ${CLAUDE_PLUGIN_ROOT} or a reviewed repo-local path' >&2
    exit 2
    ;;
esac

exit 0
