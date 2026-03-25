#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

case "$INPUT" in
  *".vscode/extensions.json"*|*".cursor/extensions.json"*|*".claude-plugin/marketplace.json"*|*".claude-plugin/plugin.json"*|*"plugins.json"*)
    ;;
  *)
    exit 0
    ;;
esac

case "$INPUT" in
  *file://*|*.vsix*|*/tmp/*|*Downloads/*|*AppData\\Local\\Temp\\*|*gist.githubusercontent.com*|*pastebin.com*)
    shield_audit "plugin-manifest-guard" "block" "risky plugin or extension manifest source detected" "$INPUT"
    printf '%s\n' '[secure-claude-code] blocked risky plugin manifest source' >&2
    printf '%s\n' 'reason: the command adds an untrusted plugin or extension source through a manifest file' >&2
    printf '%s\n' 'next: keep plugin sources on reviewed repositories and avoid temp, raw, or sideloaded sources' >&2
    exit 2
    ;;
esac

exit 0
