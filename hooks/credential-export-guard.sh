#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
PATTERN_FILE="${SECURE_CLAUDE_CODE_HOME:-$HOME/.secure-claude-code}/config/credential-export-commands.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

[ -f "$PATTERN_FILE" ] || exit 0

if ! printf '%s\n' "$INPUT" | grep -Eif "$PATTERN_FILE" >/dev/null 2>&1; then
  exit 0
fi

if ! printf '%s' "$INPUT" | grep -Eqi '(>|>>|tee|Out-File|Set-Content|Add-Content|curl|wget|scp|sftp|ftp|pbcopy|clip\.exe|Set-Clipboard|xclip|xsel|wl-copy)'; then
  exit 0
fi

shield_audit "credential-export-guard" "block" "credential material is being exported to a file, clipboard, or outbound channel" "$INPUT"
printf '%s\n' '[secure-claude-code] blocked credential export' >&2
printf '%s\n' 'reason: the command reads live credential material and then redirects, copies, or transfers it' >&2
printf '%s\n' 'next: use a reviewed manual credential flow instead of exporting secrets through tooling' >&2
exit 2
