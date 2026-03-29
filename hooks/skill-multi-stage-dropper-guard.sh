#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

case "$INPUT" in
  *"SKILL.md"*|*"AGENTS.md"*|*"CLAUDE.md"*|*".claude/commands/"*)
    ;;
  *)
    exit 0
    ;;
esac

if printf '%s' "$INPUT" | grep -Eqi '(curl|wget|iwr|Invoke-WebRequest)[^[:cntrl:]]*(>|tee)[^[:cntrl:]]*(\.sh|\.ps1|/tmp/|Downloads)'; then
  :
elif printf '%s' "$INPUT" | grep -Eqi '(base64[[:space:]]+-d|certutil[[:space:]]+-decode)[^[:cntrl:]]*(>|tee)[^[:cntrl:]]*(\.sh|\.ps1|\.exe|\.dll)'; then
  :
elif printf '%s' "$INPUT" | grep -Eqi '(chmod[[:space:]]+\+x|powershell[[:space:]]+-enc|python[[:space:]]+-c|node[[:space:]]+-e)'; then
  :
else
  exit 0
fi

shield_audit "skill-multi-stage-dropper-guard" "block" "A trusted skill or instruction file now embeds a multi-stage fetch-save-execute chain" "$INPUT"
printf '%s\n' '[runwall] blocked multi-stage dropper instructions in a trusted skill or command doc' >&2
printf '%s\n' 'reason: the trusted instruction file now teaches the runtime how to fetch, stage, decode, or execute a second-stage payload' >&2
printf '%s\n' 'next: keep skills and command docs declarative, local, and free of staged downloader or decoder flows' >&2
exit 2
