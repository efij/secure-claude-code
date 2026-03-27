#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

block() {
  shield_audit "block-dangerous-commands" "block" "$1" "$INPUT"
  printf '%s\n' '[runwall] blocked dangerous shell behavior' >&2
  printf 'reason: %s\n' "$1" >&2
  printf 'next: %s\n' "$2" >&2
  exit 2
}

if printf '%s' "$INPUT" | grep -Eq 'curl[^|]*\|[[:space:]]*(bash|sh|zsh)|wget[^|]*\|[[:space:]]*(bash|sh|zsh)'; then
  block \
    'remote script execution through a shell pipe is too risky' \
    'download the script, inspect it, then run it as a local file'
fi

if printf '%s' "$INPUT" | grep -Eqi '(powershell|pwsh).*((invoke-expression|iex).*(downloadstring|irm|invoke-webrequest)|-encodedcommand|-enc[[:space:]])'; then
  block \
    'PowerShell download-and-execute or encoded commands are too risky' \
    'expand the command, inspect the payload, and run only a reviewed local script'
fi

if printf '%s' "$INPUT" | grep -Eq 'chmod[[:space:]]+-R[[:space:]]+777'; then
  block \
    'recursive chmod 777 destroys useful file permission boundaries' \
    'use the narrowest chmod needed for the exact path'
fi

if printf '%s' "$INPUT" | grep -Eq 'rm[[:space:]]+-rf[[:space:]]+(\.git|~/.ssh|~/.aws|/etc/ssh|/var/lib)'; then
  block \
    'destructive delete targets a sensitive path' \
    'confirm the exact path and remove files manually with a narrower command'
fi

if printf '%s' "$INPUT" | grep -Eq 'sudo[[:space:]]+rm[[:space:]]+-rf[[:space:]]+/($|[[:space:]])'; then
  block \
    'root-level recursive delete would be catastrophic' \
    'stop and use a targeted cleanup command instead'
fi

if printf '%s' "$INPUT" | grep -Eqi '(^|[[:space:]])(del|erase|rmdir)[[:space:]]+(/s|/q|/f)'; then
  block \
    'Windows recursive delete flags can wipe large path trees too easily' \
    'use a narrower path and verify exactly what will be removed'
fi

exit 0
