#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

if ! printf '%s\n' "$INPUT" | grep -Eqi '(^|[[:space:]])(google-chrome|chrome|chromium|chromium-browser|msedge|microsoft-edge|open[[:space:]]+-a[[:space:]]+"?Google Chrome"?)'; then
  exit 0
fi

if ! printf '%s\n' "$INPUT" | grep -Eqi '(^|[[:space:]])--remote-debugging-(port|pipe)(=|[[:space:]])'; then
  exit 0
fi

shield_audit "browser-remote-debug-guard" "block" "browser remote debugging launch detected" "$INPUT"
printf '%s\n' '[runwall] blocked browser remote debugging launch' >&2
printf '%s\n' 'reason: the command exposes browser devtools control and can leak live sessions, cookies, and authenticated page state' >&2
printf '%s\n' 'next: use reviewed browser automation paths that do not expose a live user profile over remote debugging' >&2
exit 2
