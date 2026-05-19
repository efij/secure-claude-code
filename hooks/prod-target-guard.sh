#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
PATTERN_FILE="${STALLION_HOME:-$HOME/.stallion}/config/prod-targets.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

[ -f "$PATTERN_FILE" ] || exit 0

if ! shield_match_file "$INPUT" "$PATTERN_FILE"; then
  exit 0
fi

if ! printf '%s' "$INPUT" | grep -Eqi '(terraform[^[:cntrl:]]+apply|kubectl[^[:cntrl:]]+(apply|delete|scale|rollout|patch)|helm[^[:cntrl:]]+upgrade|wrangler[^[:cntrl:]]+deploy|fly[^[:cntrl:]]+deploy|vercel[^[:cntrl:]]+--prod|docker[^[:cntrl:]]+service[^[:cntrl:]]+update|railway[^[:cntrl:]]+up)'; then
  exit 0
fi

shield_audit "prod-target-guard" "block" "direct mutation against a production-like target detected" "$INPUT"
printf '%s\n' '[stallion] blocked direct production-target command' >&2
printf '%s\n' 'reason: the command targets a production-like environment with a mutating deploy or infrastructure action' >&2
printf '%s\n' 'next: move this step into a reviewed deployment path instead of running it directly through the agent' >&2
exit 2
