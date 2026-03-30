#!/usr/bin/env bash
set -euo pipefail

EVENT="${1:-}"
MATCHER="${2:-}"
INPUT="${3:-}"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

shield_python "$(dirname "${BASH_SOURCE[0]}")/../scripts/runwall_context_chain_hook.py" "$EVENT" "$MATCHER" "$INPUT"
