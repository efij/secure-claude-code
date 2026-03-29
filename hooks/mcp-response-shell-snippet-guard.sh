#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

printf '%s' "$INPUT" | grep -q '"tool_response"' || exit 0
shield_python "$(dirname "${BASH_SOURCE[0]}")/lib/response_guard.py" shell "$INPUT"
