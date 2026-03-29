#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

printf '%s' "$INPUT" | grep -q '"arguments"' || exit 0
shield_python "$(dirname "${BASH_SOURCE[0]}")/lib/egress_guard.py" class "$INPUT"
