#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
reminders=''
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

if printf '%s' "$INPUT" | grep -Eq '\.(ts|tsx|js|jsx|mjs|cjs)\b'; then
  reminders="${reminders}  - JS/TS: run prettier or biome, then eslint"$'\n'
fi

if printf '%s' "$INPUT" | grep -Eq '\.py\b'; then
  reminders="${reminders}  - Python: run ruff format and ruff check"$'\n'
fi

if printf '%s' "$INPUT" | grep -Eq '\.(go)\b'; then
  reminders="${reminders}  - Go: run gofmt and go test ./..."$'\n'
fi

if printf '%s' "$INPUT" | grep -Eq '\.(rs)\b'; then
  reminders="${reminders}  - Rust: run cargo fmt and cargo clippy"$'\n'
fi

if [ -n "$reminders" ]; then
  shield_audit "post-edit-quality-reminder" "warn" "post-edit quality reminder emitted" "$INPUT"
  printf '%s\n' '[runwall] quality reminder' >&2
  printf '%s' "$reminders" >&2
fi

exit 0
