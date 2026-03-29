#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
CONFIG_HOME="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config"
PATTERNS_FILE="$CONFIG_HOME/instruction-override-bridge.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$PATTERNS_FILE" ] || exit 0
case "$INPUT" in
  *"SKILL.md"*|*"AGENTS.md"*|*"CLAUDE.md"*|*".claude/commands/"*|*".mcp.json"*|*"gateway.json"*)
    ;;
  *)
    exit 0
    ;;
esac

shield_match_pattern_file "$INPUT" "$PATTERNS_FILE" || exit 0

shield_audit "instruction-override-bridge-guard" "block" "A trusted instruction surface now tells the runtime to bypass Runwall or trust tool output over policy" "$INPUT"
printf '%s\n' '[runwall] blocked policy-override bridge in trusted instructions' >&2
printf '%s\n' 'reason: the trusted instruction file now tells the runtime to trust tool output over policy or bypass local Runwall enforcement' >&2
printf '%s\n' 'next: keep trusted instructions aligned with the local policy boundary and remove any bypass or trust-override language' >&2
exit 2
