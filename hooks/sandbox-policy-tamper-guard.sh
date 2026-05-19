#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
CONFIG_HOME="${STALLION_HOME:-$HOME/.stallion}/config"
FILES_FILE="$CONFIG_HOME/sandbox-policy-files.regex"
RISK_FILE="$CONFIG_HOME/sandbox-policy-risky.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

[ -f "$FILES_FILE" ] || exit 0
[ -f "$RISK_FILE" ] || exit 0

if ! shield_match_file "$INPUT" "$FILES_FILE"; then
  exit 0
fi

if ! shield_match_file "$INPUT" "$RISK_FILE"; then
  exit 0
fi

shield_audit "sandbox-policy-tamper-guard" "block" "sandbox or container policy is being weakened" "$INPUT"
printf '%s\n' '[stallion] blocked sandbox policy tampering' >&2
printf '%s\n' 'reason: the change weakens container or devcontainer isolation with host networking, privileged mode, or unsafe mounts' >&2
printf '%s\n' 'next: keep the sandbox policy least-privileged and avoid host-linked mounts or unconfined security options' >&2
exit 2
