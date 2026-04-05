#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

if ! printf '%s\n' "$INPUT" | grep -Eqi '\.github/workflows/'; then
  exit 0
fi

if ! printf '%s\n' "$INPUT" | grep -Eqi 'runs-on:[[:space:]]*(\[.*self-hosted.*\]|self-hosted)'; then
  exit 0
fi

if ! printf '%s\n' "$INPUT" | grep -Eqi '(pull_request_target|pull_request:)'; then
  exit 0
fi

shield_audit "ci-self-hosted-runner-guard" "block" "self-hosted runner is exposed to PR-triggered workflow execution" "$INPUT"
printf '%s\n' '[runwall] blocked risky self-hosted CI runner exposure' >&2
printf '%s\n' 'reason: the workflow combines self-hosted runners with a PR-triggered path, which can expose internal infrastructure to untrusted changes' >&2
printf '%s\n' 'next: keep untrusted PRs on hosted runners or split privileged self-hosted jobs behind reviewed, non-user-controlled triggers' >&2
exit 2
