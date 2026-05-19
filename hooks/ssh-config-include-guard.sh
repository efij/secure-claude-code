#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

if ! printf '%s\n' "$INPUT" | grep -Eqi '(Include[[:space:]]+|ssh_config|\.ssh/config|ssh[[:space:]]+-F[[:space:]])'; then
  exit 0
fi

if ! printf '%s\n' "$INPUT" | grep -Eqi '(/tmp/|/var/tmp/|/private/tmp/|/Downloads/|file://|\\\\|\.zip|\.tar|\.tgz|\.gz|\.xz)'; then
  exit 0
fi

shield_audit "ssh-config-include-guard" "block" "SSH config indirection to an unreviewed path detected" "$INPUT"
printf '%s\n' '[stallion] blocked unreviewed SSH config include' >&2
printf '%s\n' 'reason: the change points SSH configuration at a temp, downloaded, or otherwise unreviewed include path' >&2
printf '%s\n' 'next: keep SSH config local and reviewed instead of chaining into scratch or download locations' >&2
exit 2
