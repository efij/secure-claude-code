#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
TOKEN_FILE="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config/live-token-patterns.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"
. "$(dirname "${BASH_SOURCE[0]}")/lib/patterns.sh"
trap 'shield_cleanup_pattern_files' EXIT

[ -f "$TOKEN_FILE" ] || exit 0

if ! printf '%s\n' "$INPUT" | grep -Eqi '(\.github/workflows/|docker-compose[^[:space:]]*\.ya?ml|(^|[[:space:]])Dockerfile([[:space:]]|$)|terraform\.tfvars|\.tfvars([[:space:]]|$)|values\.ya?ml|appsettings\.json|application\.(ya?ml|json)|config/[^[:space:]]+\.(json|ya?ml|toml)|\.mcp\.json|compose\.ya?ml)'; then
  exit 0
fi

if ! shield_match_pattern_file "$INPUT" "$TOKEN_FILE" && ! printf '%s\n' "$INPUT" | grep -Eq -- '-----BEGIN [A-Z ]+PRIVATE KEY-----'; then
  exit 0
fi

shield_audit "config-secret-inline-guard" "block" "live secret material is being written into config or workflow files" "$INPUT"
printf '%s\n' '[runwall] blocked live secret in config or workflow file' >&2
printf '%s\n' 'reason: the edit targets a deployment, workflow, or application config file and contains a live token or private key pattern' >&2
printf '%s\n' 'next: use a reviewed secret reference, env injection path, or a clearly redacted sample instead of inlining the secret' >&2
exit 2
