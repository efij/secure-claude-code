#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
ALLOWLIST_FILE="${SECURE_CLAUDE_CODE_HOME:-$HOME/.secure-claude-code}/config/secret-allowlist.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

if ! printf '%s' "$INPUT" | grep -Eq 'git[[:space:]].*push'; then
  exit 0
fi

printf '%s\n' '[secure-claude-code] running pre-push scan' >&2

collect_matches() {
  local pattern="${1:-}"
  find . \
    \( -path './.git' -o -path './node_modules' -o -path './dist' -o -path './build' -o -path './coverage' -o -path './.next' -o -path './vendor' \) -prune -o \
    -type f \
    \( -name '*.ts' -o -name '*.tsx' -o -name '*.js' -o -name '*.jsx' -o -name '*.mjs' -o -name '*.cjs' -o -name '*.json' -o -name '*.yaml' -o -name '*.yml' -o -name '*.toml' -o -name '*.py' -o -name '*.go' -o -name '*.rs' -o -name '*.env' -o -name '*.tf' -o -name '*.sh' \) \
    ! -name '*.example' ! -name '*.sample' ! -name '*.template' ! -name 'README*' ! -name '*.md' \
    -print0 \
    | xargs -0 grep -nHE "$pattern" 2>/dev/null \
    | head -n 10 || true
}

filter_allowlist() {
  local results="${1:-}"
  if [ -z "$results" ]; then
    return 0
  fi

  if [ -s "$ALLOWLIST_FILE" ]; then
    printf '%s\n' "$results" | grep -Ev -f "$ALLOWLIST_FILE" || true
  else
    printf '%s\n' "$results"
  fi
}

failures=0

secret_hits="$(collect_matches '(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{20,}|(api[_-]?key|secret|token|password|client[_-]?secret|private[_-]?key)[[:space:]]*[:=][[:space:]]*["'"'"'][^"'"'"']{6,}["'"'"'])')"
secret_hits="$(filter_allowlist "$secret_hits")"
if [ -n "$secret_hits" ]; then
  printf '%s\n' 'fail [secrets]: likely credentials found' >&2
  printf '%s\n' "$secret_hits" >&2
  failures=1
else
  printf '%s\n' 'pass [secrets]: no likely hardcoded credentials found' >&2
fi

network_hits="$(collect_matches '(192\.168\.[0-9]+\.[0-9]+|10\.[0-9]+\.[0-9]+\.[0-9]+|172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]+\.[0-9]+|\.internal|\.corp)')"
network_hits="$(filter_allowlist "$network_hits")"
if [ -n "$network_hits" ]; then
  printf '%s\n' 'fail [network]: internal network data found' >&2
  printf '%s\n' "$network_hits" >&2
  failures=1
else
  printf '%s\n' 'pass [network]: no internal network identifiers found' >&2
fi

url_hits="$(collect_matches '((postgres|mysql|mongodb(\+srv)?|redis|amqp):\/\/[^[:space:]]+|DATABASE_URL[[:space:]]*[:=][[:space:]]*["'"'"'][^"'"'"']+["'"'"']|REDIS_URL[[:space:]]*[:=][[:space:]]*["'"'"'][^"'"'"']+["'"'"'])')"
url_hits="$(filter_allowlist "$url_hits")"
if [ -n "$url_hits" ]; then
  printf '%s\n' 'fail [connection]: connection string found' >&2
  printf '%s\n' "$url_hits" >&2
  failures=1
else
  printf '%s\n' 'pass [connection]: no inline connection strings found' >&2
fi

if [ "$failures" -ne 0 ]; then
  shield_audit "pre-push-scan" "block" "pre-push scan found secrets or live connection data" "$INPUT"
  printf '%s\n' '[secure-claude-code] push blocked' >&2
  printf '%s\n' 'reason: the outgoing diff likely contains secrets, internal identifiers, or live connection data' >&2
  printf '%s\n' 'next: remove the values or add a narrow allowlist rule in ~/.secure-claude-code/config/secret-allowlist.regex' >&2
  exit 2
fi

shield_audit "pre-push-scan" "warn" "pre-push scan passed" "$INPUT"
printf '%s\n' '[secure-claude-code] pre-push scan passed' >&2
exit 0
