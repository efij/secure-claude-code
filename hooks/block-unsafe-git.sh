#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
PROTECTED_FILE="${RUNWALL_HOME:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.runwall}}/config/protected-branches.txt"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

block() {
  shield_audit "block-unsafe-git" "block" "$1" "$INPUT"
  printf '%s\n' '[runwall] blocked unsafe git action' >&2
  printf 'reason: %s\n' "$1" >&2
  printf 'next: %s\n' "$2" >&2
  exit 2
}

if [[ "$INPUT" != *git* ]]; then
  exit 0
fi

if printf '%s' "$INPUT" | grep -Eq -- '(^|[[:space:]])(--no-verify|--no-gpg-sign)([[:space:]]|$)'; then
  block \
    'git safety bypass flags would skip review and verification hooks' \
    'fix the failing checks instead of bypassing them'
fi

protected_pattern='main|master|production|release'
if [ -f "$PROTECTED_FILE" ]; then
  protected_pattern="$(paste -sd'|' "$PROTECTED_FILE" | sed 's/|$//')"
fi

current_branch=''
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  current_branch="$(git symbolic-ref --quiet --short HEAD 2>/dev/null || true)"
fi

if printf '%s' "$INPUT" | grep -Eq 'git[[:space:]].*reset[[:space:]]+--hard' &&
  printf '%s' "$current_branch" | grep -Eq "^($protected_pattern)$"; then
  block \
    "git reset --hard on protected branch \"$current_branch\" is blocked" \
    'create a feature branch or use a reversible command'
fi

if printf '%s' "$INPUT" | grep -Eq 'git[[:space:]].*push' &&
  printf '%s' "$INPUT" | grep -Eq -- '(^|[[:space:]])(--force|-f|--force-with-lease)([[:space:]]|$)' &&
  {
    printf '%s' "$INPUT" | grep -Eq "(^|[[:space:]])($protected_pattern)([[:space:]]|$)" ||
      printf '%s' "$current_branch" | grep -Eq "^($protected_pattern)$";
  }; then
  block \
    'force-push to a protected branch would rewrite shared history' \
    'push to a feature branch and land changes through a PR'
fi

if printf '%s' "$INPUT" | grep -Eq 'git[[:space:]].*push' &&
  printf '%s' "$current_branch" | grep -Eq "^($protected_pattern)$"; then
  shield_audit "block-unsafe-git" "warn" "direct push from protected branch" "$INPUT"
  printf '%s\n' '[runwall] warning: protected branch push' >&2
  printf 'reason: current branch "%s" is protected\n' "$current_branch" >&2
  printf '%s\n' 'next: prefer a PR flow from a feature branch' >&2
fi

exit 0
