#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-}"
CONFIG_HOME="${SECURE_CLAUDE_CODE_HOME:-$HOME/.secure-claude-code}/config"
CONTROL_FILE="${CONFIG_HOME}/control-files.regex"
. "$(dirname "${BASH_SOURCE[0]}")/lib/audit.sh"

block() {
  shield_audit "abuse-chain-defense" "block" "$1" "$INPUT"
  printf '%s\n' '[secure-claude-code] blocked abuse-chain or prompt-injection pattern' >&2
  printf 'reason: %s\n' "$1" >&2
  printf 'next: %s\n' "$2" >&2
  exit 2
}

touches_control_files() {
  [ -f "$CONTROL_FILE" ] || return 1
  printf '%s\n' "$INPUT" | grep -Eif "$CONTROL_FILE" >/dev/null 2>&1
}

if printf '%s' "$INPUT" | grep -Eqi '(curl|wget|Invoke-WebRequest|iwr|irm|fetch)' &&
  touches_control_files &&
  printf '%s' "$INPUT" | grep -Eqi '(>|>>|tee|Out-File|Set-Content|Add-Content|cp[[:space:]]|copy[[:space:]])'; then
  block \
    'remote content is being written directly into agent control files or local prompt instructions' \
    'review the content offline first and apply only deliberate local edits'
fi

if touches_control_files &&
  printf '%s' "$INPUT" | grep -Eqi '(ignore (all )?previous instructions|ignore the rules|bypass security|disable hooks|system prompt|developer prompt|jailbreak|override guardrails)'; then
  block \
    'a control file edit contains classic prompt-injection or rule-override language' \
    'rewrite the instruction in a minimal, local, reviewed form'
fi

if printf '%s' "$INPUT" | grep -Eqi '(\.env|\.aws|\.ssh|id_rsa|id_ed25519|\.kube/config)' &&
  printf '%s' "$INPUT" | grep -Eqi '(base64|xxd|openssl[[:space:]]+enc|tar|zip|gzip|scp|sftp|ftp|curl|wget|nc|netcat|aws[[:space:]]+s3[[:space:]]+cp|gsutil[[:space:]]+cp)'; then
  block \
    'the command chains secret material with encoding, archiving, or transfer operations' \
    'remove the sensitive source from the command and handle any export through a reviewed manual step'
fi

exit 0

