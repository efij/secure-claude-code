#!/usr/bin/env bash

shield_prepare_pattern_file() {
  local source_file="${1:-}"
  local temp_file

  [ -f "$source_file" ] || return 1

  temp_file="$(mktemp "${TMPDIR:-/tmp}/secure-claude-code-patterns.XXXXXX")" || return 1
  tr -d '\r' <"$source_file" >"$temp_file"
  printf '%s\n' "$temp_file"
}
