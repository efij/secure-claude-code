#!/usr/bin/env bash

shield_pattern_temp_files="${shield_pattern_temp_files:-}"

shield_prepare_pattern_file() {
  local source_file="${1:-}"
  local temp_file

  [ -f "$source_file" ] || return 1

  temp_file="$(mktemp "${TMPDIR:-/tmp}/runwall-patterns.XXXXXX")" || return 1
  tr -d '\r' <"$source_file" >"$temp_file"
  shield_pattern_temp_files="${shield_pattern_temp_files}${temp_file}"$'\n'
  printf '%s\n' "$temp_file"
}

shield_cleanup_pattern_files() {
  if [ -n "${shield_pattern_temp_files:-}" ]; then
    printf '%s' "$shield_pattern_temp_files" | while IFS= read -r temp_file; do
      [ -n "$temp_file" ] || continue
      rm -f "$temp_file"
    done
  fi
}

shield_match_pattern_file() {
  local input="${1:-}"
  local source_file="${2:-}"
  local clean_file

  clean_file="$(shield_prepare_pattern_file "$source_file")" || return 1
  printf '%s\n' "$input" | grep -Eif "$clean_file" >/dev/null 2>&1
}
