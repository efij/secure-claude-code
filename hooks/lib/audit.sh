#!/usr/bin/env bash

shield_audit_mode="${SECURE_CLAUDE_CODE_AUDIT_MODE:-alerts}"
shield_audit_file="${SECURE_CLAUDE_CODE_AUDIT_FILE:-${SECURE_CLAUDE_CODE_HOME:-$HOME/.secure-claude-code}/state/audit.jsonl}"

shield_should_audit() {
  local decision="${1:-}"
  case "$shield_audit_mode" in
    off) return 1 ;;
    all) return 0 ;;
    *)
      case "$decision" in
        block|warn|error) return 0 ;;
        *) return 1 ;;
      esac
      ;;
  esac
}

shield_audit() {
  local module="${1:-unknown}"
  local decision="${2:-info}"
  local reason="${3:-}"
  local input="${4:-}"

  shield_should_audit "$decision" || return 0
  command -v python3 >/dev/null 2>&1 || return 0

  mkdir -p "$(dirname "$shield_audit_file")"

  python3 - "$shield_audit_file" "$module" "$decision" "$reason" "$input" <<'PY'
import json
import os
import pathlib
import socket
import sys
from datetime import datetime, timezone

path = pathlib.Path(sys.argv[1])
module = sys.argv[2]
decision = sys.argv[3]
reason = sys.argv[4]
tool_input = sys.argv[5][:4000]

shield_home = pathlib.Path(
    os.environ.get(
        "SECURE_CLAUDE_CODE_HOME",
        os.path.expanduser("~/.secure-claude-code"),
    )
)
profile_file = shield_home / "state" / "profile.txt"
profile = profile_file.read_text().strip() if profile_file.exists() else "unknown"

event = {
    "ts": datetime.now(timezone.utc).isoformat(),
    "module": module,
    "decision": decision,
    "reason": reason,
    "profile": profile,
    "cwd": os.getcwd(),
    "user": os.environ.get("USER") or os.environ.get("USERNAME") or "unknown",
    "host": socket.gethostname(),
    "tool_input": tool_input,
}

with path.open("a", encoding="utf-8") as fh:
    fh.write(json.dumps(event, separators=(",", ":")) + "\n")
PY
}
