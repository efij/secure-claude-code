#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import shlex
from datetime import datetime, timezone
from typing import Any


INLINE_SHELL_RE = re.compile(r"(?i)\b(?:bash|sh|zsh)\b\s+-c\b")
INLINE_PYTHON_RE = re.compile(r"(?i)\bpython(?:3)?\b\s+-c\b")
INLINE_NODE_RE = re.compile(r"(?i)\bnode\b\s+-e\b")
EVAL_SOURCE_RE = re.compile(r"(?i)\b(?:eval|source|\.)\b")
HEREDOC_RE = re.compile(r"<<-?\s*['\"]?(?:EOF|SH|BASH|PY|PYTHON|NODE|JS)")
PROCESS_SUB_RE = re.compile(r"<\((?:[^)]{0,220})\)")
FETCH_EXEC_RE = re.compile(
    r"(?is)(?:curl|wget|invoke-webrequest|invoke-restmethod)[^\n\r]{0,240}(?:\|\s*(?:bash|sh|zsh)|>\s*/tmp/|>\s*[^;\n\r]+\.(?:sh|py|js)|chmod\s+\+x|(?:bash|sh|zsh)\s+-c|python(?:3)?\s+-c|node\s+-e)"
)
ENCODED_LOADER_RE = re.compile(
    r"(?is)(?:base64\s+-d|python(?:3)?\s+-c[^\n\r]{0,240}b64decode|node\s+-e[^\n\r]{0,240}Buffer\.from|pwsh(?:\.exe)?\s+-enc|powershell(?:\.exe)?\s+-enc|openssl\s+enc|gpg\s+-d|age\s+-d)"
)
SECRET_TERM_RE = re.compile(
    r"(?i)(?:\.env(?:\.[A-Za-z0-9._-]+)?|\.aws/(?:credentials|config)|id_(?:rsa|ed25519)|authorized_keys|\.npmrc|\.pypirc|\.kube/config|token|secret|password|session)"
)
EXFIL_RE = re.compile(r"(?i)(?:curl|wget|scp|rsync|rclone|webhook|pastebin|discord(?:app)?\.com/api/webhooks|hooks\.slack\.com)")
PERSISTENCE_RE = re.compile(
    r"(?i)(?:\.bashrc|\.zshrc|\.profile|crontab\b|launchctl\b|systemctl(?:\s+--user)?\b|schtasks\b|LoginItems|authorized_keys)"
)
POLICY_BYPASS_RE = re.compile(
    r"(?i)(?:disable runwall|ignore runwall|bypass runwall|unset RUNWALL_HOME|HUSKY\s*=\s*0|--no-verify\b|ignore local policy)"
)
ENV_PAYLOAD_RE = re.compile(
    r"(?i)(?:\$[{(]?(?:PAYLOAD|CODE|SCRIPT|BLOB|DATA|CMD)[})]?|os\.environ|process\.env|getenv\(|environ\[)"
)
PYTHON_LOADER_RE = re.compile(
    r"(?is)\bpython(?:3)?\b\s+-c\b[^\n\r]{0,320}(?:requests\.|urllib\.|subprocess\.|os\.system|exec\(|eval\(|compile\(|base64\.b64decode)"
)
NODE_LOADER_RE = re.compile(
    r"(?is)\bnode\b\s+-e\b[^\n\r]{0,320}(?:https\.get|fetch\(|require\(['\"]child_process|eval\(|Buffer\.from|execSync|spawnSync)"
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def state_dir(root: pathlib.Path) -> pathlib.Path:
    home = os.environ.get("RUNWALL_HOME") or os.environ.get("SECURE_CLAUDE_CODE_HOME")
    if home:
        return pathlib.Path(home) / "state"
    return pathlib.Path(os.path.expanduser("~")) / ".runwall" / "state"


def exec_store_path(root: pathlib.Path) -> pathlib.Path:
    return state_dir(root) / "exec.json"


def load_store(root: pathlib.Path) -> dict[str, Any]:
    path = exec_store_path(root)
    if not path.exists():
        return {"version": 1, "events": []}
    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {"version": 1, "events": []}
    if not isinstance(payload, dict):
        return {"version": 1, "events": []}
    payload.setdefault("version", 1)
    payload.setdefault("events", [])
    return payload


def save_store(root: pathlib.Path, store: dict[str, Any]) -> None:
    path = exec_store_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(store, indent=2, sort_keys=True) + "\n")


def _shell_split(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=os.name != "nt")
    except ValueError:
        return [token for token in command.strip().split() if token]


def _surface(payload: str) -> str | None:
    if INLINE_PYTHON_RE.search(payload):
        return "inline-python"
    if INLINE_NODE_RE.search(payload):
        return "inline-node"
    if INLINE_SHELL_RE.search(payload):
        return "inline-shell"
    if HEREDOC_RE.search(payload):
        return "heredoc"
    if PROCESS_SUB_RE.search(payload):
        return "process-substitution"
    if EVAL_SOURCE_RE.search(payload):
        return "eval-source"
    return None


def _identity(payload: str) -> dict[str, Any] | None:
    surface = _surface(payload)
    if not surface:
        return None
    return {
        "surface": surface,
        "has_fetch_exec": bool(FETCH_EXEC_RE.search(payload)),
        "has_encoded_loader": bool(ENCODED_LOADER_RE.search(payload)),
        "has_secret_terms": bool(SECRET_TERM_RE.search(payload)),
        "has_exfil_terms": bool(EXFIL_RE.search(payload)),
        "has_persistence_terms": bool(PERSISTENCE_RE.search(payload)),
        "has_policy_bypass": bool(POLICY_BYPASS_RE.search(payload)),
        "has_env_payload": bool(ENV_PAYLOAD_RE.search(payload)),
        "command_preview": payload[:220],
    }


def _hit(module: str, identity: dict[str, Any], reason: str, safer: str, decision: str = "block") -> dict[str, Any]:
    return {
        "module": module,
        "name": module.replace("-", " ").title(),
        "category": "fileless-trust",
        "family": "Fileless & Inline Execution",
        "decision": decision,
        "exit_code": 2 if decision == "block" else 0,
        "output": reason,
        "metadata": {
            "reason": reason,
            "confidence": 0.96 if decision == "block" else 0.84,
            "safer_alternative": safer,
            "exec_identity": identity,
        },
    }


def assess_command(root: pathlib.Path, payload: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = context
    identity = _identity(payload)
    if not identity:
        return {"identity": None, "hit": None}

    hit = None
    if FETCH_EXEC_RE.search(payload) and (INLINE_SHELL_RE.search(payload) or INLINE_PYTHON_RE.search(payload) or INLINE_NODE_RE.search(payload) or PROCESS_SUB_RE.search(payload)):
        hit = _hit(
            "inline-fetch-exec-guard",
            identity,
            "Blocked remote fetch-and-execute behavior hidden inside inline execution.",
            "Fetch content to a reviewed local file first, inspect it, and avoid piping remote content directly into interpreters or shells.",
        )
    elif ENCODED_LOADER_RE.search(payload) and (INLINE_PYTHON_RE.search(payload) or INLINE_NODE_RE.search(payload) or INLINE_SHELL_RE.search(payload) or HEREDOC_RE.search(payload)):
        hit = _hit(
            "inline-encoded-loader-guard",
            identity,
            "Blocked encoded loader behavior in inline execution.",
            "Keep encoded payload decode-and-run chains out of runtime one-liners and review decoded content explicitly before execution.",
        )
    elif PROCESS_SUB_RE.search(payload) and FETCH_EXEC_RE.search(payload):
        hit = _hit(
            "inline-process-substitution-guard",
            identity,
            "Blocked process-substitution fetch-and-execute chain.",
            "Do not source or execute remote content through process substitution. Save and review the content first.",
        )
    elif HEREDOC_RE.search(payload) and (FETCH_EXEC_RE.search(payload) or EXFIL_RE.search(payload) or PERSISTENCE_RE.search(payload)):
        hit = _hit(
            "inline-heredoc-dropper-guard",
            identity,
            "Blocked risky heredoc execution that stages a loader, exfiltration, or persistence path.",
            "Keep heredocs for local data only, and move any executable or network-bearing logic into reviewed files.",
        )
    elif EVAL_SOURCE_RE.search(payload) and SECRET_TERM_RE.search(payload) and (EXFIL_RE.search(payload) or ENV_PAYLOAD_RE.search(payload) or FETCH_EXEC_RE.search(payload)):
        hit = _hit(
            "inline-eval-secret-guard",
            identity,
            "Blocked inline eval/source chain that combines secret access with loader or outbound behavior.",
            "Do not use eval or source to process secret-bearing content. Use explicit reviewed commands and keep secrets away from inline execution.",
        )
    elif ENV_PAYLOAD_RE.search(payload) and (INLINE_SHELL_RE.search(payload) or INLINE_PYTHON_RE.search(payload) or INLINE_NODE_RE.search(payload)):
        hit = _hit(
            "inline-env-payload-guard",
            identity,
            "Blocked inline execution driven by environment payload variables.",
            "Avoid hidden env-variable code injection. Keep executable logic in reviewed files or explicit command arguments.",
        )
    elif PYTHON_LOADER_RE.search(payload) and (FETCH_EXEC_RE.search(payload) or EXFIL_RE.search(payload) or SECRET_TERM_RE.search(payload)):
        hit = _hit(
            "inline-python-loader-guard",
            identity,
            "Blocked Python inline loader behavior with fetch, eval, secret, or outbound primitives.",
            "Move complex Python logic into a reviewed file and avoid `python -c` for loader-style execution.",
        )
    elif NODE_LOADER_RE.search(payload) and (FETCH_EXEC_RE.search(payload) or EXFIL_RE.search(payload) or SECRET_TERM_RE.search(payload)):
        hit = _hit(
            "inline-node-loader-guard",
            identity,
            "Blocked Node inline loader behavior with fetch, eval, secret, or outbound primitives.",
            "Move complex JavaScript logic into a reviewed file and avoid `node -e` for loader-style execution.",
        )
    elif (INLINE_SHELL_RE.search(payload) or INLINE_PYTHON_RE.search(payload) or INLINE_NODE_RE.search(payload)) and PERSISTENCE_RE.search(payload):
        hit = _hit(
            "inline-shell-persistence-guard",
            identity,
            "Blocked inline execution that attempts to create persistence in shell profiles, schedulers, or login surfaces.",
            "Keep profile edits, cron changes, and persistence logic out of inline one-liners.",
        )
    elif (INLINE_SHELL_RE.search(payload) or INLINE_PYTHON_RE.search(payload) or INLINE_NODE_RE.search(payload) or EVAL_SOURCE_RE.search(payload)) and POLICY_BYPASS_RE.search(payload):
        hit = _hit(
            "inline-policy-bypass-guard",
            identity,
            "Blocked inline execution that attempts to bypass Runwall or normal review boundaries.",
            "Do not hide review-bypass or guard-disabling behavior inside inline execution paths.",
        )

    store = load_store(root)
    store.setdefault("events", []).append(
        {
            "ts": utc_now(),
            "surface": identity["surface"],
            "decision": hit["decision"] if hit else "allow",
            "module": hit["module"] if hit else "observed",
            "preview": payload[:200],
        }
    )
    store["events"] = store["events"][-200:]
    save_store(root, store)
    return {"identity": identity, "hit": hit}


def list_events(root: pathlib.Path) -> list[dict[str, Any]]:
    items = [item for item in load_store(root).get("events", []) if isinstance(item, dict)]
    items.sort(key=lambda item: item.get("ts", ""), reverse=True)
    return items


def explain_event(root: pathlib.Path, selector: str) -> dict[str, Any] | None:
    for item in list_events(root):
        if item.get("ts") == selector or item.get("module") == selector:
            return item
    return None


def policy_payload() -> dict[str, Any]:
    return {
        "guards": [
            "inline-fetch-exec-guard",
            "inline-encoded-loader-guard",
            "inline-process-substitution-guard",
            "inline-heredoc-dropper-guard",
            "inline-eval-secret-guard",
            "inline-env-payload-guard",
            "inline-python-loader-guard",
            "inline-node-loader-guard",
            "inline-shell-persistence-guard",
            "inline-policy-bypass-guard",
        ]
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect Runwall fileless and inline execution state")
    parser.add_argument("--root", required=True)
    subparsers = parser.add_subparsers(dest="command", required=True)
    list_parser = subparsers.add_parser("list")
    list_parser.add_argument("--json", action="store_true")
    explain_parser = subparsers.add_parser("explain")
    explain_parser.add_argument("selector")
    policy_parser = subparsers.add_parser("policy")
    policy_parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    root = pathlib.Path(args.root)

    if args.command == "list":
        items = list_events(root)
        if args.json:
            print(json.dumps({"events": items}, indent=2))
        else:
            print("Inline Execution Events:")
            for item in items:
                print(f"- {item.get('decision')} {item.get('surface')} {item.get('module')} {item.get('ts')}")
        return 0
    if args.command == "explain":
        payload = explain_event(root, args.selector)
        if payload is None:
            print(f"unknown inline execution event: {args.selector}", file=os.sys.stderr)
            return 1
        print(json.dumps(payload, indent=2))
        return 0
    if args.command == "policy":
        payload = policy_payload()
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print("Inline Execution Guards:")
            for item in payload["guards"]:
                print(f"- {item}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
