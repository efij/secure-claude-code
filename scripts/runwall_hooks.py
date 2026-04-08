#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shlex
from datetime import datetime, timezone
from typing import Any

import runwall_tools


DEFAULT_POLICY = {
    "review_surfaces": [
        "git-hook",
        "package-install-script",
        "plugin-hook",
    ],
    "block_origins": ["temp", "download", "cache"],
    "high_risk_surfaces": [
        "git-hook",
        "package-install-script",
        "plugin-hook",
        "ci-workflow",
        "editor-task",
        "shell-startup",
        "task-runner",
    ],
}

INSTALL_SCRIPT_NAMES = {
    "preinstall",
    "install",
    "postinstall",
    "prepare",
    "prepublish",
    "prepublishonly",
    "prepack",
    "postpack",
}
PROFILE_NAMES = {
    ".bashrc",
    ".bash_profile",
    ".profile",
    ".zshrc",
    ".zprofile",
    "config.fish",
    "profile.ps1",
    "microsoft.powershell_profile.ps1",
}
INLINE_WRAPPER_RE = re.compile(
    r"(?i)\b(?:bash|sh|zsh|python|python3|node|pwsh|powershell|cmd)\b\s+(?:-c|-e|-ec|-ce|-enc|-encodedcommand|-command|/c)\b"
)
NETWORK_RE = re.compile(
    r"(?i)\b(?:curl|wget|invoke-webrequest|invoke-restmethod|scp|rsync|nc|ncat|socat|ftp|tftp)\b|https?://|hooks\.slack\.com|discord(?:app)?\.com/api/webhooks|pastebin\.com|ngrok|cloudflared\s+tunnel|ssh\s+-R\b"
)
STEALTH_RE = re.compile(
    r"(?i)\b(?:nohup|disown|setsid|schtasks|launchctl|crontab|at)\b|(?:>\s*/dev/null\s*2>&1)|(?:2>&1\s*>\s*/dev/null)|(?:&&\s*sleep\s+\d+)|(?:\s&\s*$)|(?:\s&\s*(?:#.*)?$)"
)
EXTERNAL_RE = re.compile(
    r"(?i)https?://|(?:^|[\s'\"=])(?:/tmp/|/var/tmp/|/private/tmp/|~?/downloads/|%temp%|%tmp%|[A-Z]:\\Users\\[^\\]+\\Downloads\\|[A-Z]:\\Users\\[^\\]+\\AppData\\Local\\Temp\\)"
)
GIT_HOOK_PATH_RE = re.compile(r"(?P<path>(?:^|[\s'\"=])(?:[^\s'\"=]*?(?:\.git/hooks|\.githooks)/[A-Za-z0-9._-]+))")
PACKAGE_SCRIPT_RE = re.compile(
    r"(?i)scripts\.(?P<trigger>preinstall|install|postinstall|prepare|prepublish|prepublishonly|prepack|postpack)\b"
)
PACKAGE_JSON_TRIGGER_RE = re.compile(
    r'(?i)"(?P<trigger>preinstall|install|postinstall|prepare|prepublish|prepublishOnly|prepack|postpack)"\s*:'
)
PLUGIN_HOOK_PATH_RE = re.compile(r"(^|[\s'\"=])(?P<path>[^\s'\"=]*/?hooks/hooks\.json)\b")
WORKFLOW_PATH_RE = re.compile(r"(^|[\s'\"=])(?P<path>[^\s'\"=]*\.github/workflows/[^\s'\"=]+\.(?:yml|yaml))\b")
EDITOR_TASK_RE = re.compile(r"(^|[\s'\"=])(?P<path>[^\s'\"=]*\.vscode/tasks\.json)\b")
TASK_RUNNER_NAMES = {"Makefile", "Taskfile.yml", "Taskfile.yaml", "justfile"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _home_dir() -> pathlib.Path:
    return pathlib.Path(os.path.expanduser("~"))


def state_dir(root: pathlib.Path) -> pathlib.Path:
    home = os.environ.get("RUNWALL_HOME") or os.environ.get("SECURE_CLAUDE_CODE_HOME")
    if home:
        return pathlib.Path(home) / "state"
    return _home_dir() / ".runwall" / "state"


def hook_store_path(root: pathlib.Path) -> pathlib.Path:
    return state_dir(root) / "hooks.json"


def hook_policy_path(root: pathlib.Path) -> pathlib.Path:
    home = os.environ.get("RUNWALL_HOME") or os.environ.get("SECURE_CLAUDE_CODE_HOME")
    if home:
        return pathlib.Path(home) / "config" / "hook-trust-policy.json"
    return root / "config" / "hook-trust-policy.json"


def load_policy(root: pathlib.Path) -> dict[str, Any]:
    policy = json.loads(json.dumps(DEFAULT_POLICY))
    path = hook_policy_path(root)
    if not path.exists():
        return policy
    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError:
        return policy
    if not isinstance(payload, dict):
        return policy
    for key, default in DEFAULT_POLICY.items():
        value = payload.get(key, default)
        if isinstance(default, list):
            policy[key] = [str(item) for item in value if isinstance(item, (str, int, float))]
        else:
            policy[key] = value
    return policy


def load_store(root: pathlib.Path) -> dict[str, Any]:
    path = hook_store_path(root)
    if not path.exists():
        return {"version": 1, "hooks": {}}
    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {"version": 1, "hooks": {}}
    if not isinstance(payload, dict):
        return {"version": 1, "hooks": {}}
    payload.setdefault("version", 1)
    payload.setdefault("hooks", {})
    return payload


def save_store(root: pathlib.Path, store: dict[str, Any]) -> None:
    path = hook_store_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(store, indent=2, sort_keys=True) + "\n")


def _normalize_path_token(token: str) -> pathlib.Path:
    token = token.strip("'\"= ")
    expanded = os.path.expanduser(token)
    path = pathlib.Path(expanded)
    if not path.is_absolute():
        path = pathlib.Path(os.path.abspath(str(pathlib.Path.cwd() / path)))
    return path


def _classify_origin(candidate: str | pathlib.Path | None, root: pathlib.Path) -> str:
    if candidate is None:
        return "unknown"
    path = candidate if isinstance(candidate, pathlib.Path) else _normalize_path_token(str(candidate))
    return runwall_tools._classify_origin(path, root)  # type: ignore[attr-defined]


def _content_hash(text: str) -> str:
    normalized = re.sub(r"\s+", " ", text.strip())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _content_preview(text: str) -> str:
    preview = re.sub(r"\s+", " ", text.strip())
    return preview[:220]


def _shell_split(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=os.name != "nt")
    except ValueError:
        return [token for token in command.strip().split() if token]


def _write_surface(payload: str) -> tuple[pathlib.Path | None, str]:
    tokens = _shell_split(payload)
    if not tokens:
        return None, ""
    first = tokens[0]
    if "/" in first or "\\" in first or first.startswith("."):
        return _normalize_path_token(first), payload[len(first) :].strip()
    return None, payload


def _match_path(regex: re.Pattern[str], payload: str) -> pathlib.Path | None:
    match = regex.search(payload)
    if not match:
        return None
    path_text = match.groupdict().get("path") or match.group(0)
    return _normalize_path_token(path_text)


def _package_trigger_from_text(text: str) -> str | None:
    match = PACKAGE_SCRIPT_RE.search(text)
    if match:
        return str(match.group("trigger")).lower()
    match = PACKAGE_JSON_TRIGGER_RE.search(text)
    if match:
        return str(match.group("trigger")).lower()
    return None


def infer_hook_identity(root: pathlib.Path, event: str, matcher: str, payload: str) -> dict[str, Any] | None:
    if event != "PreToolUse" or matcher not in {"Bash", "Write", "Edit", "MultiEdit"}:
        return None

    location: pathlib.Path | None = None
    content = payload
    surface: str | None = None
    trigger: str | None = None

    if matcher in {"Write", "Edit", "MultiEdit"}:
        location, content = _write_surface(payload)
        if location:
            location_text = str(location).replace("\\", "/")
            name = location.name
            if "/.git/hooks/" in location_text or "/.githooks/" in location_text:
                surface = "git-hook"
                trigger = name
            elif location_text.endswith("/hooks/hooks.json"):
                surface = "plugin-hook"
                trigger = "hooks.json"
            elif name == "package.json":
                package_trigger = _package_trigger_from_text(content)
                if package_trigger and package_trigger in INSTALL_SCRIPT_NAMES:
                    surface = "package-install-script"
                    trigger = package_trigger
            elif "/.github/workflows/" in location_text and location.suffix in {".yml", ".yaml"}:
                surface = "ci-workflow"
                trigger = name
            elif location_text.endswith("/.vscode/tasks.json"):
                surface = "editor-task"
                trigger = "tasks.json"
            elif name in TASK_RUNNER_NAMES:
                surface = "task-runner"
                trigger = name
            elif name.lower() in PROFILE_NAMES:
                surface = "shell-startup"
                trigger = name
    else:
        location = _match_path(GIT_HOOK_PATH_RE, payload)
        if location:
            surface = "git-hook"
            trigger = location.name
        else:
            location = _match_path(PLUGIN_HOOK_PATH_RE, payload)
            if location:
                surface = "plugin-hook"
                trigger = "hooks.json"
            else:
                workflow_path = _match_path(WORKFLOW_PATH_RE, payload)
                if workflow_path:
                    location = workflow_path
                    surface = "ci-workflow"
                    trigger = workflow_path.name
                else:
                    task_path = _match_path(EDITOR_TASK_RE, payload)
                    if task_path:
                        location = task_path
                        surface = "editor-task"
                        trigger = "tasks.json"
        if surface is None:
            package_trigger = _package_trigger_from_text(payload)
            if package_trigger and package_trigger in INSTALL_SCRIPT_NAMES:
                surface = "package-install-script"
                trigger = package_trigger
                location = (root / "package.json").resolve(strict=False)
        if surface is None and "core.hooksPath" in payload:
            surface = "git-hook"
            trigger = "core.hooksPath"
            location = (root / ".git").resolve(strict=False)

    if surface is None:
        return None

    location_str = str(location) if location else f"{surface}:{trigger or 'unknown'}"
    origin = _classify_origin(location, root) if location else "unknown"
    wrappers = sorted(set(token.lower() for token in INLINE_WRAPPER_RE.findall(content)))
    has_network = bool(NETWORK_RE.search(content))
    has_stealth = bool(STEALTH_RE.search(content))
    has_external_refs = bool(EXTERNAL_RE.search(content))
    identity = {
        "surface": surface,
        "trigger": trigger or "unknown",
        "location": location_str,
        "origin": origin,
        "content_hash": _content_hash(content),
        "content_preview": _content_preview(content),
        "has_inline_wrapper": bool(INLINE_WRAPPER_RE.search(content)),
        "has_network_fanout": has_network,
        "has_stealth_persistence": has_stealth,
        "has_external_refs": has_external_refs,
        "review_surface": surface in set(load_policy(root).get("review_surfaces", [])),
        "high_risk_surface": surface in set(load_policy(root).get("high_risk_surfaces", [])),
    }
    identity["identity_key"] = f"{surface}:{location_str}"
    return identity


def _hit(module: str, decision: str, output: str, identity: dict[str, Any], *, reason: str, safer_alternative: str) -> dict[str, Any]:
    return {
        "module": module,
        "name": module.replace("-", " ").title(),
        "category": "hook-trust",
        "family": "Trust, Persistence & Evasion",
        "decision": decision,
        "exit_code": 2 if decision == "block" else 0,
        "output": output,
        "metadata": {
            "reason": reason,
            "confidence": 0.95 if decision == "block" else 0.83,
            "safer_alternative": safer_alternative,
            "hook_identity": identity,
        },
    }


def _record(identity: dict[str, Any], trust_state: str, existing: dict[str, Any] | None = None) -> dict[str, Any]:
    now = utc_now()
    record = dict(existing or {})
    record.update(
        {
            "surface": identity["surface"],
            "trigger": identity["trigger"],
            "location": identity["location"],
            "origin": identity["origin"],
            "content_hash": identity["content_hash"],
            "content_preview": identity["content_preview"],
            "has_inline_wrapper": bool(identity["has_inline_wrapper"]),
            "has_network_fanout": bool(identity["has_network_fanout"]),
            "has_stealth_persistence": bool(identity["has_stealth_persistence"]),
            "has_external_refs": bool(identity["has_external_refs"]),
            "trust_state": trust_state,
            "last_seen_at": now,
        }
    )
    record.setdefault("first_seen_at", now)
    record["use_count"] = int(record.get("use_count", 0)) + 1
    return record


def assess_change(root: pathlib.Path, event: str, matcher: str, payload: str) -> dict[str, Any]:
    identity = infer_hook_identity(root, event, matcher, payload)
    if not identity:
        return {"identity": None, "hit": None}

    policy = load_policy(root)
    store = load_store(root)
    hooks: dict[str, Any] = store.setdefault("hooks", {})
    key = identity["identity_key"]
    existing = hooks.get(key)
    trust_state = "observed"
    hit: dict[str, Any] | None = None

    if identity["origin"] in set(policy.get("block_origins", [])) or identity["has_external_refs"]:
        trust_state = "blocked"
        hit = _hit(
            "hook-origin-guard",
            "block",
            f"Blocked {identity['surface']} because it references temp, download, cache, or remote-origin execution paths.",
            identity,
            reason="Piggyback hooks should not jump to scratch paths, downloaded payloads, or remote URLs because that hides provenance behind an otherwise normal workflow trigger.",
            safer_alternative="Keep hook logic in a reviewed repo-local script or package-managed path and avoid temp or remote execution targets.",
        )
    elif identity["has_inline_wrapper"]:
        trust_state = "blocked"
        hit = _hit(
            "hook-wrapper-escalation-guard",
            "block",
            f"Blocked {identity['surface']} because it now executes through an inline interpreter or wrapper chain.",
            identity,
            reason="Inline shell and interpreter wrappers make hook provenance much weaker and are a common way to smuggle a second execution stage into normal workflow triggers.",
            safer_alternative="Call a reviewed script file directly instead of using inline interpreter payloads in hook-bearing surfaces.",
        )
    elif identity["has_network_fanout"]:
        trust_state = "blocked"
        hit = _hit(
            "hook-fanout-network-guard",
            "block",
            f"Blocked {identity['surface']} because it adds outbound network, upload, or tunnel behavior to a normal workflow trigger.",
            identity,
            reason="Piggyback hooks become much more dangerous when they fan out to the network, because a routine local action turns into exfiltration or remote code staging.",
            safer_alternative="Keep network actions out of implicit hooks and move them into reviewed explicit workflow steps.",
        )
    elif identity["has_stealth_persistence"]:
        trust_state = "blocked"
        hit = _hit(
            "hook-stealth-persistence-guard",
            "block",
            f"Blocked {identity['surface']} because it includes stealth, delayed, or background persistence behavior.",
            identity,
            reason="Backgrounding, delayed launch, and stealthy redirection are strong indicators that a hook is trying to hide side effects behind a normal trigger.",
            safer_alternative="Use visible, foreground, reviewed workflow steps instead of stealthy background execution in hook-bearing files.",
        )
    elif existing:
        if existing.get("trust_state") == "approved" and existing.get("content_hash") == identity["content_hash"]:
            trust_state = "approved"
        elif existing.get("content_hash") != identity["content_hash"]:
            trust_state = "prompted"
            updated = _record(identity, trust_state, existing)
            updated["last_drift"] = {
                "previous": {
                    "content_hash": existing.get("content_hash"),
                    "content_preview": existing.get("content_preview"),
                    "has_inline_wrapper": existing.get("has_inline_wrapper"),
                    "has_network_fanout": existing.get("has_network_fanout"),
                    "has_stealth_persistence": existing.get("has_stealth_persistence"),
                    "has_external_refs": existing.get("has_external_refs"),
                },
                "current": {
                    "content_hash": identity["content_hash"],
                    "content_preview": identity["content_preview"],
                    "has_inline_wrapper": identity["has_inline_wrapper"],
                    "has_network_fanout": identity["has_network_fanout"],
                    "has_stealth_persistence": identity["has_stealth_persistence"],
                    "has_external_refs": identity["has_external_refs"],
                },
            }
            hooks[key] = updated
            save_store(root, store)
            return {
                "identity": identity,
                "hit": _hit(
                    "hook-drift-guard",
                    "prompt",
                    f"Review required because {identity['surface']} changed since Runwall last saw or approved it.",
                    identity,
                    reason="A previously observed hook-bearing surface changed its contents, which means the trigger may now execute different behavior than the version you reviewed.",
                    safer_alternative=f"Run `./bin/runwall hooks diff {shlex.quote(identity['location'])}` and then `./bin/runwall hooks approve {shlex.quote(identity['location'])}` if the change is legitimate.",
                ),
            }
        else:
            trust_state = existing.get("trust_state", "trusted")
    elif identity["review_surface"]:
        trust_state = "prompted"
        hit = _hit(
            "hook-review-boundary-guard",
            "prompt",
            f"Review required before trusting first-seen {identity['surface']} changes at {identity['location']}.",
            identity,
            reason="This hook-bearing surface can execute during routine developer workflows, so Runwall asks for a one-time local review before treating it as trusted.",
            safer_alternative=f"Review the hook contents and then run `./bin/runwall hooks approve {shlex.quote(identity['location'])}` if this trigger is expected.",
        )
    else:
        trust_state = "trusted"

    hooks[key] = _record(identity, trust_state, existing)
    save_store(root, store)
    return {"identity": identity, "hit": hit}


def list_hooks(root: pathlib.Path) -> list[dict[str, Any]]:
    store = load_store(root)
    items = []
    for key, record in store.get("hooks", {}).items():
        if isinstance(record, dict):
            items.append(dict(record, identity_key=key))
    items.sort(key=lambda item: (item.get("surface", ""), item.get("location", "")))
    return items


def _find_record(hooks: dict[str, Any], selector: str) -> tuple[str, dict[str, Any]] | tuple[None, None]:
    record = hooks.get(selector)
    if isinstance(record, dict):
        return selector, record
    for key, candidate in hooks.items():
        if not isinstance(candidate, dict):
            continue
        if candidate.get("location") == selector:
            return key, candidate
    return None, None


def approve_hook(root: pathlib.Path, selector: str) -> bool:
    store = load_store(root)
    hooks = store.setdefault("hooks", {})
    key, record = _find_record(hooks, selector)
    if key is None or record is None:
        return False
    record["trust_state"] = "approved"
    record["approved_at"] = utc_now()
    hooks[key] = record
    save_store(root, store)
    return True


def forget_hook(root: pathlib.Path, selector: str) -> bool:
    store = load_store(root)
    hooks = store.setdefault("hooks", {})
    key, _ = _find_record(hooks, selector)
    if key is None:
        return False
    hooks.pop(key, None)
    save_store(root, store)
    return True


def diff_hook(root: pathlib.Path, selector: str) -> dict[str, Any] | None:
    store = load_store(root)
    key, record = _find_record(store.setdefault("hooks", {}), selector)
    if key is None or record is None:
        return None
    payload = {
        "identity_key": key,
        "location": record.get("location"),
        "surface": record.get("surface"),
        "trigger": record.get("trigger"),
        "trust_state": record.get("trust_state"),
        "last_drift": record.get("last_drift"),
    }
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage Runwall hook trust state")
    parser.add_argument("--root", required=True)
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list")
    list_parser.add_argument("--json", action="store_true")

    approve_parser = subparsers.add_parser("approve")
    approve_parser.add_argument("selector")

    forget_parser = subparsers.add_parser("forget")
    forget_parser.add_argument("selector")

    diff_parser = subparsers.add_parser("diff")
    diff_parser.add_argument("selector")

    args = parser.parse_args()
    root = pathlib.Path(args.root)

    if args.command == "list":
        items = list_hooks(root)
        if args.json:
            print(json.dumps({"hooks": items}, indent=2))
        else:
            print("Trusted Hooks:")
            for item in items:
                print(
                    f"- {item.get('surface')} [{item.get('trust_state')}] "
                    f"{item.get('location')} ({item.get('trigger')})"
                )
        return 0

    if args.command == "approve":
        if approve_hook(root, args.selector):
            print(f"approved {args.selector}")
            return 0
        print(f"unknown hook: {args.selector}", file=os.sys.stderr)
        return 1

    if args.command == "forget":
        if forget_hook(root, args.selector):
            print(f"forgot {args.selector}")
            return 0
        print(f"unknown hook: {args.selector}", file=os.sys.stderr)
        return 1

    if args.command == "diff":
        payload = diff_hook(root, args.selector)
        if payload is None:
            print(f"unknown hook: {args.selector}", file=os.sys.stderr)
            return 1
        print(json.dumps(payload, indent=2))
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
