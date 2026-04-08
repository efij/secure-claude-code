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


MEMORY_PATH_RE = re.compile(
    r"(?i)(?:^|/)(?:memory(?:[-_](?:store|state|journal|notes|cache|context|scratch))?\.(?:md|txt|json|yaml|yml)|project-memory\.md|session-memory\.json|agent-memory\.json|context-memory\.md|team-memory\.md|memory\.md|notes-to-self\.md|scratchpad\.md|decision-log\.md)$|(?:^|/)\.(?:claude|codex|runwall|agents)/memory(?:/|$)"
)
REMOTE_RE = re.compile(r"(?i)\bhttps?://|raw\.githubusercontent\.com|gist\.githubusercontent\.com|pastebin\.com|notion\.site|docs\.google\.com")
INSTRUCTION_RE = re.compile(r"(?i)\b(remember|persist|store|treat this as|save this|use this as)\b")
OVERRIDE_RE = re.compile(r"(?i)(ignore (?:all |the )?(?:previous|prior) instructions|new system prompt|developer message override|act as the system|system override|priority instruction)")
POLICY_BYPASS_RE = re.compile(r"(?i)(disable runwall|ignore runwall|bypass runwall|ignore local policy|turn off sandbox|disable guardrails?|treat safety as optional)")
SECRET_HARVEST_RE = re.compile(r"(?i)(read|dump|copy|collect|archive|print|exfiltrate).{0,80}(\.env|\.aws/(?:credentials|config)|id_(?:rsa|ed25519)|authorized_keys|\.npmrc|\.pypirc|\.kube/config|session|token|secret|password)")
EXFIL_RE = re.compile(r"(?i)(curl|wget|scp|rsync|rclone|upload|webhook|pastebin|slack webhook|discord webhook|gh release upload|npm publish|twine upload)")
ENCODING_RE = re.compile(r"(?i)(base64|rot13|hex[- ]?encoded|html comment|<!--|zero-width|unicode invis(?:ible)?|gpg -c|openssl enc|age -e)")
TOOL_TRUST_RE = re.compile(r"(?i)(trust tool output|install (?:this|the) (?:plugin|mcp|server|skill)|add (?:this|the) mcp server|run this generated cli|treat fetched output as trusted)")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def state_dir(root: pathlib.Path) -> pathlib.Path:
    home = os.environ.get("RUNWALL_HOME") or os.environ.get("SECURE_CLAUDE_CODE_HOME")
    if home:
        return pathlib.Path(home) / "state"
    return pathlib.Path(os.path.expanduser("~")) / ".runwall" / "state"


def memory_store_path(root: pathlib.Path) -> pathlib.Path:
    return state_dir(root) / "memory.json"


def load_store(root: pathlib.Path) -> dict[str, Any]:
    path = memory_store_path(root)
    if not path.exists():
        return {"version": 1, "sources": {}}
    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {"version": 1, "sources": {}}
    if not isinstance(payload, dict):
        return {"version": 1, "sources": {}}
    payload.setdefault("version", 1)
    payload.setdefault("sources", {})
    return payload


def save_store(root: pathlib.Path, store: dict[str, Any]) -> None:
    path = memory_store_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(store, indent=2, sort_keys=True) + "\n")


def _shell_split(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=os.name != "nt")
    except ValueError:
        return [token for token in command.strip().split() if token]


def _normalize_path_token(token: str) -> pathlib.Path:
    stripped = token.strip("'\"= ")
    expanded = os.path.expanduser(stripped)
    path = pathlib.Path(expanded)
    if not path.is_absolute():
        path = pathlib.Path(os.path.abspath(str(pathlib.Path.cwd() / path)))
    return path


def _write_surface(matcher: str, payload: str) -> tuple[pathlib.Path | None, str]:
    tokens = _shell_split(payload)
    if not tokens:
        return None, ""
    first = tokens[0]
    path = _normalize_path_token(first)
    if matcher in {"Write", "Edit", "MultiEdit"}:
        return path, payload[len(first) :].strip()
    return path, ""


def _fingerprint(text: str) -> str:
    return hashlib.sha256(re.sub(r"\s+", " ", text.strip()).encode("utf-8")).hexdigest()


def _hit(module: str, decision: str, identity: dict[str, Any], reason: str, safer: str) -> dict[str, Any]:
    return {
        "module": module,
        "name": module.replace("-", " ").title(),
        "category": "memory-trust",
        "family": "Memory & Knowledge",
        "decision": decision,
        "exit_code": 2 if decision == "block" else 0,
        "output": reason,
        "metadata": {
            "reason": reason,
            "confidence": 0.96 if decision == "block" else 0.84,
            "safer_alternative": safer,
            "memory_identity": identity,
        },
    }


def infer_memory_identity(matcher: str, payload: str) -> tuple[pathlib.Path | None, str, dict[str, Any] | None]:
    if matcher not in {"Read", "Write", "Edit", "MultiEdit"}:
        return None, "", None
    path, content = _write_surface(matcher, payload)
    if path is None:
        return None, "", None
    location = str(path).replace("\\", "/")
    if not MEMORY_PATH_RE.search(location):
        return path, content, None
    identity = {
        "path": str(path),
        "surface": "memory-source",
        "fingerprint": _fingerprint(content) if content else None,
        "matcher": matcher,
    }
    return path, content, identity


def _record(store: dict[str, Any], path: str) -> dict[str, Any] | None:
    item = store.setdefault("sources", {}).get(path)
    if isinstance(item, dict):
        return item
    return None


def assess_fileop(root: pathlib.Path, event: str, matcher: str, payload: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
    if event != "PreToolUse":
        return {"identity": None, "hit": None}
    path, content, identity = infer_memory_identity(matcher, payload)
    if identity is None or path is None:
        return {"identity": None, "hit": None}
    store = load_store(root)
    record = _record(store, str(path))
    fingerprint = identity.get("fingerprint")
    hit = None
    trust_state = record.get("trust_state") if record else "observed"

    if record and record.get("trust_state") == "quarantined":
        hit = _hit(
            "memory-quarantine-bypass-guard",
            "block",
            identity,
            f"Blocked access to quarantined memory source {path}.",
            f"Review the source first and move it out of quarantine with `./bin/runwall memory trust {path}` only if it is actually safe.",
        )
        trust_state = "quarantined"
    elif matcher in {"Write", "Edit", "MultiEdit"} and record and record.get("trust_state") == "trusted" and fingerprint and record.get("fingerprint") and record.get("fingerprint") != fingerprint:
        hit = _hit(
            "memory-drift-guard",
            "prompt",
            identity,
            f"Review required because trusted memory source {path} changed.",
            f"Run `./bin/runwall memory diff {path}` and then `./bin/runwall memory trust {path}` if the new memory content is expected.",
        )
        trust_state = "drifted"
    elif matcher in {"Write", "Edit", "MultiEdit"} and not record:
        hit = _hit(
            "memory-source-review-guard",
            "prompt",
            identity,
            f"Review required before new memory source {path} becomes trusted.",
            f"Run `./bin/runwall memory trust {path}` only after confirming this is a legitimate persistent memory surface.",
        )
        trust_state = "observed"

    if matcher in {"Write", "Edit", "MultiEdit"}:
        if REMOTE_RE.search(content) and INSTRUCTION_RE.search(content):
            hit = _hit(
                "memory-remote-ingest-guard",
                "block",
                identity,
                f"Blocked remote or pasted external content from being written directly into memory source {path}.",
                "Review external content before promoting it into trusted memory, and keep raw web or paste content out of persistent memory stores.",
            )
            trust_state = "quarantined"
        elif OVERRIDE_RE.search(content):
            hit = _hit(
                "memory-prompt-smuggling-guard",
                "block",
                identity,
                f"Blocked prompt-smuggling or override language in memory source {path}.",
                "Keep persistent memory focused on factual workflow state, not instruction-priority tricks or system-prompt overrides.",
            )
            trust_state = "quarantined"
        elif POLICY_BYPASS_RE.search(content):
            hit = _hit(
                "memory-policy-override-guard",
                "block",
                identity,
                f"Blocked policy-bypass language in memory source {path}.",
                "Do not store instructions that weaken Runwall or local runtime policy inside persistent memory.",
            )
            trust_state = "quarantined"
        elif EXFIL_RE.search(content):
            hit = _hit(
                "memory-exfil-instruction-guard",
                "block",
                identity,
                f"Blocked exfiltration instructions in memory source {path}.",
                "Keep upload, webhook, and publish instructions out of trusted memory unless they are narrowly reviewed elsewhere.",
            )
            trust_state = "quarantined"
        elif SECRET_HARVEST_RE.search(content):
            hit = _hit(
                "memory-secret-harvest-instruction-guard",
                "block",
                identity,
                f"Blocked secret-harvest instructions in memory source {path}.",
                "Persistent memory should not instruct the runtime to collect or dump secrets from local stores.",
            )
            trust_state = "quarantined"
        elif ENCODING_RE.search(content):
            hit = _hit(
                "memory-hidden-encoding-guard",
                "block",
                identity,
                f"Blocked hidden or encoded instruction content in memory source {path}.",
                "Persistent memory should not carry encoded or hidden instruction bodies that make review harder.",
            )
            trust_state = "quarantined"
        elif TOOL_TRUST_RE.search(content):
            hit = _hit(
                "memory-tool-trust-override-guard",
                "block",
                identity,
                f"Blocked trust-boundary override instructions in memory source {path}.",
                "Do not use memory as a way to silently trust fetched tools, plugins, or generated CLIs.",
            )
            trust_state = "quarantined"

    updated = {
        "path": str(path),
        "surface": "memory-source",
        "fingerprint": fingerprint or (record or {}).get("fingerprint"),
        "trust_state": trust_state,
        "first_seen_at": (record or {}).get("first_seen_at", utc_now()),
        "last_seen_at": utc_now(),
        "last_reason": hit["module"] if hit else (record or {}).get("last_reason"),
        "last_drift": utc_now() if hit and hit["module"] == "memory-drift-guard" else (record or {}).get("last_drift"),
    }
    store.setdefault("sources", {})[str(path)] = updated
    save_store(root, store)
    return {"identity": identity, "hit": hit}


def list_sources(root: pathlib.Path) -> list[dict[str, Any]]:
    items = [dict(item) for item in load_store(root).get("sources", {}).values() if isinstance(item, dict)]
    items.sort(key=lambda item: item.get("path", ""))
    return items


def set_trust(root: pathlib.Path, selector: str, state: str) -> bool:
    store = load_store(root)
    record = store.setdefault("sources", {}).get(selector)
    if not isinstance(record, dict):
        return False
    record["trust_state"] = state
    record["last_seen_at"] = utc_now()
    save_store(root, store)
    return True


def forget_source(root: pathlib.Path, selector: str) -> bool:
    store = load_store(root)
    if selector in store.setdefault("sources", {}):
        store["sources"].pop(selector, None)
        save_store(root, store)
        return True
    return False


def diff_source(root: pathlib.Path, selector: str) -> dict[str, Any] | None:
    record = load_store(root).get("sources", {}).get(selector)
    if isinstance(record, dict):
        return record
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage Runwall memory trust")
    parser.add_argument("--root", required=True)
    subparsers = parser.add_subparsers(dest="command", required=True)
    list_parser = subparsers.add_parser("list")
    list_parser.add_argument("--json", action="store_true")
    trust_parser = subparsers.add_parser("trust")
    trust_parser.add_argument("selector")
    quarantine_parser = subparsers.add_parser("quarantine")
    quarantine_parser.add_argument("selector")
    forget_parser = subparsers.add_parser("forget")
    forget_parser.add_argument("selector")
    diff_parser = subparsers.add_parser("diff")
    diff_parser.add_argument("selector")
    args = parser.parse_args()
    root = pathlib.Path(args.root)
    if args.command == "list":
        items = list_sources(root)
        if args.json:
            print(json.dumps({"sources": items}, indent=2))
        else:
            print("Memory Sources:")
            for item in items:
                print(f"- {item.get('trust_state')} {item.get('path')}")
        return 0
    if args.command == "trust":
        if set_trust(root, args.selector, "trusted"):
            print(f"trusted {args.selector}")
            return 0
        print(f"unknown memory source: {args.selector}", file=os.sys.stderr)
        return 1
    if args.command == "quarantine":
        if set_trust(root, args.selector, "quarantined"):
            print(f"quarantined {args.selector}")
            return 0
        print(f"unknown memory source: {args.selector}", file=os.sys.stderr)
        return 1
    if args.command == "forget":
        if forget_source(root, args.selector):
            print(f"forgot {args.selector}")
            return 0
        print(f"unknown memory source: {args.selector}", file=os.sys.stderr)
        return 1
    if args.command == "diff":
        payload = diff_source(root, args.selector)
        if payload is None:
            print(f"unknown memory source: {args.selector}", file=os.sys.stderr)
            return 1
        print(json.dumps(payload, indent=2))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
