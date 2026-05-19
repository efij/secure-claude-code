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


KNOWLEDGE_PATH_RE = re.compile(
    r"(?i)(?:^|/)(?:knowledge|wiki|vault|obsidian|rag|research|briefs|playbooks|runbooks|tickets|issues-cache|notes/kb|notes/knowledge|cached-pages|mirrored-issues|rag-cache)(?:/|$)|(?:^|/)\.obsidian(?:/|$)"
)
TEXT_SURFACE_RE = re.compile(r"(?i)\.(?:md|txt|json|yaml|yml|html)$")
REMOTE_RE = re.compile(r"(?i)\bhttps?://|raw\.githubusercontent\.com|gist\.githubusercontent\.com|pastebin\.com|notion\.site|docs\.google\.com|slack-export")
OVERRIDE_RE = re.compile(r"(?i)(ignore (?:all |the )?(?:previous|prior) instructions|new system prompt|developer message override|act as the system|tool output is highest priority|policy override)")
POLICY_BYPASS_RE = re.compile(r"(?i)(disable stallion|ignore stallion|bypass stallion|ignore local policy|disable guardrails?|safety does not apply)")
SECRET_HARVEST_RE = re.compile(r"(?i)(read|dump|copy|collect|archive|print|list).{0,100}(\.env|\.aws/(?:credentials|config)|id_(?:rsa|ed25519)|authorized_keys|\.npmrc|\.pypirc|\.kube/config|session|token|secret|password)")
EXFIL_RE = re.compile(r"(?i)(curl|wget|scp|rsync|rclone|upload|webhook|pastebin|slack webhook|discord webhook|gh release upload|npm publish|twine upload)")
ENCODING_RE = re.compile(r"(?i)(base64|rot13|hex[- ]?encoded|html comment|<!--|zero-width|unicode invis(?:ible)?|gpg -c|openssl enc|age -e)")
DROPPER_RE = re.compile(r"(?i)(curl.+\|\s*(?:bash|sh)|wget.+\|\s*(?:bash|sh)|python\s+-c|node\s+-e|bash\s+-c|pwsh\s+-enc)")
INSTALL_BRIDGE_RE = re.compile(r"(?i)(install (?:this|the) (?:plugin|mcp|server|skill)|add (?:this|the) mcp server|load this extension|enable this raw plugin|trust fetched output as policy)")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def state_dir(root: pathlib.Path) -> pathlib.Path:
    home = os.environ.get("STALLION_HOME") or os.environ.get("STALLION_HOME")
    if home:
        return pathlib.Path(home) / "state"
    return pathlib.Path(os.path.expanduser("~")) / ".stallion" / "state"


def knowledge_store_path(root: pathlib.Path) -> pathlib.Path:
    return state_dir(root) / "knowledge.json"


def load_store(root: pathlib.Path) -> dict[str, Any]:
    path = knowledge_store_path(root)
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
    path = knowledge_store_path(root)
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


def _fileop_surface(matcher: str, payload: str) -> tuple[pathlib.Path | None, str]:
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
        "category": "knowledge-trust",
        "family": "Memory & Knowledge",
        "decision": decision,
        "exit_code": 2 if decision == "block" else 0,
        "output": reason,
        "metadata": {
            "reason": reason,
            "confidence": 0.96 if decision == "block" else 0.84,
            "safer_alternative": safer,
            "knowledge_identity": identity,
        },
    }


def infer_knowledge_identity(matcher: str, payload: str) -> tuple[pathlib.Path | None, str, dict[str, Any] | None]:
    if matcher not in {"Read", "Write", "Edit", "MultiEdit"}:
        return None, "", None
    path, content = _fileop_surface(matcher, payload)
    if path is None:
        return None, "", None
    location = str(path).replace("\\", "/")
    if not KNOWLEDGE_PATH_RE.search(location):
        return path, content, None
    if path.suffix and not TEXT_SURFACE_RE.search(path.name):
        return path, content, None
    surface = "obsidian-vault" if ".obsidian" in location.lower() or "/vault/" in location.lower() else "knowledge-source"
    identity = {
        "path": str(path),
        "surface": surface,
        "fingerprint": _fingerprint(content) if content else None,
        "matcher": matcher,
    }
    return path, content, identity


def assess_fileop(root: pathlib.Path, event: str, matcher: str, payload: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
    if event != "PreToolUse":
        return {"identity": None, "hit": None}
    path, content, identity = infer_knowledge_identity(matcher, payload)
    if identity is None or path is None:
        return {"identity": None, "hit": None}
    store = load_store(root)
    record = store.setdefault("sources", {}).get(str(path))
    fingerprint = identity.get("fingerprint")
    hit = None
    trust_state = record.get("trust_state") if isinstance(record, dict) else "observed"

    if isinstance(record, dict) and record.get("trust_state") == "quarantined":
        hit = _hit(
            "knowledge-quarantine-bypass-guard",
            "block",
            identity,
            f"Blocked access to quarantined knowledge source {path}.",
            f"Review the source first and move it out of quarantine with `./bin/stallion knowledge trust {path}` only if it is safe.",
        )
        trust_state = "quarantined"
    elif matcher in {"Write", "Edit", "MultiEdit"} and isinstance(record, dict) and record.get("trust_state") == "trusted" and fingerprint and record.get("fingerprint") and record.get("fingerprint") != fingerprint:
        hit = _hit(
            "knowledge-drift-guard",
            "prompt",
            identity,
            f"Review required because trusted knowledge source {path} changed.",
            f"Run `./bin/stallion knowledge diff {path}` and then `./bin/stallion knowledge trust {path}` if the new source content is expected.",
        )
        trust_state = "drifted"
    elif matcher in {"Write", "Edit", "MultiEdit"} and not isinstance(record, dict):
        hit = _hit(
            "knowledge-source-review-guard",
            "prompt",
            identity,
            f"Review required before new knowledge source {path} becomes trusted.",
            f"Run `./bin/stallion knowledge trust {path}` only after confirming this vault, RAG cache, or imported knowledge surface is expected.",
        )
        trust_state = "observed"

    if matcher in {"Write", "Edit", "MultiEdit"}:
        if DROPPER_RE.search(content):
            hit = _hit(
                "knowledge-rag-cache-dropper-guard",
                "block",
                identity,
                f"Blocked staged execution or dropper content in knowledge source {path}.",
                "Do not let RAG caches or mirrored notes become a delivery channel for shell and interpreter payloads.",
            )
            trust_state = "quarantined"
        elif INSTALL_BRIDGE_RE.search(content):
            hit = _hit(
                "knowledge-tool-install-bridge-guard",
                "block",
                identity,
                f"Blocked trust-bridge instructions for tools, plugins, or MCP servers in knowledge source {path}.",
                "Keep tool-install and trust-boundary changes out of imported knowledge unless they go through reviewed runtime config or policy.",
            )
            trust_state = "quarantined"
        elif REMOTE_RE.search(content):
            hit = _hit(
                "knowledge-remote-ingest-guard",
                "block",
                identity,
                f"Blocked remote or pasted external content from being written directly into trusted knowledge source {path}.",
                "Review external knowledge before promoting it into trusted local vaults, RAG caches, or mirrored issue stores.",
            )
            trust_state = "quarantined"
        elif OVERRIDE_RE.search(content):
            hit = _hit(
                "knowledge-prompt-smuggling-guard",
                "block",
                identity,
                f"Blocked prompt-smuggling or override language in knowledge source {path}.",
                "Keep knowledge surfaces factual and reviewable instead of storing instruction-priority tricks or override payloads.",
            )
            trust_state = "quarantined"
        elif POLICY_BYPASS_RE.search(content):
            hit = _hit(
                "knowledge-policy-override-guard",
                "block",
                identity,
                f"Blocked policy-bypass language in knowledge source {path}.",
                "Do not use vault or RAG content as a way to silently weaken local runtime policy.",
            )
            trust_state = "quarantined"
        elif EXFIL_RE.search(content):
            hit = _hit(
                "knowledge-exfil-instruction-guard",
                "block",
                identity,
                f"Blocked exfiltration instructions in knowledge source {path}.",
                "Keep upload, webhook, and publish instructions out of trusted vaults and RAG sources unless they are narrowly reviewed elsewhere.",
            )
            trust_state = "quarantined"
        elif SECRET_HARVEST_RE.search(content):
            hit = _hit(
                "knowledge-secret-harvest-instruction-guard",
                "block",
                identity,
                f"Blocked secret-harvest instructions in knowledge source {path}.",
                "Knowledge sources should not instruct the runtime to gather secrets from local or cloud stores.",
            )
            trust_state = "quarantined"
        elif ENCODING_RE.search(content):
            hit = _hit(
                "knowledge-hidden-encoding-guard",
                "block",
                identity,
                f"Blocked hidden or encoded instruction content in knowledge source {path}.",
                "Trusted knowledge should not carry encoded or hidden instruction bodies that bypass straightforward review.",
            )
            trust_state = "quarantined"

    updated = {
        "path": str(path),
        "surface": identity["surface"],
        "fingerprint": fingerprint or (record or {}).get("fingerprint"),
        "trust_state": trust_state,
        "first_seen_at": (record or {}).get("first_seen_at", utc_now()) if isinstance(record, dict) else utc_now(),
        "last_seen_at": utc_now(),
        "last_reason": hit["module"] if hit else (record or {}).get("last_reason") if isinstance(record, dict) else None,
        "last_drift": utc_now() if hit and hit["module"] == "knowledge-drift-guard" else (record or {}).get("last_drift") if isinstance(record, dict) else None,
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
    parser = argparse.ArgumentParser(description="Manage Stallion knowledge trust")
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
            print("Knowledge Sources:")
            for item in items:
                print(f"- {item.get('trust_state')} {item.get('path')}")
        return 0
    if args.command == "trust":
        if set_trust(root, args.selector, "trusted"):
            print(f"trusted {args.selector}")
            return 0
        print(f"unknown knowledge source: {args.selector}", file=os.sys.stderr)
        return 1
    if args.command == "quarantine":
        if set_trust(root, args.selector, "quarantined"):
            print(f"quarantined {args.selector}")
            return 0
        print(f"unknown knowledge source: {args.selector}", file=os.sys.stderr)
        return 1
    if args.command == "forget":
        if forget_source(root, args.selector):
            print(f"forgot {args.selector}")
            return 0
        print(f"unknown knowledge source: {args.selector}", file=os.sys.stderr)
        return 1
    if args.command == "diff":
        payload = diff_source(root, args.selector)
        if payload is None:
            print(f"unknown knowledge source: {args.selector}", file=os.sys.stderr)
            return 1
        print(json.dumps(payload, indent=2))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
