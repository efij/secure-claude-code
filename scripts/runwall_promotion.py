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
KNOWLEDGE_PATH_RE = re.compile(
    r"(?i)(?:^|/)(?:knowledge|wiki|vault|obsidian|rag|research|briefs|playbooks|runbooks|tickets|issues-cache|notes/kb|notes/knowledge|cached-pages|mirrored-issues|rag-cache)(?:/|$)|(?:^|/)\.obsidian(?:/|$)"
)
AGENT_DOC_RE = re.compile(r"(?i)(?:^|/)(?:CLAUDE\.md|AGENTS\.md|\.claude/commands/[^/]+\.md|\.codex/AGENTS\.md)$")
POLICY_SURFACE_RE = re.compile(r"(?i)(?:^|/)(?:\.mcp\.json|hooks/hooks\.json|\.claude-plugin/[^/]+\.json|\.codex-plugin/[^/]+\.json|\.runwall/(?:config|state)/[^/]+|settings\.json)$")
SCRIPT_SURFACE_RE = re.compile(r"(?i)(?:^|/)(?:bin|scripts|hooks|ci|ops)/[^/]+\.(?:sh|py|js|ps1|rb|pl)$|(?:^|/)\.github/workflows/[^/]+\.(?:yml|yaml)$")
HOOK_SURFACE_RE = re.compile(r"(?i)(?:^|/)(?:\.git/hooks|\.githooks|hooks/hooks\.json)")
REMOTE_RE = re.compile(r"(?i)\bhttps?://|raw\.githubusercontent\.com|gist\.githubusercontent\.com|pastebin\.com|notion\.site|docs\.google\.com|slack-export")
RAW_HOST_RE = re.compile(r"(?i)(raw\.githubusercontent\.com|gist\.githubusercontent\.com|pastebin\.com|transfer\.sh|gist\.github\.com)")
PASTE_RE = re.compile(r"(?i)(paste this|copy this exactly|save this exact content|drop this into|mirror this output|use this exact file|promote this into)")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def state_dir(root: pathlib.Path) -> pathlib.Path:
    home = os.environ.get("RUNWALL_HOME") or os.environ.get("SECURE_CLAUDE_CODE_HOME")
    if home:
        return pathlib.Path(home) / "state"
    return pathlib.Path(os.path.expanduser("~")) / ".runwall" / "state"


def promotion_store_path(root: pathlib.Path) -> pathlib.Path:
    return state_dir(root) / "promotion.json"


def load_store(root: pathlib.Path) -> dict[str, Any]:
    path = promotion_store_path(root)
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
    path = promotion_store_path(root)
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


def _surface_type(path: pathlib.Path) -> str | None:
    location = str(path).replace("\\", "/")
    if MEMORY_PATH_RE.search(location):
        return "memory-surface"
    if KNOWLEDGE_PATH_RE.search(location):
        return "knowledge-surface"
    if AGENT_DOC_RE.search(location):
        return "agent-doc"
    if HOOK_SURFACE_RE.search(location):
        return "hook-surface"
    if POLICY_SURFACE_RE.search(location):
        return "policy-surface"
    if SCRIPT_SURFACE_RE.search(location):
        return "script-surface"
    return None


def _identity(matcher: str, payload: str) -> tuple[pathlib.Path | None, str, dict[str, Any] | None]:
    if matcher not in {"Read", "Write", "Edit", "MultiEdit"}:
        return None, "", None
    path, content = _fileop_surface(matcher, payload)
    if path is None:
        return None, "", None
    surface = _surface_type(path)
    if not surface:
        return path, content, None
    return path, content, {
        "path": str(path),
        "surface": surface,
        "matcher": matcher,
        "fingerprint": _fingerprint(content) if content else None,
    }


def _hit(module: str, decision: str, identity: dict[str, Any], reason: str, safer: str) -> dict[str, Any]:
    return {
        "module": module,
        "name": module.replace("-", " ").title(),
        "category": "promotion-trust",
        "family": "Remote Content Promotion",
        "decision": decision,
        "exit_code": 2 if decision == "block" else 0,
        "output": reason,
        "metadata": {
            "reason": reason,
            "confidence": 0.96 if decision == "block" else 0.84,
            "safer_alternative": safer,
            "promotion_identity": identity,
        },
    }


def assess_fileop(root: pathlib.Path, event: str, matcher: str, payload: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = context
    if event != "PreToolUse":
        return {"identity": None, "hit": None}
    path, content, identity = _identity(matcher, payload)
    if identity is None or path is None:
        return {"identity": None, "hit": None}
    store = load_store(root)
    record = store.setdefault("sources", {}).get(str(path))
    trust_state = record.get("trust_state") if isinstance(record, dict) else "observed"
    hit = None

    if isinstance(record, dict) and record.get("trust_state") == "quarantined":
        hit = _hit(
            "promotion-quarantine-bypass-guard",
            "block",
            identity,
            f"Blocked access to quarantined promoted surface {path}.",
            f"Review the surface first and only trust it again with `./bin/runwall promotion trust {path}` if the content is actually safe.",
        )
        trust_state = "quarantined"
    elif matcher in {"Write", "Edit", "MultiEdit"} and REMOTE_RE.search(content):
        surface = str(identity.get("surface"))
        location = str(path)
        if RAW_HOST_RE.search(content):
            hit = _hit(
                "raw-host-promotion-guard",
                "block",
                identity,
                f"Blocked promotion of raw or paste-hosted content into trusted surface {location}.",
                "Move remote content into a neutral review file first instead of promoting raw-hosted content straight into trusted local authority surfaces.",
            )
            trust_state = "quarantined"
        elif surface == "memory-surface":
            hit = _hit(
                "remote-to-memory-promotion-guard",
                "block",
                identity,
                f"Blocked remote content promotion into memory surface {location}.",
                "Keep external content out of persistent memory until it has been reviewed and rewritten into safe local context.",
            )
            trust_state = "quarantined"
        elif surface == "knowledge-surface":
            hit = _hit(
                "remote-to-knowledge-promotion-guard",
                "block",
                identity,
                f"Blocked remote content promotion into knowledge or RAG surface {location}.",
                "Review external knowledge in a neutral staging file before promoting it into vaults, RAG caches, or mirrored knowledge stores.",
            )
            trust_state = "quarantined"
        elif surface == "hook-surface":
            hit = _hit(
                "remote-to-hook-promotion-guard",
                "block",
                identity,
                f"Blocked remote content promotion into hook-bearing surface {location}.",
                "Do not promote remote or pasted content directly into hooks, because that turns fetched text into executable behavior.",
            )
            trust_state = "quarantined"
        elif surface == "policy-surface":
            hit = _hit(
                "remote-to-policy-promotion-guard",
                "block",
                identity,
                f"Blocked remote content promotion into policy or config surface {location}.",
                "Keep MCP, plugin, settings, and Runwall policy files locally reviewed instead of filling them from remote content.",
            )
            trust_state = "quarantined"
        elif surface == "script-surface":
            hit = _hit(
                "remote-to-script-promotion-guard",
                "block",
                identity,
                f"Blocked remote content promotion into script or workflow surface {location}.",
                "Do not promote remote or pasted content straight into scripts, hooks, workflows, or executable bins.",
            )
            trust_state = "quarantined"
        elif surface == "agent-doc":
            hit = _hit(
                "remote-to-agent-doc-promotion-guard",
                "block",
                identity,
                f"Blocked remote content promotion into agent instruction surface {location}.",
                "Keep agent instructions local and reviewed. Remote content should not become trusted instructions in one step.",
            )
            trust_state = "quarantined"
        elif PASTE_RE.search(content):
            hit = _hit(
                "paste-to-trusted-surface-guard",
                "prompt",
                identity,
                f"Review required before pasted external content is promoted into trusted surface {location}.",
                "Rewrite or summarize pasted content into a reviewed local form before storing it in trusted surfaces.",
            )
            trust_state = "observed"

    updated = {
        "path": str(path),
        "surface": identity.get("surface"),
        "fingerprint": identity.get("fingerprint") or (record or {}).get("fingerprint"),
        "trust_state": trust_state,
        "first_seen_at": (record or {}).get("first_seen_at", utc_now()),
        "last_seen_at": utc_now(),
        "last_reason": hit["module"] if hit else (record or {}).get("last_reason"),
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
    parser = argparse.ArgumentParser(description="Manage Runwall remote content promotion trust")
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
            print("Promotion Sources:")
            for item in items:
                print(f"- {item.get('trust_state')} {item.get('surface')} {item.get('path')}")
        return 0
    if args.command == "trust":
        if set_trust(root, args.selector, "trusted"):
            print(f"trusted {args.selector}")
            return 0
        print(f"unknown promotion source: {args.selector}", file=os.sys.stderr)
        return 1
    if args.command == "quarantine":
        if set_trust(root, args.selector, "quarantined"):
            print(f"quarantined {args.selector}")
            return 0
        print(f"unknown promotion source: {args.selector}", file=os.sys.stderr)
        return 1
    if args.command == "forget":
        if forget_source(root, args.selector):
            print(f"forgot {args.selector}")
            return 0
        print(f"unknown promotion source: {args.selector}", file=os.sys.stderr)
        return 1
    if args.command == "diff":
        payload = diff_source(root, args.selector)
        if payload is None:
            print(f"unknown promotion source: {args.selector}", file=os.sys.stderr)
            return 1
        print(json.dumps(payload, indent=2))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
