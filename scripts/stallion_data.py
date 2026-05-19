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

import stallion_approvals


SQLITE_PATH_RE = re.compile(r"(?i)(?P<path>(?:~|\.{0,2}/|/)?[A-Za-z0-9_./@-]+\.(?:sqlite(?:3)?|db))")
SQLITE_DUMP_RE = re.compile(r"(?is)\bsqlite3\b[^\n\r]{0,260}\.dump\b|\bsqlite-utils\b[^\n\r]{0,260}\bdump\b")
SQLITE_BULK_RE = re.compile(r"(?is)\bsqlite3\b[^\n\r]{0,260}(?:select\s+\*|\.schema\b|attach\s+database\b)")
POSTGRES_DUMP_RE = re.compile(r"(?is)\bpg_dump(?:all)?\b|\bpsql\b[^\n\r]{0,260}(?:\\copy\b|copy\s*\()")
POSTGRES_LOCAL_RE = re.compile(r"(?i)(?:\b(?:psql|pg_dump(?:all)?)\b[^\n\r]{0,200}(?:-h(?:=|\s+)?|--host(?:=|\s+))(?:127\.0\.0\.1|localhost|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[0-1])\.\d+\.\d+))")
REDIS_EXPORT_RE = re.compile(r"(?is)\bredis-cli\b[^\n\r]{0,260}(?:--rdb\b|\bSAVE\b|\bBGSAVE\b|\bKEYS\s+\*|\bSCAN\s+0\b|\bCONFIG\s+GET\b)")
REDIS_LOCAL_RE = re.compile(r"(?i)\bredis-cli\b")
VECTOR_STORE_RE = re.compile(r"(?i)(?:^|/)(?:chroma(?:/|$)|\.chroma(?:/|$)|faiss(?:/|$)|qdrant(?:/|$)|lancedb(?:/|$)|weaviate(?:/|$)|milvus(?:/|$)|vectors?(?:/|$)|embeddings?(?:/|$)|chroma\.sqlite3$)")
BROWSER_INDEXEDDB_RE = re.compile(r"(?i)(?:IndexedDB|Local Storage|Session Storage|leveldb|Code Cache)")
APP_CACHE_DB_RE = re.compile(r"(?i)(?:Library/Application Support/(?:Slack|Discord|Notion|Obsidian|Claude|Codex|Cursor|Windsurf)|\.config/(?:Slack|discord|obsidian|Claude|Codex|Cursor|Windsurf)|AppData/Local/(?:Slack|Discord|Notion|Claude|Codex|Cursor|Windsurf))")
SESSION_DB_RE = re.compile(r"(?i)(?:Cookies|Login Data|Web Data|History|session|auth|token)")
COPY_ARCHIVE_RE = re.compile(r"(?i)\b(?:cp|copy|rsync|tar|zip|7z|scp|sftp|curl|aws\s+s3\s+cp|gsutil\s+cp)\b")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def state_dir(root: pathlib.Path) -> pathlib.Path:
    home = os.environ.get("STALLION_HOME") or os.environ.get("STALLION_HOME")
    if home:
        return pathlib.Path(home) / "state"
    return pathlib.Path(os.path.expanduser("~")) / ".stallion" / "state"


def data_store_path(root: pathlib.Path) -> pathlib.Path:
    return state_dir(root) / "data.json"


def load_store(root: pathlib.Path) -> dict[str, Any]:
    path = data_store_path(root)
    if not path.exists():
        return {"version": 1, "targets": {}}
    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {"version": 1, "targets": {}}
    if not isinstance(payload, dict):
        return {"version": 1, "targets": {}}
    payload.setdefault("version", 1)
    payload.setdefault("targets", {})
    return payload


def save_store(root: pathlib.Path, store: dict[str, Any]) -> None:
    path = data_store_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(store, indent=2, sort_keys=True) + "\n")


def _shell_split(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=os.name != "nt")
    except ValueError:
        return [token for token in command.strip().split() if token]


def _normalize_path(token: str) -> pathlib.Path:
    cleaned = token.strip("'\"= ")
    expanded = os.path.expanduser(cleaned)
    path = pathlib.Path(expanded)
    if not path.is_absolute():
        path = pathlib.Path(os.path.abspath(str(pathlib.Path.cwd() / path)))
    return path


def _file_fingerprint(path: pathlib.Path, store_class: str) -> str:
    resolved = path.resolve(strict=False)
    payload = f"{store_class}:{resolved}"
    try:
        stat = resolved.stat()
        payload += f":{stat.st_size}:{int(stat.st_mtime)}"
    except OSError:
        payload += ":missing"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _remote_fingerprint(target: str, store_class: str) -> str:
    return hashlib.sha256(f"{store_class}:{target}".encode("utf-8")).hexdigest()


def _hit(module: str, decision: str, identity: dict[str, Any], reason: str, safer: str) -> dict[str, Any]:
    return {
        "module": module,
        "name": module.replace("-", " ").title(),
        "category": "data-trust",
        "family": "Local Data Stores",
        "decision": decision,
        "exit_code": 2 if decision == "block" else 0,
        "output": reason,
        "metadata": {
            "reason": reason,
            "confidence": 0.96 if decision == "block" else 0.84,
            "safer_alternative": safer,
            "data_identity": identity,
        },
    }


def detect_datastore(payload: str) -> dict[str, Any] | None:
    lowered = payload.lower()
    for match in SQLITE_PATH_RE.finditer(payload):
        path = _normalize_path(match.group("path"))
        path_text = str(path).replace("\\", "/")
        if BROWSER_INDEXEDDB_RE.search(path_text) and COPY_ARCHIVE_RE.search(payload):
            return {
                "target": str(path),
                "kind": "file",
                "store_class": "browser-indexeddb",
                "fingerprint": _file_fingerprint(path, "browser-indexeddb"),
                "resolved_path": str(path.resolve(strict=False)),
            }
        if SESSION_DB_RE.search(path_text) and COPY_ARCHIVE_RE.search(payload):
            return {
                "target": str(path),
                "kind": "file",
                "store_class": "sqlite-session-db",
                "fingerprint": _file_fingerprint(path, "sqlite-session-db"),
                "resolved_path": str(path.resolve(strict=False)),
            }
        return {
            "target": str(path),
            "kind": "file",
            "store_class": "sqlite-db",
            "fingerprint": _file_fingerprint(path, "sqlite-db"),
            "resolved_path": str(path.resolve(strict=False)),
        }

    for token in _shell_split(payload):
        path = _normalize_path(token)
        path_text = str(path).replace("\\", "/")
        if BROWSER_INDEXEDDB_RE.search(path_text):
            return {
                "target": str(path),
                "kind": "file",
                "store_class": "browser-indexeddb",
                "fingerprint": _file_fingerprint(path, "browser-indexeddb"),
                "resolved_path": str(path.resolve(strict=False)),
            }
        if SESSION_DB_RE.search(path_text) and APP_CACHE_DB_RE.search(path_text):
            return {
                "target": str(path),
                "kind": "file",
                "store_class": "sqlite-session-db",
                "fingerprint": _file_fingerprint(path, "sqlite-session-db"),
                "resolved_path": str(path.resolve(strict=False)),
            }
        if VECTOR_STORE_RE.search(path_text):
            return {
                "target": str(path),
                "kind": "file",
                "store_class": "vector-store",
                "fingerprint": _file_fingerprint(path, "vector-store"),
                "resolved_path": str(path.resolve(strict=False)),
            }
        if APP_CACHE_DB_RE.search(path_text) and (BROWSER_INDEXEDDB_RE.search(path_text) or path.suffix.lower() in {".db", ".sqlite", ".sqlite3"}):
            return {
                "target": str(path),
                "kind": "file",
                "store_class": "app-cache-db",
                "fingerprint": _file_fingerprint(path, "app-cache-db"),
                "resolved_path": str(path.resolve(strict=False)),
            }

    if REDIS_LOCAL_RE.search(payload):
        return {
            "target": "redis://127.0.0.1:6379",
            "kind": "tcp",
            "store_class": "redis-local",
            "fingerprint": _remote_fingerprint("redis://127.0.0.1:6379", "redis-local"),
        }

    if POSTGRES_LOCAL_RE.search(payload):
        host = "127.0.0.1"
        host_match = re.search(r"(?i)(?:-h(?:=|\s+)?|--host(?:=|\s+))([^\s]+)", payload)
        if host_match:
            host = host_match.group(1)
        target = f"postgres://{host}:5432"
        return {
            "target": target,
            "kind": "tcp",
            "store_class": "postgres-local",
            "fingerprint": _remote_fingerprint(target, "postgres-local"),
        }

    return None


def assess_command(root: pathlib.Path, payload: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
    identity = detect_datastore(payload)
    if not identity:
        return {"identity": None, "hit": None}

    ctx = context or {}
    target = str(identity["target"])
    store_class = str(identity["store_class"])
    approval_assessment = stallion_approvals.assess_match(
        root,
        kind="data",
        target=store_class,
        value=target,
        runtime=str(ctx.get("runtime")) if ctx.get("runtime") else None,
        repo=str(root.resolve(strict=False)),
        agent_id=str(ctx.get("subagent_id") or ctx.get("agent_id")) if (ctx.get("subagent_id") or ctx.get("agent_id")) else None,
        fingerprint=str(identity["fingerprint"]),
    )
    approval = approval_assessment.get("approval")
    approval_hit = approval_assessment.get("hit")
    store = load_store(root)
    existing = store.setdefault("targets", {}).get(target)
    trust_state = "observed"
    hit = None

    if store_class == "browser-indexeddb":
        trust_state = "blocked"
        hit = _hit(
            "browser-indexeddb-export-guard",
            "block",
            identity,
            f"Blocked export of browser IndexedDB or LevelDB material from {target}.",
            "Keep browser storage exports out of the runtime, especially when they can carry authenticated local state.",
        )
    elif store_class == "sqlite-session-db":
        trust_state = "blocked"
        hit = _hit(
            "sqlite-session-export-guard",
            "block",
            identity,
            f"Blocked copy or archive of session-bearing SQLite datastore {target}.",
            "Do not export session, auth, cookie, or login databases through agent workflows.",
        )
    elif SQLITE_DUMP_RE.search(payload):
        trust_state = "blocked"
        hit = _hit(
            "sqlite-dump-guard",
            "block",
            identity,
            f"Blocked full SQLite dump from {target}.",
            "Use a narrowly reviewed query or a redacted export instead of dumping a whole local database.",
        )
    elif REDIS_EXPORT_RE.search(payload):
        trust_state = "blocked"
        hit = _hit(
            "redis-admin-export-guard",
            "block",
            identity,
            "Blocked Redis export or bulk key enumeration against a local datastore.",
            "Use a reviewed diagnostic path instead of exporting or bulk-reading Redis state from the runtime.",
        )
    elif POSTGRES_DUMP_RE.search(payload):
        trust_state = "prompted"
        hit = _hit(
            "postgres-local-dump-guard",
            "prompt",
            identity,
            f"Review required before dumping or bulk-exporting local PostgreSQL target {target}.",
            f"Run `./bin/stallion data approve {target}` only if this local database export is expected.",
        )
    elif VECTOR_STORE_RE.search(target) and COPY_ARCHIVE_RE.search(payload):
        trust_state = "prompted"
        hit = _hit(
            "vector-store-export-guard",
            "prompt",
            identity,
            f"Review required before copying or archiving local vector store {target}.",
            "Treat embeddings and vector stores like sensitive local state instead of exporting them casually.",
        )
    elif APP_CACHE_DB_RE.search(target) and COPY_ARCHIVE_RE.search(payload):
        trust_state = "prompted"
        hit = _hit(
            "app-cache-db-copy-guard",
            "prompt",
            identity,
            f"Review required before copying local application cache datastore {target}.",
            "Keep application cache and local app-state databases behind explicit review before export or duplication.",
        )
    elif SQLITE_BULK_RE.search(payload) or re.search(r"(?is)\b(?:psql|sqlite3)\b[^\n\r]{0,260}(?:select\s+\*|copy\s*\(|\.schema\b)", payload):
        trust_state = "prompted"
        hit = _hit(
            "datastore-bulk-read-guard",
            "prompt",
            identity,
            f"Review required before a broad datastore read from {target}.",
            "Reduce the query scope or explicitly approve this datastore read if you really need a broad local export.",
        )
    elif approval:
        trust_state = "approved"
    elif approval_hit:
        trust_state = "prompted"
        hit = approval_hit
    elif isinstance(existing, dict) and existing.get("trust_state") == "approved" and existing.get("fingerprint") != identity["fingerprint"]:
        trust_state = "drifted"
        hit = _hit(
            "datastore-drift-guard",
            "prompt",
            identity,
            f"Review required because local datastore target drifted for {target}.",
            f"Run `./bin/stallion data diff {target}` and re-approve only if this datastore target is still expected.",
        )
    elif re.search(r"(?i)\b(?:sqlite3|psql|redis-cli)\b", payload):
        trust_state = "prompted"
        hit = _hit(
            "datastore-admin-shell-guard",
            "prompt",
            identity,
            f"Review required before opening or driving local datastore admin surface {target}.",
            f"Run `./bin/stallion data approve {target}` only if this interactive or admin datastore access is expected.",
        )
    else:
        trust_state = "trusted"

    stored_state = trust_state
    if (
        trust_state in {"blocked", "prompted"}
        and isinstance(existing, dict)
        and existing.get("trust_state") == "approved"
        and existing.get("fingerprint") == identity["fingerprint"]
    ) or approval:
        stored_state = "approved"

    record = {
        "target": target,
        "kind": identity["kind"],
        "store_class": store_class,
        "fingerprint": identity["fingerprint"],
        "resolved_path": identity.get("resolved_path"),
        "trust_state": stored_state,
        "last_observed_state": trust_state,
        "first_seen_at": existing.get("first_seen_at") if isinstance(existing, dict) else utc_now(),
        "last_seen_at": utc_now(),
        "last_reason": hit["module"] if hit else (existing or {}).get("last_reason"),
    }
    store["targets"][target] = record
    save_store(root, store)
    return {"identity": identity, "hit": hit}


def list_targets(root: pathlib.Path) -> list[dict[str, Any]]:
    items = [dict(value) for value in load_store(root).get("targets", {}).values() if isinstance(value, dict)]
    items.sort(key=lambda item: (item.get("store_class", ""), item.get("target", "")))
    return items


def approve_target(root: pathlib.Path, selector: str) -> bool:
    store = load_store(root)
    record = store.setdefault("targets", {}).get(selector)
    if not isinstance(record, dict):
        for key, value in store.get("targets", {}).items():
            if isinstance(value, dict) and value.get("target") == selector:
                selector = key
                record = value
                break
    if not isinstance(record, dict):
        return False
    stallion_approvals.create_approval(
        root,
        kind="data",
        target=str(record.get("store_class")),
        value=str(record.get("target")),
        repo=str(root.resolve(strict=False)),
        fingerprint=str(record.get("fingerprint")),
    )
    record["trust_state"] = "approved"
    store["targets"][selector] = record
    save_store(root, store)
    return True


def forget_target(root: pathlib.Path, selector: str) -> bool:
    store = load_store(root)
    targets = store.setdefault("targets", {})
    if selector in targets:
        targets.pop(selector, None)
        save_store(root, store)
        return True
    return False


def diff_target(root: pathlib.Path, selector: str) -> dict[str, Any] | None:
    record = load_store(root).get("targets", {}).get(selector)
    if isinstance(record, dict):
        return record
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage Stallion local datastore trust")
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
        items = list_targets(root)
        if args.json:
            print(json.dumps({"targets": items}, indent=2))
        else:
            print("Local Data Stores:")
            for item in items:
                print(f"- {item.get('store_class')} [{item.get('trust_state')}] {item.get('target')}")
        return 0
    if args.command == "approve":
        if approve_target(root, args.selector):
            print(f"approved {args.selector}")
            return 0
        print(f"unknown datastore target: {args.selector}", file=os.sys.stderr)
        return 1
    if args.command == "forget":
        if forget_target(root, args.selector):
            print(f"forgot {args.selector}")
            return 0
        print(f"unknown datastore target: {args.selector}", file=os.sys.stderr)
        return 1
    if args.command == "diff":
        payload = diff_target(root, args.selector)
        if payload is None:
            print(f"unknown datastore target: {args.selector}", file=os.sys.stderr)
            return 1
        print(json.dumps(payload, indent=2))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
