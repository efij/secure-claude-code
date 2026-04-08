#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import pathlib
import time
import uuid
from datetime import datetime, timezone
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def state_dir(root: pathlib.Path) -> pathlib.Path:
    home = os.environ.get("RUNWALL_HOME") or os.environ.get("SECURE_CLAUDE_CODE_HOME")
    if home:
        return pathlib.Path(home) / "state"
    return pathlib.Path(os.path.expanduser("~")) / ".runwall" / "state"


def approvals_path(root: pathlib.Path) -> pathlib.Path:
    return state_dir(root) / "approvals.json"


def load_store(root: pathlib.Path) -> dict[str, Any]:
    path = approvals_path(root)
    if not path.exists():
        return {"version": 1, "approvals": []}
    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {"version": 1, "approvals": []}
    if not isinstance(payload, dict):
        return {"version": 1, "approvals": []}
    payload.setdefault("version", 1)
    payload.setdefault("approvals", [])
    return payload


def save_store(root: pathlib.Path, store: dict[str, Any]) -> None:
    path = approvals_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(store, indent=2, sort_keys=True) + "\n")


def prune_expired(root: pathlib.Path) -> int:
    store = load_store(root)
    now = time.time()
    approvals = []
    removed = 0
    for item in store.get("approvals", []):
        if not isinstance(item, dict):
            continue
        expires_ts = item.get("expires_ts")
        if isinstance(expires_ts, (int, float)) and expires_ts < now:
            removed += 1
            continue
        approvals.append(item)
    store["approvals"] = approvals
    if removed:
        save_store(root, store)
    return removed


def list_approvals(root: pathlib.Path) -> list[dict[str, Any]]:
    prune_expired(root)
    return [item for item in load_store(root).get("approvals", []) if isinstance(item, dict)]


def create_approval(
    root: pathlib.Path,
    *,
    kind: str,
    target: str,
    value: str,
    runtime: str | None = None,
    repo: str | None = None,
    agent_id: str | None = None,
    once: bool = False,
    ttl_hours: float | None = None,
    fingerprint: str | None = None,
) -> dict[str, Any]:
    store = load_store(root)
    approval = {
        "id": uuid.uuid4().hex,
        "kind": kind,
        "target": target,
        "value": value,
        "runtime": runtime,
        "repo": repo,
        "agent_id": agent_id,
        "once": once,
        "fingerprint": fingerprint,
        "created_at": utc_now(),
        "uses": 0,
    }
    if ttl_hours is not None:
        approval["expires_ts"] = time.time() + (float(ttl_hours) * 3600.0)
    store.setdefault("approvals", []).append(approval)
    save_store(root, store)
    return approval


def revoke_approval(root: pathlib.Path, selector: str) -> bool:
    store = load_store(root)
    kept = []
    removed = False
    for item in store.get("approvals", []):
        if not isinstance(item, dict):
            continue
        if item.get("id") == selector or item.get("value") == selector:
            removed = True
            continue
        kept.append(item)
    if removed:
        store["approvals"] = kept
        save_store(root, store)
    return removed


def _repo_for_path(path: pathlib.Path) -> str:
    try:
        return str(path.resolve(strict=False))
    except Exception:
        return str(path)


def match_approval(
    root: pathlib.Path,
    *,
    kind: str,
    target: str,
    value: str,
    runtime: str | None = None,
    repo: str | None = None,
    agent_id: str | None = None,
    fingerprint: str | None = None,
) -> dict[str, Any] | None:
    prune_expired(root)
    store = load_store(root)
    approvals = []
    matched: dict[str, Any] | None = None
    for item in store.get("approvals", []):
        if not isinstance(item, dict):
            continue
        if item.get("kind") != kind or item.get("target") != target:
            approvals.append(item)
            continue
        if item.get("value") not in {value, "*"}:
            approvals.append(item)
            continue
        if item.get("runtime") and item.get("runtime") != runtime:
            approvals.append(item)
            continue
        if item.get("repo") and item.get("repo") != repo:
            approvals.append(item)
            continue
        if item.get("agent_id") and item.get("agent_id") != agent_id:
            approvals.append(item)
            continue
        if item.get("fingerprint") and item.get("fingerprint") != fingerprint:
            approvals.append(item)
            continue
        matched = dict(item)
        item["uses"] = int(item.get("uses", 0)) + 1
        if item.get("once"):
            continue
        approvals.append(item)
    if matched:
        store["approvals"] = approvals
        save_store(root, store)
    return matched


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage Runwall scoped approvals")
    parser.add_argument("--root", required=True)
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list")
    list_parser.add_argument("--json", action="store_true")

    create_parser = subparsers.add_parser("create")
    create_parser.add_argument("--kind", required=True)
    create_parser.add_argument("--target", required=True)
    create_parser.add_argument("--value", required=True)
    create_parser.add_argument("--runtime")
    create_parser.add_argument("--repo")
    create_parser.add_argument("--agent-id")
    create_parser.add_argument("--once", action="store_true")
    create_parser.add_argument("--ttl-hours", type=float)
    create_parser.add_argument("--fingerprint")

    revoke_parser = subparsers.add_parser("revoke")
    revoke_parser.add_argument("selector")

    prune_parser = subparsers.add_parser("prune")

    args = parser.parse_args()
    root = pathlib.Path(args.root)

    if args.command == "list":
        approvals = list_approvals(root)
        if args.json:
            print(json.dumps({"approvals": approvals}, indent=2))
        else:
            print("Approvals:")
            for item in approvals:
                print(
                    f"- {item.get('id')} [{item.get('kind')}/{item.get('target')}] "
                    f"{item.get('value')} runtime={item.get('runtime') or '*'} once={bool(item.get('once'))}"
                )
        return 0
    if args.command == "create":
        approval = create_approval(
            root,
            kind=args.kind,
            target=args.target,
            value=args.value,
            runtime=args.runtime,
            repo=args.repo,
            agent_id=args.agent_id,
            once=bool(args.once),
            ttl_hours=args.ttl_hours,
            fingerprint=args.fingerprint,
        )
        print(json.dumps(approval, indent=2))
        return 0
    if args.command == "revoke":
        if revoke_approval(root, args.selector):
            print(f"revoked {args.selector}")
            return 0
        print(f"unknown approval: {args.selector}", file=os.sys.stderr)
        return 1
    if args.command == "prune":
        removed = prune_expired(root)
        print(f"pruned {removed} approvals")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
