#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import time
import uuid
from datetime import datetime, timezone
from typing import Any


RISKY_KINDS = {"app", "auth", "browser", "service", "tool", "hook", "data", "ipc", "exposure"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def state_dir(root: pathlib.Path) -> pathlib.Path:
    home = os.environ.get("STALLION_HOME") or os.environ.get("STALLION_HOME")
    if home:
        return pathlib.Path(home) / "state"
    return pathlib.Path(os.path.expanduser("~")) / ".stallion" / "state"


def approvals_path(root: pathlib.Path) -> pathlib.Path:
    return state_dir(root) / "approvals.json"


def _repo_scope(root: pathlib.Path) -> str:
    try:
        return str(root.resolve(strict=False))
    except Exception:
        return str(root)


def _request_key(
    *,
    kind: str,
    target: str,
    value: str,
    runtime: str | None = None,
    repo: str | None = None,
    agent_id: str | None = None,
    fingerprint: str | None = None,
) -> str:
    payload = {
        "kind": kind,
        "target": target,
        "value": value,
        "runtime": runtime,
        "repo": repo,
        "agent_id": agent_id,
        "fingerprint": fingerprint,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def _approval_scope_summary(item: dict[str, Any]) -> str:
    return (
        f"value={item.get('value')} runtime={item.get('runtime') or '*'} "
        f"repo={item.get('repo') or '*'} agent={item.get('agent_id') or '*'} "
        f"fingerprint={'yes' if item.get('fingerprint') else 'no'} once={bool(item.get('once'))}"
    )


def _approval_hit(
    module: str,
    reason: str,
    safer: str,
    *,
    approval: dict[str, Any] | None = None,
    decision: str = "prompt",
    kind: str | None = None,
    target: str | None = None,
    value: str | None = None,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "reason": reason,
        "confidence": 0.95 if decision == "block" else 0.84,
        "safer_alternative": safer,
    }
    if approval:
        metadata["approval"] = {
            "id": approval.get("id"),
            "kind": approval.get("kind"),
            "target": approval.get("target"),
            "value": approval.get("value"),
            "runtime": approval.get("runtime"),
            "repo": approval.get("repo"),
            "agent_id": approval.get("agent_id"),
            "once": approval.get("once"),
            "fingerprint": approval.get("fingerprint"),
            "created_at": approval.get("created_at"),
        }
    if kind or target or value:
        metadata["requested_scope"] = {
            "kind": kind,
            "target": target,
            "value": value,
        }
    return {
        "module": module,
        "name": module.replace("-", " ").title(),
        "category": "approval-integrity",
        "family": "Approvals & Review Boundaries",
        "decision": decision,
        "exit_code": 2 if decision == "block" else 0,
        "output": reason,
        "metadata": metadata,
    }


def _is_expired(item: dict[str, Any], now: float | None = None) -> bool:
    expires_ts = item.get("expires_ts")
    if not isinstance(expires_ts, (int, float)):
        return False
    return float(expires_ts) < (now if now is not None else time.time())


def _match_scope(
    item: dict[str, Any],
    *,
    kind: str,
    target: str,
    value: str,
) -> tuple[bool, bool]:
    if item.get("kind") != kind or item.get("target") != target:
        return False, False
    approval_value = str(item.get("value", ""))
    value_match = approval_value in {value, "*"}
    return True, value_match


def _is_broad_scope(item: dict[str, Any]) -> bool:
    if str(item.get("value", "")) == "*":
        return True
    return (
        not bool(item.get("once"))
        and not any(
            item.get(field)
            for field in ("runtime", "repo", "agent_id", "fingerprint")
        )
    )


def load_store(root: pathlib.Path) -> dict[str, Any]:
    path = approvals_path(root)
    if not path.exists():
        return {"version": 2, "approvals": [], "consumed": []}
    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {"version": 2, "approvals": [], "consumed": []}
    if not isinstance(payload, dict):
        return {"version": 2, "approvals": [], "consumed": []}
    payload.setdefault("version", 2)
    payload.setdefault("approvals", [])
    payload.setdefault("consumed", [])
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
        if _is_expired(item, now):
            removed += 1
            continue
        approvals.append(item)
    store["approvals"] = approvals
    if removed:
        save_store(root, store)
    return removed


def _health_modules(item: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    if _is_expired(item):
        issues.append("approval-expiry-guard")
    if _is_broad_scope(item):
        issues.append("approval-broad-scope-guard")
    if (
        item.get("kind") in RISKY_KINDS
        and not item.get("once")
        and not item.get("expires_ts")
    ):
        issues.append("approval-unbounded-lifetime-guard")
    if item.get("kind") in {"service", "tool"} and not item.get("fingerprint"):
        issues.append("approval-drift-invalidation-guard")
    return issues


def list_approvals(root: pathlib.Path) -> list[dict[str, Any]]:
    prune_expired(root)
    items: list[dict[str, Any]] = []
    for item in load_store(root).get("approvals", []):
        if not isinstance(item, dict):
            continue
        enriched = dict(item)
        enriched["health"] = _health_modules(item)
        items.append(enriched)
    return items


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


def _record_consumed(
    store: dict[str, Any],
    approval: dict[str, Any],
    *,
    request_key: str,
) -> None:
    consumed = store.setdefault("consumed", [])
    consumed.append(
        {
            "request_key": request_key,
            "approval_id": approval.get("id"),
            "kind": approval.get("kind"),
            "target": approval.get("target"),
            "value": approval.get("value"),
            "runtime": approval.get("runtime"),
            "repo": approval.get("repo"),
            "agent_id": approval.get("agent_id"),
            "fingerprint": approval.get("fingerprint"),
            "consumed_at": utc_now(),
        }
    )
    store["consumed"] = consumed[-200:]


def _replay_hit(
    kind: str,
    target: str,
    value: str,
    replay: dict[str, Any],
) -> dict[str, Any]:
    return _approval_hit(
        "approval-replay-guard",
        f"Blocked replay of previously consumed one-shot approval for {kind}/{target} value={value}.",
        "Create a new one-shot approval for the current action instead of reusing an already consumed approval.",
        approval=replay,
        decision="block",
        kind=kind,
        target=target,
        value=value,
    )


def assess_match(
    root: pathlib.Path,
    *,
    kind: str,
    target: str,
    value: str,
    runtime: str | None = None,
    repo: str | None = None,
    agent_id: str | None = None,
    fingerprint: str | None = None,
    consume: bool = True,
) -> dict[str, Any]:
    store = load_store(root)
    now = time.time()
    repo_scope = repo or _repo_scope(root)
    request_key = _request_key(
        kind=kind,
        target=target,
        value=value,
        runtime=runtime,
        repo=repo_scope,
        agent_id=agent_id,
        fingerprint=fingerprint,
    )

    mismatch_hit: dict[str, Any] | None = None
    value_mismatch_candidate: dict[str, Any] | None = None
    expired_candidate: dict[str, Any] | None = None

    approvals: list[dict[str, Any]] = []
    matched_approval: dict[str, Any] | None = None

    for raw in store.get("approvals", []):
        if not isinstance(raw, dict):
            continue
        item = dict(raw)
        same_scope, value_match = _match_scope(item, kind=kind, target=target, value=value)
        if not same_scope:
            approvals.append(item)
            continue
        if _is_expired(item, now):
            expired_candidate = item
            continue
        if not value_match:
            if value_mismatch_candidate is None:
                value_mismatch_candidate = item
            approvals.append(item)
            continue
        if item.get("runtime") and item.get("runtime") != runtime:
            mismatch_hit = _approval_hit(
                "approval-runtime-mismatch-guard",
                f"Review required because an approval exists for {kind}/{target} but only for runtime {item.get('runtime')}, not {runtime or 'unknown'}.",
                "Create a runtime-specific approval for the current runtime instead of reusing one from another adapter.",
                approval=item,
                kind=kind,
                target=target,
                value=value,
            )
            approvals.append(item)
            continue
        if item.get("repo") and item.get("repo") != repo_scope:
            mismatch_hit = _approval_hit(
                "approval-repo-mismatch-guard",
                f"Review required because an approval exists for {kind}/{target} but only for repo {item.get('repo')}, not this workspace.",
                "Create a repo-scoped approval for the current repository instead of carrying an approval across workspaces.",
                approval=item,
                kind=kind,
                target=target,
                value=value,
            )
            approvals.append(item)
            continue
        if item.get("agent_id") and item.get("agent_id") != agent_id:
            mismatch_hit = _approval_hit(
                "approval-parent-child-mismatch-guard",
                f"Review required because an approval exists for {kind}/{target} but only for agent {item.get('agent_id')}, not {agent_id or 'unknown'}.",
                "Create a fresh approval for the current agent or subagent instead of reusing another actor's review boundary.",
                approval=item,
                kind=kind,
                target=target,
                value=value,
            )
            approvals.append(item)
            continue
        if item.get("fingerprint") and item.get("fingerprint") != fingerprint:
            if kind in {"service", "browser"}:
                module = "approval-destination-drift-guard"
                reason = (
                    f"Review required because the approved {kind} destination drifted for {value}."
                )
                safer = "Re-approve the exact current destination after confirming the endpoint or session target is still expected."
            elif kind == "tool":
                module = "approval-tool-identity-drift-guard"
                reason = (
                    f"Review required because the approved tool identity drifted for {value}."
                )
                safer = "Re-approve the tool only after confirming its path, hash, or wrapper chain is still the reviewed one."
            else:
                module = "approval-drift-invalidation-guard"
                reason = (
                    f"Review required because the reviewed approval fingerprint no longer matches the current {kind} request."
                )
                safer = "Create a new approval for the exact current request instead of reusing a stale approval."
            mismatch_hit = _approval_hit(
                module,
                reason,
                safer,
                approval=item,
                kind=kind,
                target=target,
                value=value,
            )
            approvals.append(item)
            continue
        if _is_broad_scope(item) and kind in RISKY_KINDS:
            mismatch_hit = _approval_hit(
                "approval-broad-scope-guard",
                f"Review required because the matching approval for {kind}/{target} is broader than the current risk warrants ({_approval_scope_summary(item)}).",
                "Replace the broad approval with a narrower one-shot or fingerprint-bound approval for the exact action.",
                approval=item,
                kind=kind,
                target=target,
                value=value,
            )
            approvals.append(item)
            continue

        matched_approval = item
        if not consume:
            break
        item["uses"] = int(item.get("uses", 0)) + 1
        item["last_used_at"] = utc_now()
        if item.get("once"):
            _record_consumed(store, item, request_key=request_key)
            continue
        approvals.append(item)
        break

    if matched_approval:
        if not consume:
            return {"approval": matched_approval, "hit": None}
        store["approvals"] = approvals + [
            item
            for item in store.get("approvals", [])
            if not isinstance(item, dict) or item.get("id") == matched_approval.get("id") and not matched_approval.get("once")
        ]
        # Remove duplicates and keep updated objects.
        deduped: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in approvals:
            item_id = str(item.get("id"))
            if item_id in seen:
                continue
            seen.add(item_id)
            deduped.append(item)
        if not matched_approval.get("once"):
            updated = dict(matched_approval)
            if str(updated.get("id")) not in seen:
                deduped.append(updated)
        store["approvals"] = deduped
        save_store(root, store)
        return {"approval": matched_approval, "hit": None}

    if consume:
        for replay in reversed(store.get("consumed", [])):
            if not isinstance(replay, dict):
                continue
            if replay.get("request_key") == request_key:
                return {"approval": None, "hit": _replay_hit(kind, target, value, replay)}

    if expired_candidate is not None:
        return {
            "approval": None,
            "hit": _approval_hit(
                "approval-expiry-guard",
                f"Review required because the prior approval for {kind}/{target} expired.",
                "Create a fresh short-lived approval for the exact current action instead of relying on an expired one.",
                approval=expired_candidate,
                kind=kind,
                target=target,
                value=value,
            ),
        }
    if mismatch_hit is not None:
        return {"approval": None, "hit": mismatch_hit}
    if value_mismatch_candidate is not None:
        return {
            "approval": None,
            "hit": _approval_hit(
                "approval-scope-mismatch-guard",
                f"Review required because an approval exists for {kind}/{target}, but for value {value_mismatch_candidate.get('value')} instead of {value}.",
                "Create a narrow approval for the exact current value instead of reusing a similar approval from another target or destination.",
                approval=value_mismatch_candidate,
                kind=kind,
                target=target,
                value=value,
            ),
        }
    return {"approval": None, "hit": None}


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
    return assess_match(
        root,
        kind=kind,
        target=target,
        value=value,
        runtime=runtime,
        repo=repo,
        agent_id=agent_id,
        fingerprint=fingerprint,
    ).get("approval")


def explain_approval(root: pathlib.Path, selector: str) -> dict[str, Any] | None:
    store = load_store(root)
    for item in store.get("approvals", []):
        if not isinstance(item, dict):
            continue
        if item.get("id") == selector or item.get("value") == selector:
            enriched = dict(item)
            enriched["health"] = _health_modules(item)
            return enriched
    for item in store.get("consumed", []):
        if not isinstance(item, dict):
            continue
        if item.get("approval_id") == selector or item.get("value") == selector:
            enriched = dict(item)
            enriched["consumed"] = True
            return enriched
    return None


def diff_approval(root: pathlib.Path, selector: str) -> dict[str, Any] | None:
    payload = explain_approval(root, selector)
    if payload is None:
        return None
    payload = dict(payload)
    payload["scope_summary"] = _approval_scope_summary(payload)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage Stallion scoped approvals")
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

    diff_parser = subparsers.add_parser("diff")
    diff_parser.add_argument("selector")

    explain_parser = subparsers.add_parser("explain")
    explain_parser.add_argument("selector")

    args = parser.parse_args()
    root = pathlib.Path(args.root)

    if args.command == "list":
        approvals = list_approvals(root)
        if args.json:
            print(json.dumps({"approvals": approvals}, indent=2))
        else:
            print("Approvals:")
            for item in approvals:
                health = ",".join(item.get("health", [])) or "ok"
                print(f"- {item.get('id')} [{item.get('kind')}/{item.get('target')}] {item.get('value')} {health}")
                print(f"  {_approval_scope_summary(item)}")
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
    if args.command == "diff":
        payload = diff_approval(root, args.selector)
        if payload is None:
            print(f"unknown approval: {args.selector}", file=os.sys.stderr)
            return 1
        print(json.dumps(payload, indent=2))
        return 0
    if args.command == "explain":
        payload = explain_approval(root, args.selector)
        if payload is None:
            print(f"unknown approval: {args.selector}", file=os.sys.stderr)
            return 1
        print(json.dumps(payload, indent=2))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
