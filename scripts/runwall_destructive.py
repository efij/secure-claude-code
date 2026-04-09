#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
from datetime import datetime, timezone
from typing import Any


MASS_DELETE_RE = re.compile(r"(?i)\brm\s+-[A-Za-z]*r[fA-Za-z]*\s+(?:/|~|\.|/\w|\.git|dist|build|release|releases)|\bgit\s+rm\s+-r\b|\bfind\b[^\n\r]{0,120}-delete\b")
ENV_DESTROY_RE = re.compile(r"(?i)(?:vercel\s+env\s+rm\b|kubectl\s+delete\s+configmap\b|kubectl\s+delete\s+secret\b|supabase\s+secrets?\s+unset\b|terraform\s+workspace\s+delete\b[^\n\r]{0,80}\bprod(?:uction)?\b)")
SECRET_REVOKE_RE = re.compile(r"(?i)(?:delete-access-key|revoke-token|tokens?\s+delete\b[^\n\r]{0,120}\ball\b|secret(?:s)?\s+(?:delete|rm)\b[^\n\r]{0,120}\ball\b|aws\s+iam\s+delete-access-key\b)")
ROLE_REMOVE_RE = re.compile(r"(?i)(?:remove-admin|remove owner|revoke admin|detach-user-policy|remove-iam-policy-binding|gh\s+api\b[^\n\r]{0,160}(?:collaborators|teams).*(?:DELETE|--method\s+DELETE))")
INFRA_TEARDOWN_RE = re.compile(r"(?i)\b(?:terraform|tofu|terragrunt)\s+destroy\b|\bpulumi\s+destroy\b|\bkubectl\s+delete\s+namespace\b[^\n\r]{0,80}\b(prod|production)\b|\bhelm\s+uninstall\b[^\n\r]{0,80}\b(prod|production)\b")
REPO_WIPE_RE = re.compile(r"(?i)(?:git\s+push\b[^\n\r]{0,120}--mirror\b[^\n\r]{0,80}--force|git\s+filter-repo\b|gh\s+repo\s+delete\b|git\s+push\b[^\n\r]{0,160}:refs/heads/)")
ARTIFACT_WIPE_RE = re.compile(r"(?i)(?:rm\s+-[A-Za-z]*r[fA-Za-z]*\s+[^\n\r]*(?:dist|build|release|releases|artifacts?|sbom|provenance|bundle)|aws\s+s3\s+rm\b[^\n\r]{0,160}(?:release|artifact)s?\b[^\n\r]{0,80}--recursive\b)")
STATE_DESTROY_RE = re.compile(r"(?i)(?:rm\s+-[A-Za-z]*f\b[^\n\r]*(?:terraform\.tfstate|Pulumi\.[^.]+\.yaml|\.pulumi|state\.json)|terraform\s+state\s+rm\b|\bpulumi\s+state\s+delete\b)")
BULK_DISABLE_RE = re.compile(r"(?i)(?:for\s+\w+\s+in\b[^\n\r]{0,160}(?:delete|disable|rm|revoke)|xargs\b[^\n\r]{0,160}(?:delete|disable|rm|revoke)|parallel\b[^\n\r]{0,160}(?:delete|disable|rm|revoke))")
BLAST_RADIUS_RE = re.compile(r"(?i)(?:--all\b|--all-namespaces\b|--prune\b|--recursive\b|delete all\b|remove all\b|revoke all\b|drop database\b)")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def state_dir(root: pathlib.Path) -> pathlib.Path:
    home = os.environ.get("RUNWALL_HOME") or os.environ.get("SECURE_CLAUDE_CODE_HOME")
    if home:
        return pathlib.Path(home) / "state"
    return pathlib.Path(os.path.expanduser("~")) / ".runwall" / "state"


def destructive_store_path(root: pathlib.Path) -> pathlib.Path:
    return state_dir(root) / "destructive.json"


def load_store(root: pathlib.Path) -> dict[str, Any]:
    path = destructive_store_path(root)
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
    path = destructive_store_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(store, indent=2, sort_keys=True) + "\n")


def _identity(module: str, payload: str, target: str) -> dict[str, Any]:
    return {"module": module, "target": target, "preview": payload[:220]}


def _hit(module: str, decision: str, identity: dict[str, Any], reason: str, safer: str) -> dict[str, Any]:
    return {
        "module": module,
        "name": module.replace("-", " ").title(),
        "category": "destructive-intent",
        "family": "Destructive Actions & Blast Radius",
        "decision": decision,
        "exit_code": 2 if decision == "block" else 0,
        "output": reason,
        "metadata": {
            "reason": reason,
            "confidence": 0.95 if decision == "block" else 0.84,
            "safer_alternative": safer,
            "destructive_identity": identity,
        },
    }


def _extract_target(payload: str) -> str:
    match = re.search(r"(?i)(?:\s|^)(/[^\s]+|~[^\s]+|[A-Za-z0-9._/-]+(?::[A-Za-z0-9._/-]+)?)", payload)
    if match:
        return match.group(1)
    return "runtime"


def assess_action(root: pathlib.Path, event: str, matcher: str, payload: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = (root, context)
    if event != "PreToolUse" or matcher != "Bash":
        return {"identity": None, "hit": None}

    checks: list[tuple[str, str, re.Pattern[str], str, str]] = [
        ("infra-teardown-guard", "block", INFRA_TEARDOWN_RE, "Blocked destructive infrastructure teardown path.", "Keep infra teardown behind a reviewed manual workflow."),
        ("bulk-disable-guard", "prompt", BULK_DISABLE_RE, "Review required before looped or bulk destructive disable/delete actions.", "Avoid fan-out destructive automation unless it has been separately reviewed."),
        ("repo-wipe-guard", "block", REPO_WIPE_RE, "Blocked repository wipe or history-destruction path.", "Use reviewed repository recovery workflows instead of destructive rewrite or delete operations."),
        ("state-destroy-guard", "block", STATE_DESTROY_RE, "Blocked destructive infrastructure or state wipe path.", "Do not delete or mutate infrastructure state directly from the runtime."),
        ("mass-delete-intent-guard", "block", MASS_DELETE_RE, "Blocked high-blast-radius delete path.", "Reduce scope and review destructive deletes before running them."),
        ("artifact-wipe-guard", "block", ARTIFACT_WIPE_RE, "Blocked destructive wipe of release or build artifacts.", "Keep release artifacts and evidence bundles intact or delete them manually after review."),
        ("env-destroy-guard", "prompt", ENV_DESTROY_RE, "Review required before destroying or removing environment-bound controls.", "Use a reviewed environment teardown path instead of ad hoc runtime deletion."),
        ("secret-revoke-all-guard", "prompt", SECRET_REVOKE_RE, "Review required before revoking or deleting broad secret or token access.", "Use a narrow secret rotation or revocation path instead of bulk destructive token changes."),
        ("role-remove-admin-guard", "prompt", ROLE_REMOVE_RE, "Review required before destructive role or admin removal.", "Keep role removal and admin teardown behind explicit human review."),
        ("blast-radius-delete-guard", "prompt", BLAST_RADIUS_RE, "Review required before a broad delete or revoke scope.", "Reduce target scope before destructive operations that act on everything or recurse broadly."),
    ]

    for module, decision, regex, reason, safer in checks:
        if regex.search(payload):
            target = _extract_target(payload)
            return {
                "identity": _identity(module, payload, target),
                "hit": _hit(module, decision, _identity(module, payload, target), f"{reason} Target={target}.", safer),
            }
    return {"identity": None, "hit": None}


def record_action(root: pathlib.Path, result: dict[str, Any], payload: str) -> None:
    identity = result.get("destructive_identity")
    if not isinstance(identity, dict) or not identity.get("module"):
        return
    store = load_store(root)
    store.setdefault("events", []).append(
        {
            "event_id": result.get("event_id"),
            "module": identity.get("module"),
            "target": identity.get("target"),
            "preview": payload[:180],
            "decision": result.get("action"),
            "ts": utc_now(),
        }
    )
    store["events"] = store["events"][-200:]
    save_store(root, store)


def list_events(root: pathlib.Path) -> list[dict[str, Any]]:
    items = [item for item in load_store(root).get("events", []) if isinstance(item, dict)]
    items.sort(key=lambda item: item.get("ts", ""), reverse=True)
    return items


def explain_event(root: pathlib.Path, selector: str) -> dict[str, Any] | None:
    for item in list_events(root):
        if item.get("event_id") == selector:
            return item
    return None


def policy_payload() -> dict[str, Any]:
    return {
        "guards": [
            "mass-delete-intent-guard",
            "env-destroy-guard",
            "secret-revoke-all-guard",
            "role-remove-admin-guard",
            "infra-teardown-guard",
            "repo-wipe-guard",
            "artifact-wipe-guard",
            "state-destroy-guard",
            "bulk-disable-guard",
            "blast-radius-delete-guard",
        ]
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect Runwall destructive-intent events")
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
            print("Destructive Actions:")
            for item in items:
                print(f"- {item.get('decision')} {item.get('module')} {item.get('target')} {item.get('event_id')}")
        return 0
    if args.command == "explain":
        payload = explain_event(root, args.selector)
        if payload is None:
            print(f"unknown destructive event: {args.selector}", file=os.sys.stderr)
            return 1
        print(json.dumps(payload, indent=2))
        return 0
    if args.command == "policy":
        payload = policy_payload()
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print("Guards:")
            for item in payload["guards"]:
                print(f"- {item}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
