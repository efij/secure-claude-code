#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
from datetime import datetime, timezone
from typing import Any


UPLOAD_RE = re.compile(r"(?i)\b(curl|wget|scp|rsync|rclone|aws\s+s3\s+cp|gsutil\s+cp|az\s+storage\s+blob\s+upload|gh\s+release\s+upload|npm\s+publish|twine\s+upload)\b|https?://")
AUTH_RE = re.compile(r"(?i)(auth\b|token\b|login\b|assume-role|impersonate|access-token|device[- ]?code|refresh[_-]?token|sso\b)")
RISKY_MUTATION_RE = re.compile(r"(?i)(deploy\b|publish\b|delete\b|destroy\b|invite\b|grant\b|env add\b|secret (set|create)|webhook\b|role\b|--prod\b)")
CREDENTIAL_MATERIAL_RE = re.compile(r"(?i)(\.env(?:\.[A-Za-z0-9._-]+)?|\.aws/(credentials|config)|\.npmrc|\.pypirc|\.docker/config\.json|\.kube/config|kubeconfig|authorized_keys|Cookies|Login Data|session|token|auth)")
ARTIFACT_RE = re.compile(r"(?i)(dist/|build/|release/|artifacts?/|\.zip\b|\.tar(?:\.gz)?\b|\.tgz\b|\.whl\b)")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def state_dir(root: pathlib.Path) -> pathlib.Path:
    home = os.environ.get("RUNWALL_HOME") or os.environ.get("SECURE_CLAUDE_CODE_HOME")
    if home:
        return pathlib.Path(home) / "state"
    return pathlib.Path(os.path.expanduser("~")) / ".runwall" / "state"


def handoff_store_path(root: pathlib.Path) -> pathlib.Path:
    return state_dir(root) / "handoff.json"


def load_store(root: pathlib.Path) -> dict[str, Any]:
    path = handoff_store_path(root)
    if not path.exists():
        return {"version": 1, "sessions": {}}
    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {"version": 1, "sessions": {}}
    if not isinstance(payload, dict):
        return {"version": 1, "sessions": {}}
    payload.setdefault("version", 1)
    payload.setdefault("sessions", {})
    return payload


def save_store(root: pathlib.Path, store: dict[str, Any]) -> None:
    path = handoff_store_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(store, indent=2, sort_keys=True) + "\n")


def _identity(session_id: str, actor: str, runtime: str, labels: list[str]) -> dict[str, Any]:
    return {
        "session_id": session_id,
        "actor": actor,
        "runtime": runtime,
        "labels": labels,
    }


def _hit(module: str, decision: str, identity: dict[str, Any], reason: str, safer: str) -> dict[str, Any]:
    return {
        "module": module,
        "name": module.replace("-", " ").title(),
        "category": "handoff-trust",
        "family": "Agent Graph & Delegation",
        "decision": decision,
        "exit_code": 2 if decision == "block" else 0,
        "output": reason,
        "metadata": {
            "reason": reason,
            "confidence": 0.95 if decision == "block" else 0.84,
            "safer_alternative": safer,
            "handoff_identity": identity,
        },
    }


def _labels_from_result(result: dict[str, Any], payload: str) -> list[str]:
    labels: set[str] = set()
    hits_blob = json.dumps(result.get("hits", []))
    if result.get("auth_identity") or any(
        guard in hits_blob
        for guard in (
            "sts-mint-guard",
            "device-flow-broker-guard",
            "sso-helper-mint-guard",
            "credential-helper-mint-guard",
            "cloud-impersonation-broker-guard",
        )
    ):
        labels.add("delegated_auth")
    if result.get("browser_identity") or any(
        guard in hits_blob
        for guard in (
            "browser-sensitive-domain-guard",
            "browser-sensitive-export-guard",
            "browser-session-cookie-guard",
            "browser-bulk-capture-guard",
        )
    ):
        labels.add("browser_session")
    if CREDENTIAL_MATERIAL_RE.search(payload):
        labels.add("credential_material")
        labels.add("secret_material")
    if ARTIFACT_RE.search(payload) or result.get("release_identity"):
        labels.add("artifact_material")
    if result.get("release_identity") or RISKY_MUTATION_RE.search(payload):
        labels.add("control_plane_mutation")
    if UPLOAD_RE.search(payload):
        labels.add("outbound_action")
    return sorted(labels)


def observe_result(root: pathlib.Path, result: dict[str, Any], payload: str) -> None:
    session_id = str(result.get("session_id") or "")
    if not session_id:
        return
    actor = str(result.get("subagent_id") or result.get("agent_id") or "")
    runtime = str(result.get("runtime") or "")
    labels = _labels_from_result(result, payload)
    store = load_store(root)
    session = store.setdefault("sessions", {}).setdefault(
        session_id,
        {"events": [], "actors": [], "runtimes": [], "updated_at": utc_now()},
    )
    if actor and actor not in session.setdefault("actors", []):
        session["actors"].append(actor)
    if runtime and runtime not in session.setdefault("runtimes", []):
        session["runtimes"].append(runtime)
    session.setdefault("events", []).append(
        {
            "event_id": result.get("event_id"),
            "actor": actor,
            "runtime": runtime,
            "labels": labels,
            "action": result.get("action"),
            "matcher": result.get("matcher"),
            "preview": payload[:180],
            "ts": utc_now(),
        }
    )
    session["events"] = session["events"][-40:]
    session["updated_at"] = utc_now()
    save_store(root, store)


def assess_action(root: pathlib.Path, payload: str, context: dict[str, Any] | None = None) -> dict[str, Any] | None:
    ctx = context or {}
    session_id = str(ctx.get("session_id") or "")
    if not session_id:
        return None
    store = load_store(root)
    session = store.get("sessions", {}).get(session_id)
    if not isinstance(session, dict):
        return None

    actor = str(ctx.get("subagent_id") or ctx.get("agent_id") or "")
    runtime = str(ctx.get("runtime") or "")
    is_subagent = bool(ctx.get("subagent_id"))
    events = [item for item in session.get("events", []) if isinstance(item, dict)]
    other_events = [item for item in events if actor and item.get("actor") and item.get("actor") != actor]
    other_labels = {label for item in other_events for label in item.get("labels", []) if isinstance(label, str)}
    session_runtimes = {str(item) for item in session.get("runtimes", []) if item}
    risky_current = bool(UPLOAD_RE.search(payload) or AUTH_RE.search(payload) or RISKY_MUTATION_RE.search(payload))
    identity = _identity(session_id, actor, runtime, sorted(other_labels))

    if actor and "delegated_auth" in other_labels and AUTH_RE.search(payload):
        return _hit(
            "token-handoff-guard",
            "block",
            identity,
            f"Blocked delegated-auth reuse because another actor in session {session_id} already minted or handled delegated auth state.",
            "Keep delegated auth minting and follow-on auth use inside the same reviewed actor context.",
        )
    if actor and "browser_session" in other_labels and (UPLOAD_RE.search(payload) or RISKY_MUTATION_RE.search(payload)):
        return _hit(
            "browser-session-handoff-guard",
            "block",
            identity,
            f"Blocked browser-session handoff because another actor in session {session_id} already touched a sensitive authenticated browser surface.",
            "Keep sensitive browser-session work and any follow-on export or mutation inside one reviewed actor context.",
        )
    if actor and "credential_material" in other_labels and (UPLOAD_RE.search(payload) or AUTH_RE.search(payload)):
        return _hit(
            "credential-file-handoff-guard",
            "block",
            identity,
            f"Blocked credential-file handoff because another actor in session {session_id} already handled auth-bearing local files.",
            "Keep credential-bearing files local to one reviewed actor instead of handing them off to a second actor or broker flow.",
        )
    if actor and "secret_material" in other_labels and UPLOAD_RE.search(payload):
        return _hit(
            "child-agent-secret-bridge-guard",
            "block",
            identity,
            f"Blocked cross-actor export because another actor in session {session_id} already touched secret-bearing material.",
            "Do not split sensitive reads and outbound transfer across actors without a narrow explicit review step.",
        )
    if actor and "artifact_material" in other_labels and UPLOAD_RE.search(payload):
        return _hit(
            "artifact-to-subagent-guard",
            "prompt",
            identity,
            f"Review required because another actor in session {session_id} prepared artifact material before this actor tried to export it.",
            "Review artifact lineage first, then approve the exact export if it is expected.",
        )
    if actor and "delegated_auth" in other_labels and UPLOAD_RE.search(payload):
        return _hit(
            "broker-to-export-bridge-guard",
            "block",
            identity,
            f"Blocked export because delegated-auth material in session {session_id} would have been bridged into an outbound channel by another actor.",
            "Keep delegated-auth outputs inside the reviewed local runtime instead of bridging them into upload or publish paths.",
        )
    if runtime and session_runtimes and runtime not in session_runtimes and risky_current:
        return _hit(
            "cross-runtime-session-bridge-guard",
            "prompt",
            identity,
            f"Review required because session {session_id} is crossing runtimes from {sorted(session_runtimes)} to {runtime} before a risky action.",
            "Keep risky actions inside one reviewed runtime boundary or require a narrow fresh approval after the runtime switch.",
        )
    if is_subagent and other_events and (RISKY_MUTATION_RE.search(payload) or AUTH_RE.search(payload)):
        return _hit(
            "delegation-overreach-guard",
            "prompt",
            identity,
            f"Review required because delegated actor {actor} is attempting a high-risk mutation in session {session_id}.",
            "Keep destructive, release, and delegated-auth actions with the reviewed parent actor unless the child actor was explicitly approved for them.",
        )
    if len(set(session.get("actors", [])) | ({actor} if actor else set())) >= 3 and len(session_runtimes | ({runtime} if runtime else set())) >= 2 and risky_current:
        return _hit(
            "session-reuse-drift-guard",
            "prompt",
            identity,
            f"Review required because session {session_id} already spans multiple actors and runtimes before this risky action.",
            "Reset the session boundary or keep high-risk work in a smaller reviewed actor/runtime set.",
        )
    if actor and other_labels and UPLOAD_RE.search(payload) and {"delegated_auth", "browser_session", "secret_material", "credential_material"}.intersection(other_labels):
        return _hit(
            "handoff-exfil-chain-guard",
            "block",
            identity,
            f"Blocked outbound handoff because session {session_id} already accumulated sensitive power in another actor context.",
            "Do not bridge sensitive session state across actors and then export it; keep the chain local or review it explicitly.",
        )
    return None


def graph_sessions(root: pathlib.Path) -> list[dict[str, Any]]:
    items = []
    for session_id, data in load_store(root).get("sessions", {}).items():
        if not isinstance(data, dict):
            continue
        labels = sorted({label for event in data.get("events", []) if isinstance(event, dict) for label in event.get("labels", []) if isinstance(label, str)})
        items.append(
            {
                "session_id": session_id,
                "actors": sorted({str(item) for item in data.get("actors", []) if item}),
                "runtimes": sorted({str(item) for item in data.get("runtimes", []) if item}),
                "labels": labels,
                "events": data.get("events", []),
                "updated_at": data.get("updated_at"),
            }
        )
    items.sort(key=lambda item: item.get("updated_at", ""), reverse=True)
    return items


def explain_session(root: pathlib.Path, session_id: str) -> dict[str, Any] | None:
    for item in graph_sessions(root):
        if item.get("session_id") == session_id:
            return item
    return None


def policy_payload() -> dict[str, Any]:
    return {
        "guards": [
            "token-handoff-guard",
            "browser-session-handoff-guard",
            "child-agent-secret-bridge-guard",
            "cross-runtime-session-bridge-guard",
            "artifact-to-subagent-guard",
            "credential-file-handoff-guard",
            "session-reuse-drift-guard",
            "delegation-overreach-guard",
            "handoff-exfil-chain-guard",
            "broker-to-export-bridge-guard",
        ]
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect Runwall session handoff trust state")
    parser.add_argument("--root", required=True)
    subparsers = parser.add_subparsers(dest="command", required=True)

    graph_parser = subparsers.add_parser("graph")
    graph_parser.add_argument("--json", action="store_true")

    explain_parser = subparsers.add_parser("explain")
    explain_parser.add_argument("session_id")

    policy_parser = subparsers.add_parser("policy")
    policy_parser.add_argument("--json", action="store_true")

    args = parser.parse_args()
    root = pathlib.Path(args.root)

    if args.command == "graph":
        items = graph_sessions(root)
        if args.json:
            print(json.dumps({"sessions": items}, indent=2))
        else:
            print("Session Handoffs:")
            for item in items:
                print(f"- {item.get('session_id')} actors={','.join(item.get('actors', []))} runtimes={','.join(item.get('runtimes', []))}")
        return 0
    if args.command == "explain":
        payload = explain_session(root, args.session_id)
        if payload is None:
            print(f"unknown handoff session: {args.session_id}", file=os.sys.stderr)
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
