#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
from datetime import datetime, timezone
from typing import Any


SECRET_SOURCE_RE = re.compile(r"(?i)(\.env|\.aws/credentials|id_(rsa|ed25519)|authorized_keys|session|token|secret|password|kubeconfig|\.kube/config)")
UPLOAD_RE = re.compile(r"(?i)\b(curl|wget|scp|rsync|rclone|aws\s+s3\s+cp|gsutil\s+cp|az\s+storage\s+blob\s+upload|npm\s+publish|twine\s+upload|gh\s+release\s+upload)\b|https?://|hooks\.slack\.com|pastebin\.com")
ARCHIVE_RE = re.compile(r"(?i)\b(tar|zip|7z|rar|gzip)\b|\.zip\b|\.tar(?:\.gz)?\b|\.7z\b")
ENCODE_RE = re.compile(r"(?i)\b(base64|openssl\s+enc|gpg\s+-c|age\s+-e|python\s+-c|node\s+-e)\b")
CLIPBOARD_RE = re.compile(r"(?i)\b(pbcopy|xclip|xsel|wl-copy|clip(?:\.exe)?)\b")
PUBLIC_ARTIFACT_RE = re.compile(r"(?i)(^|[\\s'\"=])(dist/|build/|public/|artifacts?/|release/|upload-artifact|pages deploy)")
PROD_RE = re.compile(r"(?i)\b(prod|production|billing|customer[-_ ]?data)\b")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def state_dir(root: pathlib.Path) -> pathlib.Path:
    home = os.environ.get("STALLION_HOME") or os.environ.get("STALLION_HOME")
    if home:
        return pathlib.Path(home) / "state"
    return pathlib.Path(os.path.expanduser("~")) / ".stallion" / "state"


def flow_path(root: pathlib.Path) -> pathlib.Path:
    return state_dir(root) / "flows.json"


def load_store(root: pathlib.Path) -> dict[str, Any]:
    path = flow_path(root)
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
    path = flow_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(store, indent=2, sort_keys=True) + "\n")


def _hit(module: str, decision: str, reason: str, metadata: dict[str, Any]) -> dict[str, Any]:
    return {
        "module": module,
        "name": module.replace("-", " ").title(),
        "category": "flow-trust",
        "family": "Secrets & Identity",
        "decision": decision,
        "exit_code": 2 if decision == "block" else 0,
        "output": reason,
        "metadata": {
            "reason": reason,
            "confidence": 0.95 if decision == "block" else 0.84,
            "safer_alternative": metadata.get("safer_alternative", "Keep sensitive data in local reviewed flows and avoid exporting it through agent automation."),
            "flow_identity": metadata,
        },
    }


def _ensure_session(store: dict[str, Any], session_id: str) -> dict[str, Any]:
    session = store.setdefault("sessions", {}).setdefault(
        session_id,
        {"labels": [], "events": [], "updated_at": utc_now()},
    )
    return session


def _add_label(session: dict[str, Any], label: str, event_id: str, actor: str | None = None) -> None:
    labels = session.setdefault("labels", [])
    if not any(item.get("label") == label and item.get("actor") == actor for item in labels if isinstance(item, dict)):
        labels.append({"label": label, "event_id": event_id, "actor": actor, "ts": utc_now()})


def observe_result(root: pathlib.Path, result: dict[str, Any], payload: str) -> None:
    session_id = result.get("session_id")
    if not session_id:
        return
    store = load_store(root)
    session = _ensure_session(store, str(session_id))
    actor = str(result.get("subagent_id") or result.get("agent_id") or "")
    event_id = str(result.get("event_id") or "")
    matcher = str(result.get("matcher") or "")
    action = str(result.get("action") or "")

    if matcher in {"Read", "Bash", "Write", "Edit", "MultiEdit"} and SECRET_SOURCE_RE.search(payload):
        _add_label(session, "secret_data", event_id, actor)
    if matcher == "PostToolUse" and SECRET_SOURCE_RE.search(payload):
        _add_label(session, "secret_data", event_id, actor)
    if ARCHIVE_RE.search(payload):
        _add_label(session, "archive_ready", event_id, actor)
    if PROD_RE.search(payload):
        _add_label(session, "prod_data", event_id, actor)
    if "browser-sensitive-domain-guard" in json.dumps(result.get("hits", [])):
        _add_label(session, "browser_session", event_id, actor)
    if "browser-sensitive-export-guard" in json.dumps(result.get("hits", [])):
        _add_label(session, "browser_export", event_id, actor)
    if PUBLIC_ARTIFACT_RE.search(payload):
        _add_label(session, "public_artifact", event_id, actor)

    session.setdefault("events", []).append(
        {
            "event_id": event_id,
            "matcher": matcher,
            "action": action,
            "preview": payload[:200],
            "actor": actor,
            "ts": utc_now(),
        }
    )
    session["events"] = session["events"][-25:]
    session["updated_at"] = utc_now()
    save_store(root, store)


def assess_preflight(root: pathlib.Path, event: str, matcher: str, payload: str, context: dict[str, Any] | None = None) -> dict[str, Any] | None:
    session_id = (context or {}).get("session_id")
    if not session_id:
        return None
    store = load_store(root)
    session = store.get("sessions", {}).get(str(session_id))
    if not isinstance(session, dict):
        return None
    labels = {item.get("label") for item in session.get("labels", []) if isinstance(item, dict)}
    actor = str((context or {}).get("subagent_id") or (context or {}).get("agent_id") or "")
    label_actors = {
        item.get("label"): item.get("actor")
        for item in session.get("labels", [])
        if isinstance(item, dict) and item.get("label")
    }

    if UPLOAD_RE.search(payload) and ("secret_data" in labels or "archive_ready" in labels or "browser_export" in labels):
        if actor and "secret_data" in labels and label_actors.get("secret_data") not in {"", actor}:
            return _hit(
                "cross-agent-secret-flow-guard",
                "block",
                "Blocked cross-agent export because another agent in this session already accessed sensitive data.",
                {
                    "session_id": session_id,
                    "labels": sorted(labels),
                    "actor": actor,
                    "source_actor": label_actors.get("secret_data"),
                    "safer_alternative": "Keep sensitive reads and outbound actions in the same reviewed actor context or require explicit human approval before cross-agent export.",
                },
            )
        if actor and "browser_export" in labels and label_actors.get("browser_export") not in {"", actor}:
            return _hit(
                "cross-agent-browser-export-guard",
                "block",
                "Blocked cross-agent upload because another agent in this session already captured sensitive browser output.",
                {
                    "session_id": session_id,
                    "labels": sorted(labels),
                    "actor": actor,
                    "source_actor": label_actors.get("browser_export"),
                    "safer_alternative": "Keep browser export and outbound transfer inside one reviewed agent context or require a narrow human approval before handoff.",
                },
            )
    if ("secret_data" in labels or "browser_export" in labels) and CLIPBOARD_RE.search(payload):
        return _hit(
            "clipboard-secret-flow-guard",
            "block",
            "Blocked clipboard export because this session already touched sensitive data.",
            {
                "session_id": session_id,
                "labels": sorted(labels),
                "actor": actor,
                "safer_alternative": "Keep sensitive values out of clipboard bridges and use reviewed local handling instead.",
            },
        )

    if "secret_data" in labels and (ARCHIVE_RE.search(payload) or ENCODE_RE.search(payload)):
        return _hit(
            "secret-archive-prep-guard",
            "block",
            "Blocked archive or encoding step because this session already touched sensitive data and is preparing it for transport.",
            {
                "session_id": session_id,
                "labels": sorted(labels),
                "actor": actor,
                "safer_alternative": "Avoid re-packing secret-bearing material into archives or encoded blobs unless a human explicitly approved that flow.",
            },
        )

    if UPLOAD_RE.search(payload) and ("browser_session" in labels or "browser_export" in labels):
        return _hit(
            "browser-session-upload-guard",
            "block",
            "Blocked outbound transfer because this session already touched a sensitive authenticated browser session.",
            {
                "session_id": session_id,
                "labels": sorted(labels),
                "actor": actor,
                "safer_alternative": "Review browser-driven exports before sending anything derived from authenticated sessions outside the local runtime.",
            },
        )

    if UPLOAD_RE.search(payload) and ("secret_data" in labels or "archive_ready" in labels or "browser_export" in labels):
        reason = "Blocked outbound action because this session already touched sensitive data and now tries to export or publish it."
        return _hit(
            "sensitive-data-flow-guard",
            "block",
            reason,
            {
                "session_id": session_id,
                "labels": sorted(labels),
                "actor": actor,
                "safer_alternative": "Split sensitive reads from upload or publish steps, and keep export targets behind explicit human review.",
            },
        )

    if PUBLIC_ARTIFACT_RE.search(payload) and ("secret_data" in labels or "prod_data" in labels):
        return _hit(
            "public-artifact-flow-guard",
            "block",
            "Blocked artifact or public-output write because this session already touched sensitive or production data.",
            {
                "session_id": session_id,
                "labels": sorted(labels),
                "actor": actor,
                "safer_alternative": "Keep production and secret-bearing material out of public artifacts, build outputs, and release bundles.",
            },
        )

    return None


def list_sessions(root: pathlib.Path) -> list[dict[str, Any]]:
    items = []
    for session_id, data in load_store(root).get("sessions", {}).items():
        if isinstance(data, dict):
            items.append({"session_id": session_id, **data})
    items.sort(key=lambda item: item.get("updated_at", ""), reverse=True)
    return items


def explain_session(root: pathlib.Path, session_id: str) -> dict[str, Any] | None:
    session = load_store(root).get("sessions", {}).get(session_id)
    if isinstance(session, dict):
        return {"session_id": session_id, **session}
    return None


def clear_flow(root: pathlib.Path, session_id: str | None = None) -> int:
    store = load_store(root)
    if session_id:
        if session_id in store.get("sessions", {}):
            store["sessions"].pop(session_id, None)
            save_store(root, store)
            return 1
        return 0
    count = len(store.get("sessions", {}))
    store["sessions"] = {}
    save_store(root, store)
    return count


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage Stallion sensitive data flow state")
    parser.add_argument("--root", required=True)
    subparsers = parser.add_subparsers(dest="command", required=True)
    list_parser = subparsers.add_parser("list")
    list_parser.add_argument("--json", action="store_true")
    explain_parser = subparsers.add_parser("explain")
    explain_parser.add_argument("session_id")
    clear_parser = subparsers.add_parser("clear")
    clear_parser.add_argument("session_id", nargs="?")
    args = parser.parse_args()
    root = pathlib.Path(args.root)
    if args.command == "list":
        items = list_sessions(root)
        if args.json:
            print(json.dumps({"sessions": items}, indent=2))
        else:
            print("Sensitive Flows:")
            for item in items:
                labels = ",".join(sorted({entry.get("label", "") for entry in item.get("labels", []) if isinstance(entry, dict)}))
                print(f"- {item['session_id']} labels={labels}")
        return 0
    if args.command == "explain":
        payload = explain_session(root, args.session_id)
        if payload is None:
            print(f"unknown session: {args.session_id}", file=os.sys.stderr)
            return 1
        print(json.dumps(payload, indent=2))
        return 0
    if args.command == "clear":
        removed = clear_flow(root, args.session_id)
        print(f"cleared {removed} flow records")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
