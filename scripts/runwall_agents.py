#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
from datetime import datetime, timezone
from typing import Any

UPLOAD_RE = re.compile(r"(?i)\b(curl|wget|scp|rsync|rclone|aws\s+s3\s+cp|gsutil\s+cp|az\s+storage\s+blob\s+upload|gh\s+release\s+upload|upload-artifact)\b|https?://")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def state_dir(root: pathlib.Path) -> pathlib.Path:
    home = os.environ.get("RUNWALL_HOME") or os.environ.get("SECURE_CLAUDE_CODE_HOME")
    if home:
        return pathlib.Path(home) / "state"
    return pathlib.Path(os.path.expanduser("~")) / ".runwall" / "state"


def graph_path(root: pathlib.Path) -> pathlib.Path:
    return state_dir(root) / "agents.json"


def load_store(root: pathlib.Path) -> dict[str, Any]:
    path = graph_path(root)
    if not path.exists():
        return {"version": 1, "isolated_agents": [], "events": []}
    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {"version": 1, "isolated_agents": [], "events": []}
    if not isinstance(payload, dict):
        return {"version": 1, "isolated_agents": [], "events": []}
    payload.setdefault("version", 1)
    payload.setdefault("isolated_agents", [])
    payload.setdefault("events", [])
    return payload


def save_store(root: pathlib.Path, store: dict[str, Any]) -> None:
    path = graph_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(store, indent=2, sort_keys=True) + "\n")


def observe_result(root: pathlib.Path, result: dict[str, Any], payload: str) -> None:
    store = load_store(root)
    actor = result.get("subagent_id") or result.get("agent_id")
    if not actor:
        return
    store.setdefault("events", []).append(
        {
            "event_id": result.get("event_id"),
            "session_id": result.get("session_id"),
            "agent_id": result.get("agent_id"),
            "subagent_id": result.get("subagent_id"),
            "parent_agent_id": result.get("parent_agent_id"),
            "matcher": result.get("matcher"),
            "action": result.get("action"),
            "preview": payload[:180],
            "ts": utc_now(),
        }
    )
    store["events"] = store["events"][-200:]
    save_store(root, store)


def assess_context(root: pathlib.Path, context: dict[str, Any] | None) -> dict[str, Any] | None:
    ctx = context or {}
    actor = str(ctx.get("subagent_id") or ctx.get("agent_id") or "")
    if not actor:
        return None
    store = load_store(root)
    isolated = set(store.get("isolated_agents", []))
    if actor not in isolated:
        parent = str(ctx.get("parent_agent_id") or ctx.get("agent_id") or "")
        if parent and parent in isolated and actor != parent:
            return {
                "module": "isolated-parent-bridge-guard",
                "name": "Isolated Parent Bridge Guard",
                "category": "agent-graph",
                "family": "Trust, Persistence & Evasion",
                "decision": "block",
                "exit_code": 2,
                "output": f"Blocked action because parent agent {parent} is isolated and child agent {actor} cannot inherit around that boundary.",
                "metadata": {
                    "reason": "A child or delegated agent cannot keep executing once the parent actor has been isolated.",
                    "confidence": 0.97,
                    "safer_alternative": f"Review the parent agent context first, then clear isolation explicitly with `./bin/runwall agents unisolate {parent}` if appropriate.",
                    "agent_identity": {"actor": actor, "parent_agent_id": parent, "session_id": ctx.get("session_id")},
                },
            }
        return None
    return {
        "module": "isolated-agent-guard",
        "name": "Isolated Agent Guard",
        "category": "agent-graph",
        "family": "Quality & Workflow",
        "decision": "block",
        "exit_code": 2,
        "output": f"Blocked action because agent {actor} is currently isolated.",
        "metadata": {
            "reason": "This agent was manually isolated, so Runwall blocks further actions until the isolation is cleared.",
            "confidence": 0.98,
            "safer_alternative": f"Run `./bin/runwall agents unisolate {actor}` only after reviewing why the agent was isolated.",
            "agent_identity": {"actor": actor, "session_id": ctx.get("session_id")},
        },
    }


def assess_action(root: pathlib.Path, payload: str, context: dict[str, Any] | None) -> dict[str, Any] | None:
    ctx = context or {}
    session_id = str(ctx.get("session_id") or "")
    if not session_id or not UPLOAD_RE.search(payload):
        return None
    for item in graph_sessions(root):
        if item["session_id"] != session_id:
            continue
        if len(item.get("actors", [])) < 4:
            return None
        return {
            "module": "agent-fanout-guard",
            "name": "Agent Fanout Guard",
            "category": "agent-graph",
            "family": "Quality & Workflow",
            "decision": "prompt",
            "exit_code": 0,
            "output": f"Review required because session {session_id} already fanned out across {len(item.get('actors', []))} agents before an outbound action.",
            "metadata": {
                "reason": "Large multi-agent fanout before an outbound action is a common capability-laundering pattern and deserves review.",
                "confidence": 0.83,
                "safer_alternative": "Reduce the agent fanout or keep outbound actions in a narrow reviewed actor set before proceeding.",
                "agent_identity": {"session_id": session_id, "actors": item.get("actors", [])},
            },
        }
    return None


def graph_sessions(root: pathlib.Path) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for event in load_store(root).get("events", []):
        if not isinstance(event, dict):
            continue
        session_id = str(event.get("session_id") or "unknown")
        item = grouped.setdefault(session_id, {"session_id": session_id, "actors": set(), "edges": []})
        actor = event.get("subagent_id") or event.get("agent_id")
        if actor:
            item["actors"].add(actor)
        if event.get("parent_agent_id") and actor:
            item["edges"].append({"from": event.get("parent_agent_id"), "to": actor, "event_id": event.get("event_id")})
    results = []
    for item in grouped.values():
        results.append(
            {
                "session_id": item["session_id"],
                "actors": sorted(item["actors"]),
                "edges": item["edges"],
            }
        )
    results.sort(key=lambda row: row["session_id"])
    return results


def isolate_agent(root: pathlib.Path, agent_id: str) -> None:
    store = load_store(root)
    isolated = {str(item) for item in store.get("isolated_agents", [])}
    isolated.add(agent_id)
    store["isolated_agents"] = sorted(isolated)
    save_store(root, store)


def unisolate_agent(root: pathlib.Path, agent_id: str) -> bool:
    store = load_store(root)
    isolated = [str(item) for item in store.get("isolated_agents", [])]
    if agent_id not in isolated:
        return False
    store["isolated_agents"] = [item for item in isolated if item != agent_id]
    save_store(root, store)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage Runwall agent graph state")
    parser.add_argument("--root", required=True)
    subparsers = parser.add_subparsers(dest="command", required=True)
    graph_parser = subparsers.add_parser("graph")
    graph_parser.add_argument("--json", action="store_true")
    explain_parser = subparsers.add_parser("explain")
    explain_parser.add_argument("session_id")
    isolate_parser = subparsers.add_parser("isolate")
    isolate_parser.add_argument("agent_id")
    unisolate_parser = subparsers.add_parser("unisolate")
    unisolate_parser.add_argument("agent_id")
    args = parser.parse_args()
    root = pathlib.Path(args.root)
    if args.command == "graph":
        items = graph_sessions(root)
        if args.json:
            print(json.dumps({"sessions": items, "isolated_agents": load_store(root).get("isolated_agents", [])}, indent=2))
        else:
            print("Agent Graph:")
            for item in items:
                print(f"- {item['session_id']} actors={','.join(item['actors'])}")
        return 0
    if args.command == "explain":
        for item in graph_sessions(root):
            if item["session_id"] == args.session_id:
                print(json.dumps(item, indent=2))
                return 0
        print(f"unknown session: {args.session_id}", file=os.sys.stderr)
        return 1
    if args.command == "isolate":
        isolate_agent(root, args.agent_id)
        print(f"isolated {args.agent_id}")
        return 0
    if args.command == "unisolate":
        if unisolate_agent(root, args.agent_id):
            print(f"unisolated {args.agent_id}")
            return 0
        print(f"unknown isolated agent: {args.agent_id}", file=os.sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
