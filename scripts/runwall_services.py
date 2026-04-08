#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
from datetime import datetime, timezone
from typing import Any

import runwall_approvals


LOCAL_URL_RE = re.compile(r"(?i)\bhttps?://(?P<host>127\.0\.0\.1|localhost|0\.0\.0\.0)(?::(?P<port>\d+))?")
PRIVATE_URL_RE = re.compile(r"(?i)\bhttps?://(?P<host>10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[0-1])\.\d+\.\d+)(?::(?P<port>\d+))?")
METADATA_URL_RE = re.compile(r"(?i)\bhttps?://(?P<host>169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)(?::(?P<port>\d+))?")
SOCKET_RE = re.compile(r"(?P<path>/var/run/docker\.sock|/run/docker\.sock|/var/run/containerd/containerd\.sock|/run/containerd/containerd\.sock|/var/run/podman/podman\.sock|/run/user/\d+/podman/podman\.sock|/var/run/crio/crio\.sock|/run/crio/crio\.sock|/var/run/dbus/system_bus_socket|/run/user/\d+/gnupg/S\.gpg-agent(?:\.ssh)?|/run/user/\d+/keyring/ssh)")
UNIX_FLAG_RE = re.compile(r"--unix-socket[= ](?P<path>/[A-Za-z0-9_./-]+)")
SSH_AGENT_RE = re.compile(r"(?i)\bssh-add\b|\bSSH_AUTH_SOCK=")


DEFAULT_ADMIN_PORTS = {2375, 2376, 9222, 9223, 5432, 6379, 27017, 5000, 6443}
DATABASE_PORTS = {3306, 5432, 6379, 27017, 9200}
KUBE_PORTS = {6443, 8443}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def state_dir(root: pathlib.Path) -> pathlib.Path:
    home = os.environ.get("RUNWALL_HOME") or os.environ.get("SECURE_CLAUDE_CODE_HOME")
    if home:
        return pathlib.Path(home) / "state"
    return pathlib.Path(os.path.expanduser("~")) / ".runwall" / "state"


def services_store_path(root: pathlib.Path) -> pathlib.Path:
    return state_dir(root) / "services.json"


def load_store(root: pathlib.Path) -> dict[str, Any]:
    path = services_store_path(root)
    if not path.exists():
        return {"version": 1, "services": {}}
    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {"version": 1, "services": {}}
    if not isinstance(payload, dict):
        return {"version": 1, "services": {}}
    payload.setdefault("version", 1)
    payload.setdefault("services", {})
    return payload


def save_store(root: pathlib.Path, store: dict[str, Any]) -> None:
    path = services_store_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(store, indent=2, sort_keys=True) + "\n")


def _fingerprint(target: str, kind: str) -> str:
    return hashlib.sha256(f"{kind}:{target}".encode("utf-8")).hexdigest()


def _hit(module: str, decision: str, identity: dict[str, Any], reason: str, safer: str) -> dict[str, Any]:
    return {
        "module": module,
        "name": module.replace("-", " ").title(),
        "category": "service-trust",
        "family": "Runtime, Network & Egress",
        "decision": decision,
        "exit_code": 2 if decision == "block" else 0,
        "output": reason,
        "metadata": {
            "reason": reason,
            "confidence": 0.96 if decision == "block" else 0.84,
            "safer_alternative": safer,
            "service_identity": identity,
        },
    }


def detect_service(payload: str) -> dict[str, Any] | None:
    for match in METADATA_URL_RE.finditer(payload):
        host = match.group("host")
        port = int(match.group("port") or 80)
        return {"target": f"http://{host}:{port}", "kind": "tcp", "service_class": "metadata-service", "port": port}
    for regex in (SOCKET_RE, UNIX_FLAG_RE):
        match = regex.search(payload)
        if match:
            path = match.groupdict().get("path") or match.group(0)
            lower = path.lower()
            if "docker" in lower or "containerd" in lower or "podman" in lower or "crio" in lower:
                service_class = "container-socket"
            elif "dbus" in lower:
                service_class = "dbus"
            elif "ssh" in lower or "gpg-agent" in lower or "keyring" in lower:
                service_class = "agent-socket"
            else:
                service_class = "unix-service"
            return {"target": path, "kind": "unix", "service_class": service_class}
    for match in LOCAL_URL_RE.finditer(payload):
        host = match.group("host")
        port = int(match.group("port") or 80)
        target = f"http://{host}:{port}"
        if port in {9222, 9223}:
            service_class = "browser-debug"
        elif port in {2375, 2376}:
            service_class = "docker-api"
        elif port in KUBE_PORTS:
            service_class = "kube-api"
        elif port in DATABASE_PORTS:
            service_class = "database-admin"
        else:
            service_class = "localhost-admin"
        return {"target": target, "kind": "tcp", "service_class": service_class, "port": port}
    for match in PRIVATE_URL_RE.finditer(payload):
        host = match.group("host")
        port = int(match.group("port") or 80)
        if port in KUBE_PORTS:
            service_class = "kube-api"
        elif port in DATABASE_PORTS:
            service_class = "database-admin"
        else:
            service_class = "private-service"
        return {"target": f"http://{host}:{port}", "kind": "tcp", "service_class": service_class, "port": port}
    if SSH_AGENT_RE.search(payload):
        return {"target": "ssh-agent", "kind": "env", "service_class": "agent-socket"}
    return None


def assess_command(root: pathlib.Path, payload: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
    identity = detect_service(payload)
    if not identity:
        return {"identity": None, "hit": None}
    runtime = (context or {}).get("runtime")
    agent_id = (context or {}).get("subagent_id") or (context or {}).get("agent_id")
    target = str(identity["target"])
    fingerprint = _fingerprint(target, str(identity["kind"]))
    approval = runwall_approvals.match_approval(
        root,
        kind="service",
        target=str(identity["service_class"]),
        value=target,
        runtime=str(runtime) if runtime else None,
        agent_id=str(agent_id) if agent_id else None,
        fingerprint=fingerprint,
    )
    store = load_store(root)
    existing = store.setdefault("services", {}).get(target)
    trust_state = "observed"
    hit = None
    if approval:
        trust_state = "approved"
    elif identity["service_class"] == "metadata-service":
        trust_state = "blocked"
        hit = _hit(
            "metadata-endpoint-service-guard",
            "block",
            identity,
            f"Blocked access to metadata endpoint {target}.",
            "Keep cloud and platform metadata endpoints out of agent reach unless you are on a narrowly reviewed debugging path.",
        )
    elif identity["service_class"] == "kube-api":
        trust_state = "blocked"
        hit = _hit(
            "local-kube-admin-guard",
            "block",
            identity,
            f"Blocked direct access to local or private Kubernetes control plane target {target}.",
            "Use reviewed cluster workflows instead of direct agent access to kube admin surfaces.",
        )
    elif identity["service_class"] == "database-admin":
        trust_state = "prompted"
        hit = _hit(
            "database-admin-service-guard",
            "prompt",
            identity,
            f"Review required before trusting database or admin service target {target}.",
            f"Run `./bin/runwall services approve {target}` only after confirming this local database or admin service is part of your expected workflow.",
        )
    elif identity["service_class"] in {"container-socket", "dbus", "agent-socket"}:
        trust_state = "blocked"
        hit = _hit(
            "local-admin-socket-guard",
            "block",
            identity,
            f"Blocked access to sensitive local service {identity['service_class']} at {target}.",
            "Keep Docker, DBus, SSH agent, and similar local control sockets behind explicit approval or avoid exposing them to the runtime.",
        )
    elif identity["service_class"] in {"browser-debug", "private-service", "localhost-admin"} or int(identity.get("port") or 0) in DEFAULT_ADMIN_PORTS:
        if existing and existing.get("fingerprint") != fingerprint:
            trust_state = "prompted"
            hit = _hit(
                "service-drift-guard",
                "prompt",
                identity,
                f"Review required because local service identity drifted for {target}.",
                f"Run `./bin/runwall services approve {target}` only after confirming the new local service is expected.",
            )
        else:
            trust_state = "prompted"
            hit = _hit(
                "sensitive-local-service-guard",
                "prompt",
                identity,
                f"Review required before trusting sensitive local service target {target}.",
                f"Run `./bin/runwall services approve {target}` if this local service is expected for your workflow.",
            )
    else:
        trust_state = "trusted"

    record = {
        "target": target,
        "kind": identity["kind"],
        "service_class": identity["service_class"],
        "port": identity.get("port"),
        "fingerprint": fingerprint,
        "trust_state": trust_state,
        "first_seen_at": existing.get("first_seen_at") if isinstance(existing, dict) else utc_now(),
        "last_seen_at": utc_now(),
    }
    store["services"][target] = record
    save_store(root, store)
    return {"identity": identity, "hit": hit}


def list_services(root: pathlib.Path) -> list[dict[str, Any]]:
    items = [dict(value) for value in load_store(root).get("services", {}).values() if isinstance(value, dict)]
    items.sort(key=lambda item: (item.get("service_class", ""), item.get("target", "")))
    return items


def approve_service(root: pathlib.Path, selector: str) -> bool:
    store = load_store(root)
    record = store.setdefault("services", {}).get(selector)
    if not isinstance(record, dict):
        for key, value in store.get("services", {}).items():
            if isinstance(value, dict) and value.get("target") == selector:
                selector = key
                record = value
                break
    if not isinstance(record, dict):
        return False
    runwall_approvals.create_approval(
        root,
        kind="service",
        target=str(record.get("service_class")),
        value=str(record.get("target")),
        fingerprint=str(record.get("fingerprint")),
    )
    record["trust_state"] = "approved"
    store["services"][selector] = record
    save_store(root, store)
    return True


def forget_service(root: pathlib.Path, selector: str) -> bool:
    store = load_store(root)
    services = store.setdefault("services", {})
    if selector in services:
        services.pop(selector, None)
        save_store(root, store)
        return True
    return False


def diff_service(root: pathlib.Path, selector: str) -> dict[str, Any] | None:
    record = load_store(root).get("services", {}).get(selector)
    if isinstance(record, dict):
        return record
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage Runwall local service trust")
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
        items = list_services(root)
        if args.json:
            print(json.dumps({"services": items}, indent=2))
        else:
            print("Services:")
            for item in items:
                print(f"- {item.get('service_class')} [{item.get('trust_state')}] {item.get('target')}")
        return 0
    if args.command == "approve":
        if approve_service(root, args.selector):
            print(f"approved {args.selector}")
            return 0
        print(f"unknown service: {args.selector}", file=os.sys.stderr)
        return 1
    if args.command == "forget":
        if forget_service(root, args.selector):
            print(f"forgot {args.selector}")
            return 0
        print(f"unknown service: {args.selector}", file=os.sys.stderr)
        return 1
    if args.command == "diff":
        payload = diff_service(root, args.selector)
        if payload is None:
            print(f"unknown service: {args.selector}", file=os.sys.stderr)
            return 1
        print(json.dumps(payload, indent=2))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
