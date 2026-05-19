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

import stallion_approvals


UNIX_SOCKET_RE = re.compile(r"(?P<path>/[A-Za-z0-9_./@-]+\.sock)\b|--unix-socket[= ](?P<flag>/[A-Za-z0-9_./@-]+)")
UNIX_CONNECT_RE = re.compile(r"(?i)UNIX-CONNECT:(?P<path>/[A-Za-z0-9_./@-]+)")
NAMED_PIPE_RE = re.compile(r"(?i)(\\\\\.\\pipe\\[A-Za-z0-9._-]+)")
SOCK_ENV_RE = re.compile(r"(?i)(?:SSH_AUTH_SOCK|GPG_AGENT_INFO|PINENTRY_USER_DATA)=(?P<path>/[A-Za-z0-9_./@-]+)")
LOCAL_LLM_RE = re.compile(r"(?i)(?:http://(?:127\.0\.0\.1|localhost):(?:11434|11435|1234|8000|8080|8081)\b|ollama\b|lmstudio\b|llama\.cpp|vllm\b)")
DEBUG_HELPER_RE = re.compile(r"(?i)(?:127\.0\.0\.1:(?:9222|9229|9333)\b|devtools/browser|--inspect(?:-brk)?\b|debug adapter)")
IDE_BACKEND_RE = re.compile(r"(?i)(?:\.cursor-server|\.vscode-server|windsurf|language-server|lsp|code helper|extensionhost|cursor agent|copilot-agent)")
CREDENTIAL_HELPER_RE = re.compile(r"(?i)(?:gpg-agent|ssh-agent|SSH_AUTH_SOCK|keyring|1password|op-ssh-sign|pinentry|security-agent|secret-tool)")
AGENT_SIDECAR_RE = re.compile(r"(?i)(?:stallion|claude|codex|openclaw).{0,40}(?:socket|sidecar|ipc|agent)")
WRAPPER_BRIDGE_RE = re.compile(r"(?i)(?:socat|nc|netcat|bash\s+-c|python(?:3)?\s+-c|node\s+-e)")
EXPORT_BRIDGE_RE = re.compile(r"(?i)(?:\bcurl\b[^\n\r]{0,120}(?:-T|--upload-file|-F|--form|--data|-d)\b|\bwget\b[^\n\r]{0,120}(?:--post-data|--body-file)\b|\bscp\b|\brsync\b|\brclone\b|webhook|pastebin|hooks\.slack\.com|discord(?:app)?\.com/api/webhooks|aws\s+s3\s+cp|gh\s+release\s+upload)")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def state_dir(root: pathlib.Path) -> pathlib.Path:
    home = os.environ.get("STALLION_HOME") or os.environ.get("STALLION_HOME")
    if home:
        return pathlib.Path(home) / "state"
    return pathlib.Path(os.path.expanduser("~")) / ".stallion" / "state"


def ipc_store_path(root: pathlib.Path) -> pathlib.Path:
    return state_dir(root) / "ipc.json"


def load_store(root: pathlib.Path) -> dict[str, Any]:
    path = ipc_store_path(root)
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
    path = ipc_store_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(store, indent=2, sort_keys=True) + "\n")


def _fingerprint(target: str, helper_class: str) -> str:
    payload = f"{helper_class}:{target}"
    path = pathlib.Path(target) if target.startswith("/") else None
    if path is not None:
        try:
            resolved = path.resolve(strict=False)
            stat = resolved.stat()
            payload += f":{resolved}:{stat.st_size}:{int(stat.st_mtime)}"
        except OSError:
            payload += f":{path.resolve(strict=False)}:missing"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _hit(module: str, decision: str, identity: dict[str, Any], reason: str, safer: str) -> dict[str, Any]:
    return {
        "module": module,
        "name": module.replace("-", " ").title(),
        "category": "ipc-trust",
        "family": "Local IPC & Helpers",
        "decision": decision,
        "exit_code": 2 if decision == "block" else 0,
        "output": reason,
        "metadata": {
            "reason": reason,
            "confidence": 0.96 if decision == "block" else 0.84,
            "safer_alternative": safer,
            "ipc_identity": identity,
        },
    }


def _service_equivalent(identity: dict[str, Any]) -> tuple[str, str] | None:
    helper_class = str(identity.get("helper_class") or "")
    target = str(identity.get("target") or "")
    if helper_class == "debug-helper":
        if target.startswith("http://") or target.startswith("https://"):
            service_target = target
        else:
            service_target = f"http://{target}"
        return ("browser-debug", service_target)
    if helper_class == "local-llm":
        if target.startswith("http://") or target.startswith("https://"):
            return ("localhost-admin", target)
    return None


def detect_ipc(payload: str) -> dict[str, Any] | None:
    match = NAMED_PIPE_RE.search(payload)
    if match:
        target = match.group(1)
        return {
            "target": target,
            "kind": "pipe",
            "helper_class": "named-pipe",
            "fingerprint": _fingerprint(target, "named-pipe"),
        }

    match = SOCK_ENV_RE.search(payload)
    if match:
        target = match.group("path")
        return {
            "target": target,
            "kind": "unix",
            "helper_class": "credential-helper",
            "fingerprint": _fingerprint(target, "credential-helper"),
        }

    for regex in (UNIX_SOCKET_RE, UNIX_CONNECT_RE):
        match = regex.search(payload)
        if match:
            target = match.groupdict().get("path") or match.groupdict().get("flag") or match.group(0)
            lowered = target.lower()
            if CREDENTIAL_HELPER_RE.search(payload) or any(item in lowered for item in ("gpg-agent", "keyring", "ssh", "pinentry")):
                helper_class = "credential-helper"
            elif IDE_BACKEND_RE.search(payload) or any(item in lowered for item in ("cursor", "vscode", "windsurf", "lsp", "language-server")):
                helper_class = "ide-backend"
            elif AGENT_SIDECAR_RE.search(payload) or any(item in lowered for item in ("claude", "codex", "stallion", "openclaw")):
                helper_class = "agent-sidecar"
            else:
                helper_class = "unix-helper"
            return {
                "target": target,
                "kind": "unix",
                "helper_class": helper_class,
                "fingerprint": _fingerprint(target, helper_class),
            }

    if LOCAL_LLM_RE.search(payload):
        target = "http://127.0.0.1:11434"
        url_match = re.search(r"(?i)http://(?:127\.0\.0\.1|localhost):\d+", payload)
        if url_match:
            target = url_match.group(0)
        return {
            "target": target,
            "kind": "tcp",
            "helper_class": "local-llm",
            "fingerprint": _fingerprint(target, "local-llm"),
        }

    if DEBUG_HELPER_RE.search(payload):
        target = "debug-helper"
        url_match = re.search(r"(?i)(?:127\.0\.0\.1|localhost):(?:9222|9229|9333)", payload)
        if url_match:
            target = url_match.group(0)
        return {
            "target": target,
            "kind": "tcp",
            "helper_class": "debug-helper",
            "fingerprint": _fingerprint(target, "debug-helper"),
        }

    return None


def assess_command(root: pathlib.Path, payload: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
    identity = detect_ipc(payload)
    if not identity:
        return {"identity": None, "hit": None}

    ctx = context or {}
    target = str(identity["target"])
    helper_class = str(identity["helper_class"])
    approval_assessment = stallion_approvals.assess_match(
        root,
        kind="ipc",
        target=helper_class,
        value=target,
        runtime=str(ctx.get("runtime")) if ctx.get("runtime") else None,
        repo=str(root.resolve(strict=False)),
        agent_id=str(ctx.get("subagent_id") or ctx.get("agent_id")) if (ctx.get("subagent_id") or ctx.get("agent_id")) else None,
        fingerprint=str(identity["fingerprint"]),
    )
    approval = approval_assessment.get("approval")
    approval_hit = approval_assessment.get("hit")
    service_equivalent = _service_equivalent(identity)
    service_approval = None
    if service_equivalent and not approval:
        service_target_class, service_target_value = service_equivalent
        service_approval_assessment = stallion_approvals.assess_match(
            root,
            kind="service",
            target=service_target_class,
            value=service_target_value,
            runtime=str(ctx.get("runtime")) if ctx.get("runtime") else None,
            repo=str(root.resolve(strict=False)),
            agent_id=str(ctx.get("subagent_id") or ctx.get("agent_id")) if (ctx.get("subagent_id") or ctx.get("agent_id")) else None,
            fingerprint=None,
            consume=False,
        )
        service_approval = service_approval_assessment.get("approval")
    store = load_store(root)
    existing = store.setdefault("targets", {}).get(target)
    trust_state = "observed"
    hit = None

    if approval:
        trust_state = "approved"
    elif service_approval:
        trust_state = "approved"
    elif approval_hit:
        trust_state = "prompted"
        hit = approval_hit
    elif isinstance(existing, dict) and existing.get("trust_state") == "approved" and existing.get("fingerprint") != identity["fingerprint"]:
        trust_state = "drifted"
        hit = _hit(
            "unix-socket-drift-guard",
            "prompt",
            identity,
            f"Review required because local IPC target drifted for {target}.",
            f"Run `./bin/stallion ipc diff {target}` and re-approve only if the new helper endpoint is still expected.",
        )
    elif helper_class == "credential-helper":
        trust_state = "blocked"
        hit = _hit(
            "credential-helper-ipc-guard",
            "block",
            identity,
            f"Blocked direct access to credential-helper IPC target {target}.",
            "Keep SSH agents, keyrings, gpg-agent, and similar credential helper channels out of agent reach.",
        )
    elif helper_class == "named-pipe":
        trust_state = "blocked"
        hit = _hit(
            "named-pipe-admin-guard",
            "block",
            identity,
            f"Blocked access to named-pipe IPC target {target}.",
            "Treat local named pipes like privileged control surfaces instead of transparent transport.",
        )
    elif EXPORT_BRIDGE_RE.search(payload) and identity["kind"] in {"unix", "pipe"}:
        trust_state = "blocked"
        hit = _hit(
            "ipc-export-bridge-guard",
            "block",
            identity,
            f"Blocked outbound export bridge from IPC target {target}.",
            "Keep local helper and sidecar channels away from upload, webhook, and export flows.",
        )
    elif WRAPPER_BRIDGE_RE.search(payload) and identity["kind"] in {"unix", "pipe"}:
        trust_state = "blocked"
        hit = _hit(
            "ipc-wrapper-bridge-guard",
            "block",
            identity,
            f"Blocked wrapper or inline interpreter bridge against IPC target {target}.",
            "Do not bridge helper sockets into ad hoc shell, socat, netcat, or inline interpreter execution paths.",
        )
    elif helper_class == "debug-helper":
        trust_state = "prompted"
        hit = _hit(
            "debug-helper-ipc-guard",
            "prompt",
            identity,
            f"Review required before trusting debug helper target {target}.",
            f"Run `./bin/stallion ipc approve {target}` only if this local debug helper is expected.",
        )
    elif helper_class == "local-llm":
        trust_state = "prompted"
        hit = _hit(
            "local-llm-socket-guard",
            "prompt",
            identity,
            f"Review required before trusting local LLM endpoint {target}.",
            f"Run `./bin/stallion ipc approve {target}` only if this local model endpoint is expected in your workflow.",
        )
    elif helper_class == "ide-backend":
        trust_state = "prompted"
        hit = _hit(
            "ide-backend-ipc-guard",
            "prompt",
            identity,
            f"Review required before trusting IDE backend IPC target {target}.",
            f"Run `./bin/stallion ipc approve {target}` only if this IDE helper endpoint is expected.",
        )
    elif helper_class == "agent-sidecar":
        trust_state = "prompted"
        hit = _hit(
            "agent-sidecar-ipc-guard",
            "prompt",
            identity,
            f"Review required before trusting agent sidecar IPC target {target}.",
            f"Run `./bin/stallion ipc approve {target}` only if this sidecar endpoint is part of your expected runtime setup.",
        )
    else:
        trust_state = "prompted"
        hit = _hit(
            "ipc-first-seen-review-guard",
            "prompt",
            identity,
            f"Review required before trusting new local IPC target {target}.",
            f"Run `./bin/stallion ipc approve {target}` only after confirming this helper endpoint is expected.",
        )

    stored_state = trust_state
    if (
        trust_state in {"blocked", "prompted"}
        and isinstance(existing, dict)
        and existing.get("trust_state") == "approved"
        and existing.get("fingerprint") == identity["fingerprint"]
    ) or approval or service_approval:
        stored_state = "approved"

    record = {
        "target": target,
        "kind": identity["kind"],
        "helper_class": helper_class,
        "fingerprint": identity["fingerprint"],
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
    items.sort(key=lambda item: (item.get("helper_class", ""), item.get("target", "")))
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
        kind="ipc",
        target=str(record.get("helper_class")),
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
    parser = argparse.ArgumentParser(description="Manage Stallion local IPC and helper trust")
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
            print("Local IPC Targets:")
            for item in items:
                print(f"- {item.get('helper_class')} [{item.get('trust_state')}] {item.get('target')}")
        return 0
    if args.command == "approve":
        if approve_target(root, args.selector):
            print(f"approved {args.selector}")
            return 0
        print(f"unknown IPC target: {args.selector}", file=os.sys.stderr)
        return 1
    if args.command == "forget":
        if forget_target(root, args.selector):
            print(f"forgot {args.selector}")
            return 0
        print(f"unknown IPC target: {args.selector}", file=os.sys.stderr)
        return 1
    if args.command == "diff":
        payload = diff_target(root, args.selector)
        if payload is None:
            print(f"unknown IPC target: {args.selector}", file=os.sys.stderr)
            return 1
        print(json.dumps(payload, indent=2))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
