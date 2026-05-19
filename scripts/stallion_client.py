#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import hmac
import json
import os
import pathlib
import re
import shlex
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any


DEFAULT_CONFIG = {
    "enabled": False,
    "server_url": "",
    "policy_file": "state/stallion-policy.json",
    "event_queue_file": "state/stallion-events.jsonl",
    "fail_closed": False,
    "max_policy_age_seconds": 86400,
    "upload_enabled": False,
    "upload_path": "/api/client/events",
    "capture": {
        "audit_events": True,
        "prompts": True,
        "tool_payloads": True,
        "redact": True,
    },
    "verification": {
        "mode": "none",
        "sha256": "",
        "hmac_env": "STALLION_STALLION_POLICY_HMAC_KEY",
    },
}

DEFAULT_POLICY = {
    "version": 1,
    "policy_id": "local-unmanaged",
    "mode": "monitor",
    "mcp": {"default": "allow", "servers": {}},
    "required_routes": [],
    "plugins": {"default": "allow", "allow": [], "deny": []},
    "skills": {"default": "allow", "allow": [], "deny": []},
}

ACTION_PRIORITY = {"allow": 0, "warn": 1, "prompt": 2, "block": 3}

PLUGIN_COMMAND_RE = re.compile(
    r"(?i)\b(?:claude|codex|openclaw)\s+plugin\s+(?:install|add|marketplace\s+add|marketplace\s+install)\s+([^\s;&|]+)"
)
SKILL_COMMAND_RE = re.compile(
    r"(?i)\b(?:claude|codex|openclaw)?\s*(?:skill|skills)\s+(?:install|add|use|enable)\s+([^\s;&|]+)"
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_json_dumps(payload: Any) -> str:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def _merge_config(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    merged = json.loads(json.dumps(base))
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key].update(value)
        else:
            merged[key] = value
    return merged


def _state_base(root: pathlib.Path) -> pathlib.Path:
    home = os.environ.get("STALLION_HOME") or os.environ.get("STALLION_HOME")
    if home:
        return pathlib.Path(home)
    return root


def _resolve_config_path(root: pathlib.Path) -> pathlib.Path:
    override = os.environ.get("STALLION_CLIENT_CONFIG")
    if override:
        return pathlib.Path(override).expanduser()
    return root / "config" / "stallion-client.json"


def _resolve_path(root: pathlib.Path, configured: str | None) -> pathlib.Path:
    text = configured or ""
    if not text:
        return _state_base(root) / "state" / "stallion-policy.json"
    path = pathlib.Path(os.path.expanduser(text))
    if path.is_absolute():
        return path
    return _state_base(root) / path


def _env_enabled() -> bool | None:
    value = os.environ.get("STALLION_STALLION_ENABLED")
    if value is None:
        return None
    return value.strip().lower() in {"1", "true", "yes", "on"}


def load_client_config(root: pathlib.Path) -> dict[str, Any]:
    config = json.loads(json.dumps(DEFAULT_CONFIG))
    path = _resolve_config_path(root)
    if path.exists():
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                config = _merge_config(config, payload)
        except json.JSONDecodeError:
            config["config_error"] = f"invalid Stallion client config: {path}"
    enabled_override = _env_enabled()
    if enabled_override is not None:
        config["enabled"] = enabled_override
    return config


def client_enabled(root: pathlib.Path) -> bool:
    return bool(load_client_config(root).get("enabled"))


def policy_file_path(root: pathlib.Path, config: dict[str, Any] | None = None) -> pathlib.Path:
    config = config or load_client_config(root)
    override = os.environ.get("STALLION_STALLION_POLICY")
    return pathlib.Path(override).expanduser() if override else _resolve_path(root, str(config.get("policy_file") or ""))


def event_queue_path(root: pathlib.Path, config: dict[str, Any] | None = None) -> pathlib.Path:
    config = config or load_client_config(root)
    override = os.environ.get("STALLION_STALLION_EVENT_QUEUE")
    return pathlib.Path(override).expanduser() if override else _resolve_path(root, str(config.get("event_queue_file") or ""))


def _canonical_policy_bytes(policy: dict[str, Any]) -> bytes:
    unsigned = dict(policy)
    unsigned.pop("signature", None)
    return safe_json_dumps(unsigned).encode("utf-8")


def verify_policy(policy: dict[str, Any], config: dict[str, Any]) -> tuple[bool, str]:
    verification = config.get("verification") if isinstance(config.get("verification"), dict) else {}
    mode = str(verification.get("mode") or "none").lower()
    if mode in {"", "none"}:
        return True, "verification disabled"
    if mode == "sha256":
        expected = str(verification.get("sha256") or policy.get("sha256") or "").strip().lower()
        actual = hashlib.sha256(_canonical_policy_bytes(policy)).hexdigest()
        if expected and hmac.compare_digest(expected, actual):
            return True, "sha256 verified"
        return False, "policy sha256 verification failed"
    if mode == "hmac-sha256":
        signature = str((policy.get("signature") or {}).get("value") or "").strip()
        secret = os.environ.get(str(verification.get("hmac_env") or "STALLION_STALLION_POLICY_HMAC_KEY"), "")
        if not signature or not secret:
            return False, "policy hmac verification missing key or signature"
        actual = hmac.new(secret.encode("utf-8"), _canonical_policy_bytes(policy), hashlib.sha256).hexdigest()
        if hmac.compare_digest(signature.lower(), actual.lower()):
            return True, "hmac-sha256 verified"
        return False, "policy hmac verification failed"
    return False, f"unsupported policy verification mode: {mode}"


def _parse_time(value: Any) -> float | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        text = value.strip().replace("Z", "+00:00")
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


def load_policy(root: pathlib.Path, config: dict[str, Any] | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    config = config or load_client_config(root)
    if not config.get("enabled"):
        return json.loads(json.dumps(DEFAULT_POLICY)), {"ok": True, "enabled": False, "reason": "Stallion client disabled"}
    path = policy_file_path(root, config)
    if not path.exists():
        return json.loads(json.dumps(DEFAULT_POLICY)), {
            "ok": not bool(config.get("fail_closed")),
            "enabled": True,
            "missing": True,
            "reason": f"Stallion policy cache missing: {path}",
        }
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return json.loads(json.dumps(DEFAULT_POLICY)), {
            "ok": not bool(config.get("fail_closed")),
            "enabled": True,
            "invalid": True,
            "reason": f"Stallion policy cache is invalid JSON: {path}",
        }
    if not isinstance(policy, dict):
        return json.loads(json.dumps(DEFAULT_POLICY)), {
            "ok": not bool(config.get("fail_closed")),
            "enabled": True,
            "invalid": True,
            "reason": f"Stallion policy cache is not an object: {path}",
        }
    verified, verify_reason = verify_policy(policy, config)
    if not verified:
        return policy, {
            "ok": not bool(config.get("fail_closed")),
            "enabled": True,
            "invalid": True,
            "reason": verify_reason,
        }
    now = time.time()
    fetched_at = _parse_time(policy.get("fetched_at") or policy.get("issued_at"))
    expires_at = _parse_time(policy.get("expires_at"))
    max_age = int(config.get("max_policy_age_seconds") or 0)
    if expires_at is not None and now > expires_at:
        return policy, {
            "ok": not bool(config.get("fail_closed")),
            "enabled": True,
            "stale": True,
            "reason": "Stallion policy cache expired",
        }
    if fetched_at is not None and max_age > 0 and now - fetched_at > max_age:
        return policy, {
            "ok": not bool(config.get("fail_closed")),
            "enabled": True,
            "stale": True,
            "reason": "Stallion policy cache is older than max_policy_age_seconds",
        }
    return _merge_config(DEFAULT_POLICY, policy), {
        "ok": True,
        "enabled": True,
        "reason": verify_reason,
        "policy_id": policy.get("policy_id"),
    }


def _hit(
    module: str,
    decision: str,
    output: str,
    *,
    reason: str,
    policy: dict[str, Any] | None = None,
    evidence: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "module": module,
        "name": "Stallion Managed Policy",
        "category": "stallion-governance",
        "decision": decision,
        "exit_code": 2 if decision == "block" else 0,
        "output": output,
        "metadata": {
            "reason": reason,
            "policy_id": (policy or {}).get("policy_id"),
            "confidence": 0.98 if decision == "block" else 0.86,
            "evidence": evidence or [],
        },
    }


def _status_hit(status: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any] | None:
    if status.get("ok", True):
        return None
    return _hit(
        "stallion-policy-unavailable",
        "block",
        "Blocked because managed Stallion policy is missing, invalid, or stale.",
        reason=str(status.get("reason") or "Stallion policy unavailable"),
        policy=policy,
        evidence=[{"type": "policy_status", **status}],
    )


def _selectors_match(name: str, selectors: list[Any]) -> bool:
    values = [str(item) for item in selectors if isinstance(item, str) and item.strip()]
    return any(fnmatch.fnmatch(name, selector) for selector in values)


def _configured_action(value: Any, default: str = "allow") -> str:
    action = str(value or default).lower()
    return action if action in ACTION_PRIORITY else default


def _combine(current: dict[str, Any] | None, candidate: dict[str, Any] | None) -> dict[str, Any] | None:
    if candidate is None:
        return current
    if current is None:
        return candidate
    if ACTION_PRIORITY[candidate["decision"]] > ACTION_PRIORITY[current["decision"]]:
        return candidate
    return current


def assess_mcp_server(root: pathlib.Path, profile: str, server_id: str, spec: dict[str, Any] | None = None, context: dict[str, Any] | None = None) -> dict[str, Any]:
    config = load_client_config(root)
    if not config.get("enabled"):
        return {"hit": None, "policy_status": {"enabled": False, "ok": True}}
    policy, status = load_policy(root, config)
    status_hit = _status_hit(status, policy)
    if status_hit:
        return {"hit": status_hit, "policy_status": status}
    mcp = policy.get("mcp") if isinstance(policy.get("mcp"), dict) else {}
    default = _configured_action(mcp.get("default"), "allow")
    blocked = set(str(item) for item in mcp.get("deny_servers", []) if isinstance(item, str))
    allowed = set(str(item) for item in mcp.get("allow_servers", []) if isinstance(item, str))
    servers = mcp.get("servers") if isinstance(mcp.get("servers"), dict) else {}
    server_policy = servers.get(server_id) if isinstance(servers.get(server_id), dict) else {}
    action = _configured_action(server_policy.get("action"), default)
    if server_id in blocked:
        action = "block"
    if allowed and server_id not in allowed:
        action = "block"
    if action == "allow":
        return {"hit": None, "policy_status": status}
    return {
        "hit": _hit(
            "stallion-mcp-server-policy",
            action,
            f"{action.title()} MCP server {server_id} by Stallion policy.",
            reason=f"Stallion policy does not allow MCP server {server_id}.",
            policy=policy,
            evidence=[{"server_id": server_id, "config": spec or {}}],
        ),
        "policy_status": status,
    }


def assess_mcp_tool(
    root: pathlib.Path,
    profile: str,
    server_id: str,
    tool_name: str,
    arguments: dict[str, Any] | None = None,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    server_assessment = assess_mcp_server(root, profile, server_id, None, context)
    hit = server_assessment.get("hit")
    if hit:
        return {"hit": hit, "policy_status": server_assessment.get("policy_status")}
    config = load_client_config(root)
    if not config.get("enabled"):
        return {"hit": None, "policy_status": {"enabled": False, "ok": True}}
    policy, status = load_policy(root, config)
    if not status.get("ok", True):
        return {"hit": _status_hit(status, policy), "policy_status": status}
    mcp = policy.get("mcp") if isinstance(policy.get("mcp"), dict) else {}
    servers = mcp.get("servers") if isinstance(mcp.get("servers"), dict) else {}
    server_policy = servers.get(server_id) if isinstance(servers.get(server_id), dict) else {}
    tools = server_policy.get("tools") if isinstance(server_policy.get("tools"), dict) else {}
    full_name = f"{server_id}__{tool_name}"
    action = _configured_action(tools.get("default"), "allow")
    allowed = tools.get("allow", [])
    if allowed:
        action = "allow" if (_selectors_match(tool_name, allowed) or _selectors_match(full_name, allowed)) else "block"
    if _selectors_match(tool_name, tools.get("deny", [])) or _selectors_match(full_name, tools.get("deny", [])):
        action = "block"
    if _selectors_match(tool_name, tools.get("prompt", [])) or _selectors_match(full_name, tools.get("prompt", [])):
        action = "prompt"
    if action == "allow":
        return {"hit": None, "policy_status": status}
    return {
        "hit": _hit(
            "stallion-mcp-tool-policy",
            action,
            f"{action.title()} MCP tool {full_name} by Stallion policy.",
            reason=f"Stallion policy does not allow MCP tool {full_name}.",
            policy=policy,
            evidence=[{"server_id": server_id, "tool_name": tool_name, "arguments": arguments or {}}],
        ),
        "policy_status": status,
    }


def _shell_tokens(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=os.name != "nt")
    except ValueError:
        return [token for token in command.strip().split() if token]


def _command_names(command: str) -> set[str]:
    tokens = _shell_tokens(command)
    names: set[str] = set()
    separators = {";", "&&", "||", "|"}
    next_is_command = True
    for token in tokens:
        if token in separators:
            next_is_command = True
            continue
        if next_is_command and "=" not in token:
            names.add(pathlib.Path(token).name)
            next_is_command = False
    if tokens:
        names.add(pathlib.Path(tokens[0]).name)
    return names


def _route_matches(route: dict[str, Any], payload: str) -> bool:
    commands = set(str(item) for item in route.get("block_commands", []) if isinstance(item, str))
    names = _command_names(payload)
    url_patterns = [str(item) for item in route.get("url_patterns", []) if isinstance(item, str)]
    command_patterns = [str(item) for item in route.get("command_patterns", []) if isinstance(item, str)]
    if commands and commands.intersection(names):
        return True
    if url_patterns and any(pattern in payload for pattern in url_patterns):
        return True
    for pattern in command_patterns:
        try:
            if re.search(pattern, payload):
                return True
        except re.error:
            return False
    return False


def _assess_required_routes(policy: dict[str, Any], payload: str) -> dict[str, Any] | None:
    for route in policy.get("required_routes", []) or []:
        if not isinstance(route, dict) or not _route_matches(route, payload):
            continue
        capability = str(route.get("capability") or "managed capability")
        required = route.get("required_route") if isinstance(route.get("required_route"), dict) else {}
        server = required.get("server") or route.get("mcp_server") or "approved MCP"
        return _hit(
            "stallion-required-route-policy",
            _configured_action(route.get("action"), "block"),
            f"Blocked direct CLI/API access to {capability}; use the approved MCP route.",
            reason=f"Stallion requires {capability} to go through MCP server {server}.",
            policy=policy,
            evidence=[{"capability": capability, "required_route": required, "command_preview": payload[:240]}],
        )
    return None


def _assess_named_surface(policy: dict[str, Any], payload: str, surface: str, pattern: re.Pattern[str]) -> dict[str, Any] | None:
    settings = policy.get(surface) if isinstance(policy.get(surface), dict) else {}
    default = _configured_action(settings.get("default"), "allow")
    allow = [str(item) for item in settings.get("allow", []) if isinstance(item, str)]
    deny = [str(item) for item in settings.get("deny", []) if isinstance(item, str)]
    for match in pattern.finditer(payload):
        target = match.group(1).strip().strip("\"'")
        if _selectors_match(target, deny):
            action = "block"
        elif allow:
            action = "allow" if _selectors_match(target, allow) else "block"
        else:
            action = default
        if action == "allow":
            continue
        module = f"stallion-{surface[:-1] if surface.endswith('s') else surface}-policy"
        return _hit(
            module,
            action,
            f"{action.title()} {surface[:-1] if surface.endswith('s') else surface} {target} by Stallion policy.",
            reason=f"Stallion policy does not allow {surface[:-1] if surface.endswith('s') else surface} {target}.",
            policy=policy,
            evidence=[{"surface": surface, "target": target, "command_preview": payload[:240]}],
        )
    return None


def _assess_config_bypass(policy: dict[str, Any], matcher: str, payload: str) -> dict[str, Any] | None:
    if matcher not in {"Write", "Edit", "MultiEdit"}:
        return None
    if not re.search(r"(?i)(mcpServers|mcp_servers|\.mcp\.json|mcp\.json|mcp_config\.json|claude_desktop_config\.json)", payload):
        return None
    if re.search(r"stallion_gateway|stallion-gateway|stallion_mcp_server|bin/stallion|scripts/stallion_gateway\.py", payload):
        return None
    mcp = policy.get("mcp") if isinstance(policy.get("mcp"), dict) else {}
    if not bool(mcp.get("require_gateway", True)):
        return None
    return _hit(
        "stallion-direct-mcp-config-policy",
        "block",
        "Blocked direct MCP server configuration that bypasses the Stallion client gateway.",
        reason="Managed Stallion clients must expose upstream MCP servers through the Stallion/Stallion gateway.",
        policy=policy,
        evidence=[{"matcher": matcher, "payload_preview": payload[:240]}],
    )


def assess_action(root: pathlib.Path, event: str, matcher: str, payload: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
    config = load_client_config(root)
    if not config.get("enabled"):
        return {"identity": None, "hit": None, "policy_status": {"enabled": False, "ok": True}}
    policy, status = load_policy(root, config)
    status_hit = _status_hit(status, policy)
    if status_hit:
        return {"identity": {"surface": "stallion-policy", "policy_status": status}, "hit": status_hit, "policy_status": status}
    hit: dict[str, Any] | None = None
    if event == "PreToolUse" and matcher.startswith("mcp__"):
        rest = matcher[len("mcp__") :]
        if "__" in rest:
            server_id, tool_name = rest.split("__", 1)
        else:
            server_id, tool_name = rest, ""
        hit = _combine(hit, assess_mcp_tool(root, str(context.get("profile") if context else ""), server_id, tool_name, {}, context).get("hit"))
    if event == "PreToolUse" and matcher == "Bash":
        hit = _combine(hit, _assess_required_routes(policy, payload))
        hit = _combine(hit, _assess_named_surface(policy, payload, "plugins", PLUGIN_COMMAND_RE))
        hit = _combine(hit, _assess_named_surface(policy, payload, "skills", SKILL_COMMAND_RE))
    if event == "PreToolUse":
        hit = _combine(hit, _assess_config_bypass(policy, matcher, payload))
    return {
        "identity": {"surface": "stallion-client", "policy_id": policy.get("policy_id")},
        "hit": hit,
        "policy_status": status,
    }


def _masked_event(event: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    capture = config.get("capture") if isinstance(config.get("capture"), dict) else {}
    if capture.get("tool_payloads", True):
        return event
    masked = dict(event)
    for key in ("tool_input", "raw_payload", "request_preview", "response_preview"):
        if key in masked:
            masked[key] = "[stallion-redacted]"
    return masked


def record_event(root: pathlib.Path, event: dict[str, Any]) -> None:
    config = load_client_config(root)
    if not config.get("enabled"):
        return
    capture = config.get("capture") if isinstance(config.get("capture"), dict) else {}
    if event.get("event_type") == "PromptObserved" and not capture.get("prompts", True):
        return
    if event.get("event_type") != "PromptObserved" and not capture.get("audit_events", True):
        return
    queued = _masked_event({**event, "queued_at": utc_now()}, config)
    path = event_queue_path(root, config)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(queued, separators=(",", ":")) + "\n")
    if config.get("upload_enabled") and config.get("server_url"):
        flush_events(root, limit=25)


def _event_upload_url(config: dict[str, Any]) -> str:
    base = str(config.get("server_url") or "").rstrip("/")
    path = str(config.get("upload_path") or "/api/client/events")
    if not path.startswith("/"):
        path = "/" + path
    return base + path


def flush_events(root: pathlib.Path, limit: int = 100) -> tuple[int, str]:
    config = load_client_config(root)
    path = event_queue_path(root, config)
    if not path.exists() or not config.get("server_url"):
        return 0, "nothing to flush"
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    selected = lines[:limit]
    if not selected:
        return 0, "nothing to flush"
    payload = {"events": [json.loads(line) for line in selected]}
    request = urllib.request.Request(
        _event_upload_url(config),
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    token = os.environ.get("STALLION_STALLION_TOKEN")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            if response.status >= 300:
                return 0, f"upload failed: HTTP {response.status}"
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return 0, f"upload failed: {exc}"
    remaining = lines[len(selected) :]
    path.write_text(("\n".join(remaining) + "\n") if remaining else "", encoding="utf-8")
    return len(selected), "flushed"


def record_prompt(root: pathlib.Path, args: argparse.Namespace) -> int:
    event = {
        "event_type": "PromptObserved",
        "ts": utc_now(),
        "runtime": args.runtime,
        "agent_id": args.agent_id,
        "subagent_id": args.subagent_id,
        "session_id": args.session_id,
        "prompt_role": args.role,
        "prompt": args.prompt,
    }
    record_event(root, event)
    print("recorded")
    return 0


def print_status(root: pathlib.Path, as_json: bool = False) -> int:
    config = load_client_config(root)
    policy, status = load_policy(root, config)
    payload = {
        "enabled": bool(config.get("enabled")),
        "policy_file": str(policy_file_path(root, config)),
        "event_queue_file": str(event_queue_path(root, config)),
        "policy_status": status,
        "policy_id": policy.get("policy_id"),
        "server_url_configured": bool(config.get("server_url")),
    }
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"enabled: {'yes' if payload['enabled'] else 'no'}")
        print(f"policy: {payload['policy_id'] or '-'}")
        print(f"status: {status.get('reason', 'ok')}")
        print(f"queue: {payload['event_queue_file']}")
    return 0 if status.get("ok", True) else 2


def print_policy(root: pathlib.Path, as_json: bool = False) -> int:
    config = load_client_config(root)
    policy, status = load_policy(root, config)
    payload = {"policy": policy, "status": status}
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if status.get("ok", True) else 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Stallion managed client policy and telemetry")
    parser.add_argument("--root", default=pathlib.Path(__file__).resolve().parents[1])
    subparsers = parser.add_subparsers(dest="command", required=True)

    status_parser = subparsers.add_parser("status", help="Show Stallion client status")
    status_parser.add_argument("--json", action="store_true")

    policy_parser = subparsers.add_parser("policy", help="Show loaded Stallion policy")
    policy_parser.add_argument("--json", action="store_true")

    flush_parser = subparsers.add_parser("flush", help="Upload queued Stallion events")
    flush_parser.add_argument("--limit", type=int, default=100)

    prompt_parser = subparsers.add_parser("record-prompt", help="Record an observed prompt when a runtime exposes it")
    prompt_parser.add_argument("--runtime", default="")
    prompt_parser.add_argument("--agent-id", default="")
    prompt_parser.add_argument("--subagent-id", default="")
    prompt_parser.add_argument("--session-id", default="")
    prompt_parser.add_argument("--role", default="user")
    prompt_parser.add_argument("prompt")

    args = parser.parse_args(argv)
    root = pathlib.Path(args.root).resolve()
    if args.command == "status":
        return print_status(root, as_json=args.json)
    if args.command == "policy":
        return print_policy(root, as_json=args.json)
    if args.command == "flush":
        count, message = flush_events(root, limit=args.limit)
        print(f"{message}: {count}")
        return 2 if message.startswith("upload failed") else 0
    if args.command == "record-prompt":
        return record_prompt(root, args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
