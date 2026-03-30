#!/usr/bin/env python3
import argparse
import copy
import hashlib
import json
import os
import pathlib
import queue
import re
import socketserver
import subprocess
import sys
import threading
import time
import uuid
from collections import deque
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

import runwall_policy
import runwall_forensics
import runwall_runtime


INTERNAL_TOOLS = [
    {
        "name": "preflight_bash",
        "description": "Evaluate a shell command against Runwall pre-tool policy.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {"type": "string"},
                "profile": {"type": "string"},
            },
            "required": ["command"],
        },
    },
    {
        "name": "preflight_read",
        "description": "Evaluate a file read against Runwall pre-tool policy.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "profile": {"type": "string"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "preflight_write",
        "description": "Evaluate a file write or edit against Runwall pre-tool policy.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "content": {"type": "string"},
                "profile": {"type": "string"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "inspect_output",
        "description": "Scan tool output for indirect prompt injection and other post-tool signals.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "tool_name": {"type": "string"},
                "content": {"type": "string"},
                "profile": {"type": "string"},
            },
            "required": ["tool_name", "content"],
        },
    },
]


def read_message(reader) -> dict[str, Any] | None:
    headers = {}
    while True:
        line = reader.readline()
        if not line:
            return None
        if line in (b"\r\n", b"\n"):
            break
        key, _, value = line.decode("utf-8").partition(":")
        headers[key.strip().lower()] = value.strip()
    length = int(headers.get("content-length", "0"))
    if length <= 0:
        return None
    body = reader.read(length)
    if not body:
        return None
    return json.loads(body.decode("utf-8"))


def write_message(writer, payload: dict[str, Any]) -> None:
    body = json.dumps(payload).encode("utf-8")
    writer.write(f"Content-Length: {len(body)}\r\n\r\n".encode("utf-8"))
    writer.write(body)
    writer.flush()


def tool_result(result: dict[str, Any], *, is_error: bool | None = None) -> dict[str, Any]:
    text = json.dumps(result, indent=2)
    if is_error is None:
        is_error = not result.get("allowed", True)
    return {
        "content": [{"type": "text", "text": text}],
        "structuredContent": result,
        "isError": is_error,
    }


def safe_json_dumps(payload: Any) -> str:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def sha256_json(payload: Any) -> str:
    digest = hashlib.sha256()
    digest.update(safe_json_dumps(payload).encode("utf-8"))
    return digest.hexdigest()


_MASK_PATTERNS = (
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ASIA[0-9A-Z]{16}"),
    re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*[A-Za-z0-9/+=]{20,}"),
    re.compile(r"(?i)(token|secret|password|api[_-]?key)\s*[:=]\s*[A-Za-z0-9._/+\\=-]{10,}"),
    re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----"),
)


def mask_text(text: str, *, limit: int = 240) -> str:
    masked = text
    for pattern in _MASK_PATTERNS:
        masked = pattern.sub("[runwall-masked]", masked)
    return masked[:limit]


def safe_preview(value: Any, *, limit: int = 240) -> str:
    if isinstance(value, str):
        return mask_text(value, limit=limit)
    return mask_text(safe_json_dumps(value), limit=limit)


def request_fingerprint(
    server_id: str,
    tool_name: str,
    arguments: dict[str, Any],
    profile: str,
    context: dict[str, Any] | None = None,
) -> str:
    digest = hashlib.sha256()
    digest.update(safe_json_dumps({
        "server_id": server_id,
        "tool_name": tool_name,
        "arguments": arguments,
        "profile": profile,
        "context": runwall_runtime.normalize_context(context),
    }).encode("utf-8"))
    return digest.hexdigest()


def response_fingerprint(request_id: str, result: dict[str, Any], context: dict[str, Any] | None = None) -> str:
    digest = hashlib.sha256()
    digest.update(
        safe_json_dumps(
            {
                "request": request_id,
                "result": result,
                "context": runwall_runtime.normalize_context(context),
            }
        ).encode("utf-8")
    )
    return digest.hexdigest()


def first_reason(result: dict[str, Any], fallback: str) -> str:
    for hit in result.get("hits", []):
        if hit.get("output"):
            return hit["output"].splitlines()[0]
    return fallback


def recursive_string_scrub(value: Any, replacement: str) -> Any:
    if isinstance(value, str):
        return replacement
    if isinstance(value, list):
        return [recursive_string_scrub(item, replacement) for item in value]
    if isinstance(value, dict):
        return {key: recursive_string_scrub(item, replacement) for key, item in value.items()}
    return value


def response_preview(result: dict[str, Any], limit: int = 240) -> str:
    for item in result.get("content", []):
        if isinstance(item, dict) and item.get("type") == "text" and item.get("text"):
            return safe_preview(item["text"], limit=limit)
    structured = result.get("structuredContent")
    if isinstance(structured, dict):
        return safe_preview(structured, limit=limit)
    return safe_preview(result, limit=limit)


def response_evidence(evaluation: dict[str, Any]) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for hit in evaluation.get("hits", []):
        metadata = hit.get("metadata") or {}
        if isinstance(metadata.get("evidence"), list):
            evidence.extend(item for item in metadata["evidence"] if isinstance(item, dict))
    return evidence[:5]


def first_artifact(evidence: list[dict[str, Any]]) -> str | None:
    for item in evidence:
        for key in ("path", "artifact", "url", "host", "tool", "target"):
            value = item.get(key)
            if isinstance(value, str) and value:
                return value
    return None


def event_confidence(decision: str, hits: list[dict[str, Any]]) -> float:
    explicit: list[float] = []
    for hit in hits:
        metadata = hit.get("metadata") or {}
        value = metadata.get("confidence")
        if isinstance(value, (int, float)):
            explicit.append(float(value))
    if explicit:
        return max(min(max(explicit), 1.0), 0.0)
    defaults = {
        "block": 0.98,
        "prompt": 0.84,
        "redact": 0.93,
        "warn": 0.72,
        "allow": 0.58,
        "info": 0.55,
    }
    return defaults.get(decision, 0.5)


def safer_alternative(event: dict[str, Any]) -> str:
    if event.get("decision") == "block" and event.get("direction") == "request":
        return "Review the request, narrow the tool input, or approve it from the local gateway if the action is expected."
    if event.get("decision") == "prompt":
        return "Use the pending prompt queue to approve only after verifying the tool, destination, and data being sent."
    if event.get("decision") == "redact":
        return "Re-run the task with narrower scope or fetch only the fields the agent actually needs."
    if event.get("direction") == "tools/list":
        return "Review the upstream server or tool diff and re-establish trust before exposing the changed tool to the runtime."
    return "Keep the current profile or reduce the action scope if the tool does not need broad access."


def summarize_hits(hits: list[dict[str, Any]]) -> list[str]:
    modules = []
    for hit in hits:
        module = hit.get("module")
        if isinstance(module, str) and module and module not in modules:
            modules.append(module)
    return modules


def normalize_server_metadata(server_id: str, spec: dict[str, Any], upstream: "UpstreamSession") -> dict[str, Any]:
    command = spec.get("command", "")
    return {
        "server_id": server_id,
        "serverInfo": upstream.server_info or {},
        "command": pathlib.Path(command).name if command else "",
        "args": spec.get("args", []),
        "cwd": spec.get("cwd") or "",
    }


def normalize_tool_metadata(server_id: str, tool: dict[str, Any]) -> dict[str, Any]:
    return {
        "server_id": server_id,
        "name": tool.get("name", ""),
        "description": tool.get("description", ""),
        "inputSchema": tool.get("inputSchema", {}),
        "annotations": tool.get("annotations", {}),
        "title": tool.get("title", ""),
    }


def schema_properties(schema: Any) -> set[str]:
    if not isinstance(schema, dict):
        return set()
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return set()
    return {str(key) for key in properties.keys()}


def description_keywords(text: str) -> set[str]:
    normalized = text.lower()
    keywords = {
        "shell",
        "command",
        "write",
        "edit",
        "delete",
        "network",
        "upload",
        "download",
        "fetch",
        "token",
        "secret",
        "key",
        "http",
        "https",
    }
    return {word for word in keywords if word in normalized}


def diff_server_metadata(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any] | None:
    changes: list[dict[str, Any]] = []
    previous_info = previous.get("serverInfo") or {}
    current_info = current.get("serverInfo") or {}
    for key in ("name", "version"):
        if previous_info.get(key) != current_info.get(key):
            changes.append(
                {
                    "field": f"serverInfo.{key}",
                    "before": previous_info.get(key),
                    "after": current_info.get(key),
                    "summary": f"Server {key} changed.",
                }
            )
    for key in ("command", "args", "cwd"):
        if previous.get(key) != current.get(key):
            changes.append(
                {
                    "field": key,
                    "before": previous.get(key),
                    "after": current.get(key),
                    "summary": f"Server {key} changed.",
                }
            )
    if not changes:
        return None
    return {
        "kind": "server",
        "entity": current.get("server_id"),
        "summary": "Trusted MCP server metadata drifted from the stored baseline.",
        "changes": changes,
    }


def diff_tool_metadata(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any] | None:
    changes: list[dict[str, Any]] = []
    previous_schema = previous.get("inputSchema") or {}
    current_schema = current.get("inputSchema") or {}
    if previous.get("description") != current.get("description"):
        changes.append(
            {
                "field": "description",
                "before": previous.get("description"),
                "after": current.get("description"),
                "summary": "Tool description changed.",
            }
        )
    if previous_schema != current_schema:
        changes.append(
            {
                "field": "inputSchema",
                "before": previous_schema,
                "after": current_schema,
                "summary": "Tool input schema changed.",
            }
        )
    previous_properties = schema_properties(previous_schema)
    current_properties = schema_properties(current_schema)
    added_properties = sorted(current_properties - previous_properties)
    if added_properties:
        changes.append(
            {
                "field": "capability-expansion",
                "before": sorted(previous_properties),
                "after": sorted(current_properties),
                "summary": f"Tool schema added new inputs: {', '.join(added_properties)}.",
            }
        )
    if not bool(previous_schema.get("additionalProperties")) and bool(current_schema.get("additionalProperties")):
        changes.append(
            {
                "field": "additionalProperties",
                "before": previous_schema.get("additionalProperties"),
                "after": current_schema.get("additionalProperties"),
                "summary": "Tool schema widened to accept free-form additional properties.",
            }
        )
    previous_keywords = description_keywords(str(previous.get("description", "")))
    current_keywords = description_keywords(str(current.get("description", "")))
    added_keywords = sorted(current_keywords - previous_keywords)
    if added_keywords:
        changes.append(
            {
                "field": "description-keywords",
                "before": sorted(previous_keywords),
                "after": sorted(current_keywords),
                "summary": f"Tool description now advertises higher-risk capabilities: {', '.join(added_keywords)}.",
            }
        )
    if not changes:
        return None
    return {
        "kind": "tool",
        "entity": f"{current.get('server_id')}::{current.get('name')}",
        "summary": "Trusted MCP tool metadata drifted from the stored baseline.",
        "changes": changes,
    }


def secret_redaction_fallback(result: dict[str, Any]) -> dict[str, Any] | None:
    payload = safe_json_dumps(result)
    obvious_markers = (
        "AWS_SECRET_ACCESS_KEY",
        "ghp_",
        "github_pat_",
        "PRIVATE KEY",
    )
    if not any(marker in payload for marker in obvious_markers):
        return None
    return {
        "allowed": True,
        "action": "redact",
        "hits": [
            {
                "module": "mcp-response-secret-leak-guard",
                "name": "MCP Response Secret Leak Guard Pack",
                "category": "mcp",
                "decision": "redact",
                "exit_code": 0,
                "output": "[runwall] redacting secret-like MCP response content",
                "metadata": {
                    "reason": "The upstream response contains secret-like material and should be redacted before it reaches the client.",
                    "redactions": [{"type": "full-response", "label": "secret-material"}],
                },
            }
        ],
    }


def load_gateway_config(path: pathlib.Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return {"servers": {}}
    payload = json.loads(path.read_text())
    if not isinstance(payload, dict):
        raise SystemExit(f"invalid gateway config: {path}")
    payload.setdefault("servers", {})
    return payload


def identity_policy_path(root: pathlib.Path) -> pathlib.Path:
    return root / "config" / "tool-identity-policy.json"


def load_identity_policy(root: pathlib.Path) -> dict[str, dict[str, str]]:
    defaults = {
        "balanced": {
            "server_drift": "prompt",
            "tool_drift": "prompt",
            "same_name_collision": "prompt",
        },
        "strict": {
            "server_drift": "block",
            "tool_drift": "block",
            "same_name_collision": "block",
        },
        "minimal": {
            "server_drift": "warn",
            "tool_drift": "warn",
            "same_name_collision": "warn",
        },
    }
    path = identity_policy_path(root)
    if not path.exists():
        return defaults
    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError:
        return defaults
    if not isinstance(payload, dict):
        return defaults
    for profile, values in defaults.items():
        current = payload.get(profile)
        if not isinstance(current, dict):
            payload[profile] = dict(values)
            continue
        for key, value in values.items():
            current.setdefault(key, value)
    return payload


def fingerprint_store_path(root: pathlib.Path) -> pathlib.Path:
    override = os.environ.get("RUNWALL_GATEWAY_FINGERPRINT_FILE")
    if override:
        return pathlib.Path(override)
    return root / "state" / "gateway-fingerprints.json"


class FingerprintStore:
    def __init__(self, path: pathlib.Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._payload = self._load()

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"servers": {}, "tools": {}}
        try:
            payload = json.loads(self.path.read_text())
        except json.JSONDecodeError:
            return {"servers": {}, "tools": {}}
        if not isinstance(payload, dict):
            return {"servers": {}, "tools": {}}
        payload.setdefault("servers", {})
        payload.setdefault("tools", {})
        return payload

    def _save(self) -> None:
        self.path.write_text(json.dumps(self._payload, indent=2) + "\n")

    def get_server(self, server_id: str) -> dict[str, Any] | None:
        with self._lock:
            value = self._payload.get("servers", {}).get(server_id)
            return copy.deepcopy(value) if isinstance(value, dict) else None

    def set_server(self, server_id: str, metadata: dict[str, Any]) -> None:
        with self._lock:
            self._payload.setdefault("servers", {})[server_id] = copy.deepcopy(metadata)
            self._save()

    def get_tool(self, server_id: str, tool_name: str) -> dict[str, Any] | None:
        key = f"{server_id}::{tool_name}"
        with self._lock:
            value = self._payload.get("tools", {}).get(key)
            return copy.deepcopy(value) if isinstance(value, dict) else None

    def set_tool(self, server_id: str, tool_name: str, metadata: dict[str, Any]) -> None:
        key = f"{server_id}::{tool_name}"
        with self._lock:
            self._payload.setdefault("tools", {})[key] = copy.deepcopy(metadata)
            self._save()


class EventStore:
    def __init__(self) -> None:
        self._events = deque(maxlen=1000)
        self._pending: dict[str, dict[str, Any]] = {}
        self._approvals: dict[str, dict[str, Any]] = {}
        self._subscribers: list[queue.Queue] = []
        self._lock = threading.Lock()

    def add_event(self, event: dict[str, Any]) -> None:
        with self._lock:
            self._events.append(event)
            subscribers = list(self._subscribers)
        for subscriber in subscribers:
            subscriber.put(event)

    def list_events(self, query: dict[str, list[str]]) -> list[dict[str, Any]]:
        with self._lock:
            events = list(self._events)
        runtime = (query.get("runtime") or [""])[0]
        server_id = (query.get("server_id") or [""])[0]
        tool_name = (query.get("tool_name") or [""])[0]
        decision = (query.get("decision") or [""])[0]
        direction = (query.get("direction") or [""])[0]
        module = (query.get("module") or [""])[0]
        session_id = (query.get("session_id") or [""])[0]
        agent_id = (query.get("agent_id") or [""])[0]
        subagent_id = (query.get("subagent_id") or [""])[0]
        chain_id = (query.get("chain_id") or [""])[0]
        if runtime:
            events = [event for event in events if event.get("runtime") == runtime]
        if server_id:
            events = [event for event in events if event.get("server_id") == server_id]
        if tool_name:
            events = [event for event in events if event.get("tool_name") == tool_name]
        if decision:
            events = [event for event in events if event.get("decision") == decision]
        if direction:
            events = [event for event in events if event.get("direction") == direction]
        if module:
            events = [event for event in events if event.get("module") == module]
        if session_id:
            events = [event for event in events if event.get("session_id") == session_id]
        if agent_id:
            events = [event for event in events if event.get("agent_id") == agent_id]
        if subagent_id:
            events = [event for event in events if event.get("subagent_id") == subagent_id]
        if chain_id:
            events = [
                event
                for event in events
                if event.get("chain_id") == chain_id
                or any(alert.get("chain_id") == chain_id for alert in event.get("chain_alerts", []))
            ]
        return events

    def subscribe(self) -> queue.Queue:
        subscriber: queue.Queue = queue.Queue()
        with self._lock:
            self._subscribers.append(subscriber)
        return subscriber

    def unsubscribe(self, subscriber: queue.Queue) -> None:
        with self._lock:
            if subscriber in self._subscribers:
                self._subscribers.remove(subscriber)

    def create_prompt(self, payload: dict[str, Any]) -> dict[str, Any]:
        fingerprint = payload.get("fingerprint")
        if isinstance(fingerprint, str):
            with self._lock:
                for prompt in self._pending.values():
                    if prompt.get("fingerprint") == fingerprint:
                        return dict(prompt)
        prompt_id = uuid.uuid4().hex
        prompt = {"id": prompt_id, "status": "pending", **payload}
        with self._lock:
            self._pending[prompt_id] = prompt
        return prompt

    def list_pending(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._pending.values())

    def resolve_prompt(self, prompt_id: str, approved: bool) -> dict[str, Any] | None:
        with self._lock:
            prompt = self._pending.get(prompt_id)
            if prompt is None:
                return None
            prompt = dict(prompt)
            prompt["status"] = "approved" if approved else "denied"
            prompt["resolved_at"] = time.time()
            self._pending.pop(prompt_id, None)
            self._approvals[prompt["fingerprint"]] = prompt
            return prompt

    def approved(self, fingerprint: str) -> bool:
        with self._lock:
            record = self._approvals.get(fingerprint)
            return bool(record and record.get("status") == "approved")

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        with self._lock:
            for event in reversed(self._events):
                if event.get("event_id") == event_id:
                    return dict(event)
        return None

    def build_incident_bundle(self, event_id: str) -> dict[str, Any] | None:
        event = self.get_event(event_id)
        if event is None:
            return None
        related = []
        chain_id = event.get("chain_id")
        prompt_id = event.get("prompt_id")
        with self._lock:
            for candidate in self._events:
                if candidate.get("event_id") == event_id:
                    continue
                if prompt_id and candidate.get("prompt_id") == prompt_id:
                    related.append(dict(candidate))
                    continue
                if chain_id and candidate.get("chain_id") == chain_id:
                    related.append(dict(candidate))
                    continue
        return {
            "schema": "runwall-incident-bundle/v1",
            "exported_at": time.time(),
            "event": event,
            "related_events": related[:25],
            "summary": {
                "decision": event.get("decision"),
                "reason": event.get("reason"),
                "module": event.get("module"),
                "runtime": event.get("runtime"),
                "signature_modules": event.get("signature_modules", []),
                "artifact_touched": event.get("artifact_touched"),
                "safer_alternative": event.get("safer_alternative"),
            },
        }


class UpstreamSession:
    def __init__(self, server_id: str, spec: dict[str, Any]):
        self.server_id = server_id
        self.spec = spec
        self.proc: subprocess.Popen | None = None
        self.initialized = False
        self._request_id = 0
        self._lock = threading.Lock()
        self.initialize_result: dict[str, Any] = {}
        self.server_info: dict[str, Any] = {}

    def start(self) -> None:
        if self.proc is not None:
            return
        env = None
        if isinstance(self.spec.get("env"), dict):
            env = {**os.environ, **self.spec["env"]}
        cwd = self.spec.get("cwd")
        self.proc = subprocess.Popen(
            [self.spec["command"], *self.spec.get("args", [])],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env=env,
        )

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self.start()
        assert self.proc is not None
        assert self.proc.stdin is not None
        assert self.proc.stdout is not None
        with self._lock:
            self._request_id += 1
            request_id = self._request_id
            payload = {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": method,
                "params": params or {},
            }
            write_message(self.proc.stdin, payload)
            while True:
                message = read_message(self.proc.stdout)
                if message is None:
                    stderr = ""
                    if self.proc.stderr is not None:
                        stderr = self.proc.stderr.read().decode("utf-8", errors="ignore")
                    raise RuntimeError(
                        f"upstream {self.server_id} closed during {method}: {stderr.strip()}"
                    )
                if message.get("id") == request_id:
                    return message

    def initialize(self) -> None:
        if self.initialized:
            return
        response = self.request("initialize", {})
        self.initialize_result = response.get("result", {}) if isinstance(response.get("result"), dict) else {}
        server_info = self.initialize_result.get("serverInfo")
        self.server_info = server_info if isinstance(server_info, dict) else {}
        assert self.proc is not None and self.proc.stdin is not None
        write_message(
            self.proc.stdin,
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        )
        self.initialized = True

    def list_tools(self) -> list[dict[str, Any]]:
        self.initialize()
        response = self.request("tools/list", {})
        return response.get("result", {}).get("tools", [])

    def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self.initialize()
        response = self.request("tools/call", {"name": tool_name, "arguments": arguments})
        if "error" in response:
            raise RuntimeError(response["error"].get("message", "unknown upstream error"))
        return response["result"]

    def close(self) -> None:
        if self.proc is None:
            return
        self.proc.terminate()
        try:
            self.proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.proc = None


class Gateway:
    def __init__(
        self,
        root: pathlib.Path,
        profile: str,
        config_path: pathlib.Path | None,
        api_port: int,
    ) -> None:
        self.root = root
        self.profile = profile
        self.config_path = config_path
        self.api_port = api_port
        self.event_store = EventStore()
        self.registry = load_gateway_config(config_path)
        self.identity_policy = load_identity_policy(root)
        self.fingerprint_store = FingerprintStore(fingerprint_store_path(root))
        self.upstreams: dict[str, UpstreamSession] = {}
        self.asset_root = root / "web" / "gateway"
        self.httpd: ThreadingHTTPServer | None = None

    def audit_gateway_event(self, event: dict[str, Any]) -> None:
        audited = runwall_policy.write_audit_event(
            self.root,
            module=event.get("module", "runwall-gateway"),
            decision=event.get("decision", "info"),
            reason=event.get("reason", ""),
            tool_input=event.get("tool_input", ""),
            profile=self.profile,
            extra={
                key: value
                for key, value in event.items()
                if key not in {"module", "decision", "reason", "tool_input"}
            },
            context={
                field: event.get(field)
                for field in runwall_runtime.CONTEXT_FIELDS
                if event.get(field) is not None
            },
        )
        hits = audited.get("hits") or []
        evidence = audited.get("evidence")
        if not isinstance(evidence, list):
            evidence = response_evidence({"hits": hits})
        request_preview = audited.get("request_preview")
        if not request_preview and audited.get("tool_input"):
            request_preview = safe_preview(audited.get("tool_input"))
        response_hint = audited.get("response_preview")
        enriched = {
            **audited,
            "request_preview": request_preview,
            "response_preview": response_hint or None,
            "signature_modules": summarize_hits(hits),
            "confidence": event_confidence(str(audited.get("decision", "info")), hits),
            "artifact_touched": audited.get("artifact_touched") or first_artifact(evidence),
            "safer_alternative": audited.get("safer_alternative") or safer_alternative(audited),
            "call_chain_ref": audited.get("chain_id")
            or next(
                (alert.get("chain_id") for alert in audited.get("chain_alerts", []) if alert.get("chain_id")),
                None,
            ),
            "evidence": evidence,
        }
        self.event_store.add_event(enriched)

    def approval_url(self, prompt_id: str) -> str:
        return f"http://127.0.0.1:{self.api_port}/#prompt={prompt_id}"

    def start_http_server(self) -> None:
        gateway = self

        class Handler(BaseHTTPRequestHandler):
            def _read_json_body(self) -> dict[str, Any]:
                length = int(self.headers.get("Content-Length", "0") or "0")
                if length <= 0:
                    return {}
                body = self.rfile.read(length)
                if not body:
                    return {}
                payload = json.loads(body.decode("utf-8"))
                return payload if isinstance(payload, dict) else {}

            def _json(self, payload: Any, status: int = 200) -> None:
                body = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _serve_asset(self, asset_name: str, content_type: str) -> None:
                asset_path = gateway.asset_root / asset_name
                if not asset_path.exists():
                    self.send_error(HTTPStatus.NOT_FOUND)
                    return
                body = asset_path.read_bytes()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:  # noqa: N802
                parsed = urlparse(self.path)
                if parsed.path == "/":
                    return self._serve_asset("index.html", "text/html; charset=utf-8")
                if parsed.path == "/app.js":
                    return self._serve_asset("app.js", "application/javascript; charset=utf-8")
                if parsed.path == "/styles.css":
                    return self._serve_asset("styles.css", "text/css; charset=utf-8")
                if parsed.path == "/health":
                    return self._json(
                        {
                            "ok": True,
                            "profile": gateway.profile,
                            "servers": sorted(gateway.registry.get("servers", {}).keys()),
                        }
                    )
                if parsed.path == "/api/events":
                    return self._json({"events": runwall_forensics.query_events(gateway.root, parse_qs(parsed.query))})
                if parsed.path.startswith("/api/events/") and parsed.path != "/api/events/stream":
                    event_id = parsed.path.rsplit("/", 1)[-1]
                    event = runwall_forensics.get_event(gateway.root, event_id)
                    if event is None:
                        self.send_error(HTTPStatus.NOT_FOUND)
                        return
                    return self._json(event)
                if parsed.path.startswith("/api/drift/"):
                    drift_id = parsed.path.rsplit("/", 1)[-1]
                    drift = runwall_forensics.get_drift(gateway.root, drift_id)
                    if drift is None:
                        self.send_error(HTTPStatus.NOT_FOUND)
                        return
                    return self._json(drift)
                if parsed.path == "/api/pending-prompts":
                    return self._json({"pending": gateway.event_store.list_pending()})
                if parsed.path.startswith("/api/incidents/"):
                    event_id = parsed.path.rsplit("/", 1)[-1]
                    bundle = gateway.event_store.build_incident_bundle(event_id)
                    if bundle is None:
                        self.send_error(HTTPStatus.NOT_FOUND)
                        return
                    return self._json(bundle)
                if parsed.path == "/api/events/stream":
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Cache-Control", "no-cache")
                    self.send_header("Connection", "keep-alive")
                    self.end_headers()
                    subscriber = gateway.event_store.subscribe()
                    try:
                        for event in runwall_forensics.query_events(gateway.root, {})[-50:]:
                            self.wfile.write(
                                f"data: {json.dumps(event, separators=(',', ':'))}\n\n".encode("utf-8")
                            )
                        self.wfile.flush()
                        while True:
                            event = subscriber.get(timeout=15)
                            self.wfile.write(
                                f"data: {json.dumps(event, separators=(',', ':'))}\n\n".encode("utf-8")
                            )
                            self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError, queue.Empty):
                        pass
                    finally:
                        gateway.event_store.unsubscribe(subscriber)
                    return
                self.send_error(HTTPStatus.NOT_FOUND)

            def do_POST(self) -> None:  # noqa: N802
                parsed = urlparse(self.path)
                if parsed.path == "/api/incidents/export":
                    payload = self._read_json_body()
                    selector = str(payload.get("selector") or "").strip()
                    if not selector:
                        self.send_error(HTTPStatus.BAD_REQUEST, "selector is required")
                        return
                    format_name = str(payload.get("format") or "zip")
                    if format_name not in {"zip", "json"}:
                        self.send_error(HTTPStatus.BAD_REQUEST, "invalid format")
                        return
                    output = runwall_forensics.export_incident(gateway.root, selector, format_name=format_name)
                    response: dict[str, Any] = {
                        "ok": True,
                        "selector": selector,
                        "format": format_name,
                        "path": str(output),
                    }
                    if format_name == "json":
                        response["bundle"] = json.loads(output.read_text(encoding="utf-8"))
                    return self._json(response)
                if not parsed.path.startswith("/api/pending-prompts/"):
                    self.send_error(HTTPStatus.NOT_FOUND)
                    return
                prompt_id = parsed.path.rsplit("/", 2)[-2]
                action = parsed.path.rsplit("/", 1)[-1]
                if action not in {"approve", "deny"}:
                    self.send_error(HTTPStatus.NOT_FOUND)
                    return
                resolved = gateway.event_store.resolve_prompt(prompt_id, approved=action == "approve")
                if resolved is None:
                    self.send_error(HTTPStatus.NOT_FOUND)
                    return
                if resolved.get("entity_type") and resolved.get("entity_key") and resolved.get("snapshot_id"):
                    if action == "approve":
                        runwall_forensics.approve_drift(
                            gateway.root,
                            str(resolved["entity_type"]),
                            str(resolved["entity_key"]),
                            str(resolved["snapshot_id"]),
                            str(resolved["drift_id"]) if resolved.get("drift_id") else None,
                        )
                    else:
                        runwall_forensics.reject_drift(
                            gateway.root,
                            str(resolved["drift_id"]) if resolved.get("drift_id") else None,
                        )
                gateway.audit_gateway_event(
                    {
                        "module": "runwall-gateway",
                        "decision": "allow" if action == "approve" else "block",
                        "reason": f"Prompt {action}d by local reviewer",
                        "runtime": "gateway",
                        "server_id": resolved["server_id"],
                        "tool_name": resolved["tool_name"],
                        "direction": "prompt",
                        "prompt_id": prompt_id,
                        "prompt_type": resolved.get("prompt_type"),
                        "tool_input": safe_json_dumps(resolved["arguments"]),
                        "drift_id": resolved.get("drift_id"),
                        "drift_kind": resolved.get("drift_kind"),
                        "baseline_fingerprint": resolved.get("baseline_fingerprint"),
                        "current_fingerprint": resolved.get("current_fingerprint"),
                        "request_preview": resolved.get("response_hint"),
                        **{
                            field: resolved.get(field)
                            for field in runwall_runtime.CONTEXT_FIELDS
                            if resolved.get(field) is not None
                        },
                    }
                )
                self._json({"prompt": resolved})

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
                return

        self.httpd = ThreadingHTTPServer(("127.0.0.1", self.api_port), Handler)
        thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        thread.start()

    def registry_servers(self) -> dict[str, dict[str, Any]]:
        return self.registry.get("servers", {})

    def registry_allowed(self, server_id: str, spec: dict[str, Any]) -> bool:
        payload = safe_json_dumps({"server_id": server_id, "config": spec})
        result = runwall_policy.evaluate(self.root, self.profile, "PreToolUse", "GatewayRegistry", payload)
        if result["action"] == "block":
            self.audit_gateway_event(
                {
                    "module": "runwall-gateway",
                    "decision": "block",
                    "reason": first_reason(result, f"Blocked upstream server {server_id}"),
                    "runtime": "gateway",
                    "server_id": server_id,
                    "tool_name": "",
                    "direction": "registry",
                    "tool_input": payload,
                    "hits": result["hits"],
                }
            )
            return False
        return True

    def get_upstream(self, server_id: str) -> UpstreamSession:
        if server_id in self.upstreams:
            return self.upstreams[server_id]
        spec = self.registry_servers()[server_id]
        session = UpstreamSession(server_id, spec)
        self.upstreams[server_id] = session
        return session

    def identity_action(self, key: str) -> str:
        return str(self.identity_policy.get(self.profile, {}).get(key, "prompt"))

    def identity_event(
        self,
        *,
        decision: str,
        drift: dict[str, Any],
        server_id: str,
        tool_name: str,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        diff = drift.get("diff") or {}
        reason = diff.get("summary") or f"Detected {drift.get('drift_kind', 'metadata drift')}."
        return {
            "module": "runwall-gateway",
            "decision": decision if decision in {"prompt", "block"} else "warn",
            "reason": str(reason),
            "runtime": "gateway",
            "server_id": server_id,
            "tool_name": tool_name,
            "direction": "tools/list",
            "tool_input": safe_json_dumps(diff),
            "diff": diff,
            "artifact_touched": drift.get("entity_key"),
            "request_preview": safe_preview(diff),
            "confidence": drift.get("confidence", 0.94 if decision == "block" else 0.82),
            "drift_id": drift.get("drift_id"),
            "drift_kind": drift.get("drift_kind"),
            "baseline_fingerprint": drift.get("baseline_fingerprint"),
            "current_fingerprint": drift.get("current_fingerprint"),
            "baseline_snapshot_id": drift.get("baseline_snapshot_id"),
            "current_snapshot_id": drift.get("current_snapshot_id"),
            **{
                field: context.get(field)
                for field in runwall_runtime.CONTEXT_FIELDS
                if isinstance(context, dict) and context.get(field) is not None
            },
        }

    def handle_identity_assessment(
        self,
        *,
        assessment: dict[str, Any],
        server_id: str,
        tool_name: str,
        context: dict[str, Any] | None = None,
    ) -> bool:
        decision = str(assessment.get("action") or "allow")
        if decision == "allow":
            return True
        drift = assessment.get("drift")
        if not isinstance(drift, dict):
            return decision == "warn"
        event = self.identity_event(
            decision=decision,
            drift=drift,
            server_id=server_id,
            tool_name=tool_name,
            context=context,
        )
        if decision == "prompt":
            prompt_type = "baseline-review" if drift.get("drift_kind") == "first_sight" else "drift-review"
            fingerprint = f"drift:{drift['drift_id']}"
            prompt = self.event_store.create_prompt(
                {
                    "fingerprint": fingerprint,
                    "profile": self.profile,
                    "server_id": server_id,
                    "tool_name": tool_name,
                    "arguments": {"identity_diff": drift["diff"]},
                    "hits": [
                        {
                            "module": "runwall-gateway",
                            "name": "Runwall Gateway Identity Check",
                            "category": "mcp",
                            "decision": "prompt",
                            "exit_code": 0,
                            "output": event["reason"],
                            "metadata": {
                                "reason": event["reason"],
                                "confidence": drift.get("confidence", 0.82),
                                "evidence": [{"type": "drift", "drift_id": drift["drift_id"]}],
                            },
                        }
                    ],
                    "direction": "tools/list",
                    "prompt_type": prompt_type,
                    "response_hint": safe_preview(drift["diff"], limit=360),
                    "evidence": [{"artifact": drift.get("entity_key"), "type": drift.get("drift_kind")}],
                    "created_at": time.time(),
                    "entity_type": drift.get("entity_type"),
                    "entity_key": drift.get("entity_key"),
                    "snapshot_id": assessment.get("snapshot_id"),
                    "drift_id": drift.get("drift_id"),
                    "drift_kind": drift.get("drift_kind"),
                    "baseline_fingerprint": drift.get("baseline_fingerprint"),
                    "current_fingerprint": drift.get("current_fingerprint"),
                    **{
                        field: context.get(field)
                        for field in runwall_runtime.CONTEXT_FIELDS
                        if isinstance(context, dict) and context.get(field) is not None
                    },
                }
            )
            event["prompt_id"] = prompt["id"]
            event["prompt_type"] = prompt_type
        self.audit_gateway_event(event)
        return decision == "warn"

    def server_identity_allowed(self, server_id: str, spec: dict[str, Any], upstream: UpstreamSession) -> bool:
        assessment = runwall_forensics.assess_server(
            self.root,
            server_id,
            spec,
            upstream.server_info,
        )
        return self.handle_identity_assessment(
            assessment=assessment,
            server_id=server_id,
            tool_name="",
        )

    def tool_identity_allowed(self, server_id: str, tool: dict[str, Any]) -> bool:
        assessment = runwall_forensics.assess_tool(self.root, server_id, tool)
        return self.handle_identity_assessment(
            assessment=assessment,
            server_id=server_id,
            tool_name=str(tool.get("name", "")),
        )

    def evaluate_tool_definition(self, server_id: str, tool: dict[str, Any]) -> dict[str, Any]:
        payload = safe_json_dumps({"server_id": server_id, "tool": tool})
        return runwall_policy.evaluate(
            self.root,
            self.profile,
            "PreToolUse",
            f"mcp__{server_id}__{tool['name']}",
            payload,
        )

    def aggregated_tools(self) -> list[dict[str, Any]]:
        tools = copy.deepcopy(INTERNAL_TOOLS)
        collected: list[tuple[str, dict[str, Any]]] = []
        internal_names = {tool["name"] for tool in INTERNAL_TOOLS}
        for server_id, spec in sorted(self.registry_servers().items()):
            if not self.registry_allowed(server_id, spec):
                continue
            upstream = self.get_upstream(server_id)
            upstream_tools = upstream.list_tools()
            if not self.server_identity_allowed(server_id, spec, upstream):
                continue
            for tool in upstream_tools:
                if not self.tool_identity_allowed(server_id, tool):
                    continue
                evaluation = self.evaluate_tool_definition(server_id, tool)
                if evaluation["action"] == "block":
                    self.audit_gateway_event(
                        {
                            "module": "runwall-gateway",
                            "decision": "block",
                            "reason": first_reason(
                                evaluation, f"Suppressed risky tool {server_id}__{tool['name']}"
                            ),
                            "runtime": "gateway",
                            "server_id": server_id,
                            "tool_name": tool["name"],
                            "direction": "tools/list",
                            "tool_input": safe_json_dumps(tool),
                            "hits": evaluation["hits"],
                        }
                    )
                    continue
                raw_name = str(tool.get("name", ""))
                if raw_name in internal_names:
                    drift = runwall_forensics.build_collision(
                        self.root,
                        drift_kind="internal_name_collision",
                        decision="block",
                        server_id=server_id,
                        tool_name=raw_name,
                        owners=[server_id, "runwall-gateway"],
                    )
                    self.audit_gateway_event(
                        self.identity_event(
                            decision="block",
                            drift=drift,
                            server_id=server_id,
                            tool_name=raw_name,
                        )
                    )
                    continue
                collected.append((server_id, copy.deepcopy(tool)))

        collisions: dict[str, list[str]] = {}
        for server_id, tool in collected:
            collisions.setdefault(str(tool.get("name", "")), []).append(server_id)

        for server_id, tool in collected:
            raw_name = str(tool.get("name", ""))
            if len(collisions.get(raw_name, [])) > 1:
                drift = runwall_forensics.build_collision(
                    self.root,
                    drift_kind="same_name_collision",
                    decision="block",
                    server_id=server_id,
                    tool_name=raw_name,
                    owners=collisions[raw_name],
                )
                self.audit_gateway_event(
                    self.identity_event(
                        decision="block",
                        drift=drift,
                        server_id=server_id,
                        tool_name=raw_name,
                    )
                )
                continue
            exposed = copy.deepcopy(tool)
            exposed["name"] = f"{server_id}__{raw_name}"
            tools.append(exposed)
        return tools

    def handle_internal_tool(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        profile = args.get("profile") or self.profile
        context = args.get("_runwall_context") or {}
        if name == "preflight_bash":
            result = runwall_policy.evaluate(
                self.root,
                profile,
                "PreToolUse",
                "Bash",
                args["command"],
                context=context,
            )
        elif name == "preflight_read":
            result = runwall_policy.evaluate(
                self.root,
                profile,
                "PreToolUse",
                "Read",
                args["path"],
                context=context,
            )
        elif name == "preflight_write":
            payload = f"{args['target']} {args.get('content', '')}".strip()
            result = runwall_policy.evaluate(
                self.root,
                profile,
                "PreToolUse",
                "Write",
                payload,
                context=context,
            )
        elif name == "inspect_output":
            payload = safe_json_dumps(
                {
                    "tool_name": args["tool_name"],
                    "tool_input": {},
                    "tool_response": {"content": args["content"]},
                }
            )
            result = runwall_policy.evaluate(
                self.root,
                profile,
                "PostToolUse",
                args["tool_name"],
                payload,
                context=context,
            )
        else:
            raise KeyError(name)
        return tool_result(result)

    def redact_result(self, result: dict[str, Any], evaluation: dict[str, Any]) -> dict[str, Any]:
        redactions = [
            {
                "module": hit["module"],
                "reason": hit.get("output") or hit.get("decision"),
            }
            for hit in evaluation["hits"]
            if hit["decision"] == "redact"
        ]
        redacted = copy.deepcopy(result)
        replacement = "[runwall] sensitive or malicious upstream content was redacted"
        for item in redacted.get("content", []):
            if isinstance(item, dict) and item.get("type") == "text":
                item["text"] = replacement
        structured = redacted.get("structuredContent")
        if isinstance(structured, dict):
            preserved = recursive_string_scrub(structured, replacement)
            preserved["runwall_redacted"] = True
            preserved["runwall_redactions"] = redactions
            redacted["structuredContent"] = preserved
        else:
            redacted["structuredContent"] = {
                "runwall_redacted": True,
                "runwall_redactions": redactions,
            }
        return redacted

    def prompt_result(
        self,
        server_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        evaluation: dict[str, Any],
        fingerprint: str,
        context: dict[str, Any],
        *,
        direction: str,
        response_hint: str | None = None,
    ) -> dict[str, Any]:
        prompt = self.event_store.create_prompt(
            {
                "fingerprint": fingerprint,
                "profile": self.profile,
                "server_id": server_id,
                "tool_name": tool_name,
                "arguments": arguments,
                "hits": evaluation["hits"],
                "direction": direction,
                "response_hint": response_hint,
                "evidence": response_evidence(evaluation),
                "created_at": time.time(),
                "event_id": evaluation.get("event_id"),
                "chain_alerts": evaluation.get("chain_alerts", []),
                **{
                    field: context.get(field)
                    for field in runwall_runtime.CONTEXT_FIELDS
                    if context.get(field) is not None
                },
            }
        )
        payload = {
            "allowed": False,
            "action": "prompt",
            "review_required": True,
            "prompt_id": prompt["id"],
            "approval_url": self.approval_url(prompt["id"]),
            "hits": evaluation["hits"],
            "chain_alerts": evaluation.get("chain_alerts", []),
            **{
                field: context.get(field)
                for field in runwall_runtime.CONTEXT_FIELDS
                if context.get(field) is not None
            },
        }
        self.audit_gateway_event(
            {
                "module": "runwall-gateway",
                "decision": "prompt",
                "reason": first_reason(evaluation, f"Review required for {server_id}__{tool_name}"),
                "runtime": "gateway",
                "server_id": server_id,
                "tool_name": tool_name,
                "direction": direction,
                "prompt_id": prompt["id"],
                "tool_input": safe_json_dumps(arguments),
                "hits": evaluation["hits"],
                "evidence": response_evidence(evaluation),
                "response_preview": response_hint,
                "event_id": evaluation.get("event_id"),
                "chain_alerts": evaluation.get("chain_alerts", []),
                **{
                    field: context.get(field)
                    for field in runwall_runtime.CONTEXT_FIELDS
                    if context.get(field) is not None
                },
            }
        )
        for alert in evaluation.get("triggered_chain_alerts", []):
            self.audit_gateway_event(
                {
                    "module": "runwall-chain-engine",
                    "decision": "warn",
                    "reason": f"Detected risky chain {alert['chain_id']}",
                    "runtime": context.get("runtime") or "gateway",
                    "server_id": server_id,
                    "tool_name": tool_name,
                    "direction": direction,
                    "session_id": alert["session_id"],
                    "chain_id": alert["chain_id"],
                    "severity_score": alert["severity_score"],
                    "evidence_event_ids": alert["evidence_event_ids"],
                    "tool_input": safe_json_dumps(arguments),
                    **{
                        field: context.get(field)
                        for field in runwall_runtime.CONTEXT_FIELDS
                        if context.get(field) is not None
                    },
                }
            )
        return tool_result(payload, is_error=True)

    def handle_upstream_tool(self, full_name: str, arguments: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        if "__" not in full_name:
            raise KeyError(full_name)
        server_id, tool_name = full_name.split("__", 1)
        if server_id not in self.registry_servers():
            raise KeyError(full_name)

        matcher = f"mcp__{server_id}__{tool_name}"
        request_payload = {
            "runtime": "gateway",
            "server_id": server_id,
            "tool_name": tool_name,
            "arguments": arguments,
        }
        fingerprint = request_fingerprint(server_id, tool_name, arguments, self.profile, context)
        request_prompt_key = f"{fingerprint}:request"
        request_eval = runwall_policy.evaluate(
            self.root,
            self.profile,
            "PreToolUse",
            matcher,
            safe_json_dumps(request_payload),
            context=context,
        )

        if request_eval["action"] == "block":
            self.audit_gateway_event(
                {
                    "module": "runwall-gateway",
                    "decision": "block",
                    "reason": first_reason(request_eval, f"Blocked {full_name}"),
                    "runtime": "gateway",
                    "server_id": server_id,
                    "tool_name": tool_name,
                    "direction": "request",
                    "tool_input": safe_json_dumps(arguments),
                    "hits": request_eval["hits"],
                    "event_id": request_eval.get("event_id"),
                    "chain_alerts": request_eval.get("chain_alerts", []),
                    **{
                        field: context.get(field)
                        for field in runwall_runtime.CONTEXT_FIELDS
                        if context.get(field) is not None
                    },
                }
            )
            for alert in request_eval.get("triggered_chain_alerts", []):
                self.audit_gateway_event(
                    {
                        "module": "runwall-chain-engine",
                        "decision": "warn",
                        "reason": f"Detected risky chain {alert['chain_id']}",
                        "runtime": context.get("runtime") or "gateway",
                        "server_id": server_id,
                        "tool_name": tool_name,
                        "direction": "request",
                        "session_id": alert["session_id"],
                        "chain_id": alert["chain_id"],
                        "severity_score": alert["severity_score"],
                        "evidence_event_ids": alert["evidence_event_ids"],
                        "tool_input": safe_json_dumps(arguments),
                        **{
                            field: context.get(field)
                            for field in runwall_runtime.CONTEXT_FIELDS
                            if context.get(field) is not None
                        },
                    }
                )
            return tool_result(request_eval, is_error=True)

        if request_eval["action"] == "prompt" and not self.event_store.approved(request_prompt_key):
            return self.prompt_result(
                server_id,
                tool_name,
                arguments,
                request_eval,
                request_prompt_key,
                context,
                direction="request",
            )
        for alert in request_eval.get("triggered_chain_alerts", []):
            self.audit_gateway_event(
                {
                    "module": "runwall-chain-engine",
                    "decision": "warn",
                    "reason": f"Detected risky chain {alert['chain_id']}",
                    "runtime": context.get("runtime") or "gateway",
                    "server_id": server_id,
                    "tool_name": tool_name,
                    "direction": "request",
                    "session_id": alert["session_id"],
                    "chain_id": alert["chain_id"],
                    "severity_score": alert["severity_score"],
                    "evidence_event_ids": alert["evidence_event_ids"],
                    "tool_input": safe_json_dumps(arguments),
                    **{
                        field: context.get(field)
                        for field in runwall_runtime.CONTEXT_FIELDS
                        if context.get(field) is not None
                    },
                }
            )

        started = time.perf_counter()
        upstream = self.get_upstream(server_id)
        result = upstream.call_tool(tool_name, arguments)
        latency_ms = round((time.perf_counter() - started) * 1000, 2)

        response_eval = runwall_policy.evaluate(
            self.root,
            self.profile,
            "PostToolUse",
            matcher,
            safe_json_dumps(
                {
                    "runtime": "gateway",
                    "server_id": server_id,
                    "tool_name": tool_name,
                    "tool_input": arguments,
                    "tool_response": result,
                }
            ),
            context=context,
        )
        if response_eval["action"] == "allow":
            fallback = secret_redaction_fallback(result)
            if fallback is not None:
                response_eval = fallback
        response_prompt_key = f"{response_fingerprint(fingerprint, result, context)}:response"
        if response_eval["action"] == "block":
            self.audit_gateway_event(
                {
                    "module": "runwall-gateway",
                    "decision": "block",
                    "reason": first_reason(response_eval, f"Suppressed response from {full_name}"),
                    "runtime": "gateway",
                    "server_id": server_id,
                    "tool_name": tool_name,
                    "direction": "response",
                    "latency_ms": latency_ms,
                    "tool_input": safe_json_dumps(arguments),
                    "hits": response_eval["hits"],
                    "response_preview": response_preview(result),
                    "evidence": response_evidence(response_eval),
                    "event_id": response_eval.get("event_id"),
                    "chain_alerts": response_eval.get("chain_alerts", []),
                    **{
                        field: context.get(field)
                        for field in runwall_runtime.CONTEXT_FIELDS
                        if context.get(field) is not None
                    },
                }
            )
            for alert in response_eval.get("triggered_chain_alerts", []):
                self.audit_gateway_event(
                    {
                        "module": "runwall-chain-engine",
                        "decision": "warn",
                        "reason": f"Detected risky chain {alert['chain_id']}",
                        "runtime": context.get("runtime") or "gateway",
                        "server_id": server_id,
                        "tool_name": tool_name,
                        "direction": "response",
                        "session_id": alert["session_id"],
                        "chain_id": alert["chain_id"],
                        "severity_score": alert["severity_score"],
                        "evidence_event_ids": alert["evidence_event_ids"],
                        "tool_input": safe_json_dumps(arguments),
                        **{
                            field: context.get(field)
                            for field in runwall_runtime.CONTEXT_FIELDS
                            if context.get(field) is not None
                        },
                    }
                )
            return tool_result(response_eval, is_error=True)

        if response_eval["action"] == "prompt" and not self.event_store.approved(response_prompt_key):
            return self.prompt_result(
                server_id,
                tool_name,
                arguments,
                response_eval,
                response_prompt_key,
                context,
                direction="response",
                response_hint=response_preview(result),
            )

        final_result = result
        if response_eval["action"] == "redact":
            final_result = self.redact_result(result, response_eval)
            self.audit_gateway_event(
                {
                    "module": "runwall-gateway",
                    "decision": "redact",
                    "reason": first_reason(response_eval, f"Redacted response from {full_name}"),
                    "runtime": "gateway",
                    "server_id": server_id,
                    "tool_name": tool_name,
                    "direction": "response",
                    "latency_ms": latency_ms,
                    "tool_input": safe_json_dumps(arguments),
                    "hits": response_eval["hits"],
                    "redactions": final_result.get("structuredContent", {}).get("runwall_redactions", []),
                    "response_preview": response_preview(final_result),
                    "evidence": response_evidence(response_eval),
                    "event_id": response_eval.get("event_id"),
                    "chain_alerts": response_eval.get("chain_alerts", []),
                    **{
                        field: context.get(field)
                        for field in runwall_runtime.CONTEXT_FIELDS
                        if context.get(field) is not None
                    },
                }
            )
        else:
            self.audit_gateway_event(
                {
                    "module": "runwall-gateway",
                    "decision": "allow",
                    "reason": f"Allowed {full_name}",
                    "runtime": "gateway",
                    "server_id": server_id,
                    "tool_name": tool_name,
                    "direction": "response",
                    "latency_ms": latency_ms,
                    "tool_input": safe_json_dumps(arguments),
                    "response_preview": response_preview(result),
                    "event_id": response_eval.get("event_id"),
                    "chain_alerts": response_eval.get("chain_alerts", []),
                    **{
                        field: context.get(field)
                        for field in runwall_runtime.CONTEXT_FIELDS
                        if context.get(field) is not None
                    },
                }
            )
        for alert in response_eval.get("triggered_chain_alerts", []):
            self.audit_gateway_event(
                {
                    "module": "runwall-chain-engine",
                    "decision": "warn",
                    "reason": f"Detected risky chain {alert['chain_id']}",
                    "runtime": context.get("runtime") or "gateway",
                    "server_id": server_id,
                    "tool_name": tool_name,
                    "direction": "response",
                    "session_id": alert["session_id"],
                    "chain_id": alert["chain_id"],
                    "severity_score": alert["severity_score"],
                    "evidence_event_ids": alert["evidence_event_ids"],
                    "tool_input": safe_json_dumps(arguments),
                    **{
                        field: context.get(field)
                        for field in runwall_runtime.CONTEXT_FIELDS
                        if context.get(field) is not None
                    },
                }
            )
        return final_result

    def serve_stdio(self) -> int:
        self.start_http_server()
        while True:
            message = read_message(sys.stdin.buffer)
            if message is None:
                return 0
            method = message.get("method")
            request_id = message.get("id")
            if method == "initialize":
                write_message(
                    sys.stdout.buffer,
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "result": {
                            "protocolVersion": "2024-11-05",
                            "capabilities": {"tools": {}},
                            "serverInfo": {"name": "runwall-gateway", "version": "4.2.0"},
                        },
                    },
                )
                continue
            if method == "notifications/initialized":
                continue
            if method == "tools/list":
                write_message(
                    sys.stdout.buffer,
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "result": {"tools": self.aggregated_tools()},
                    },
                )
                continue
            if method == "tools/call":
                params = message.get("params", {})
                name = params.get("name")
                arguments = params.get("arguments", {})
                meta = params.get("_meta")
                request_context = runwall_runtime.merge_contexts(
                    runwall_runtime.context_from_env(),
                    meta.get("runwall_context") if isinstance(meta, dict) else None,
                )
                try:
                    if name in {tool["name"] for tool in INTERNAL_TOOLS}:
                        internal_args = dict(arguments)
                        internal_args["_runwall_context"] = request_context
                        result = self.handle_internal_tool(name, internal_args)
                    else:
                        result = self.handle_upstream_tool(name, arguments, request_context)
                    write_message(
                        sys.stdout.buffer,
                        {
                            "jsonrpc": "2.0",
                            "id": request_id,
                            "result": result,
                        },
                    )
                except Exception as exc:  # pragma: no cover
                    write_message(
                        sys.stdout.buffer,
                        {
                            "jsonrpc": "2.0",
                            "id": request_id,
                            "error": {"code": -32000, "message": str(exc)},
                        },
                    )
                continue
            if method == "ping":
                write_message(sys.stdout.buffer, {"jsonrpc": "2.0", "id": request_id, "result": {}})
                continue
            if request_id is not None:
                write_message(
                    sys.stdout.buffer,
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "error": {"code": -32601, "message": f"Method not found: {method}"},
                    },
                )

    def close(self) -> None:
        for upstream in self.upstreams.values():
            upstream.close()
        if self.httpd is not None:
            self.httpd.shutdown()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Runwall inline MCP gateway")
    parser.add_argument("--root", required=True)
    parser.add_argument("--profile", default="balanced")
    parser.add_argument("--config")
    parser.add_argument("--api-port", type=int, default=9470)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    gateway = Gateway(
        root=pathlib.Path(args.root),
        profile=args.profile,
        config_path=pathlib.Path(args.config) if args.config else None,
        api_port=args.api_port,
    )
    try:
        return gateway.serve_stdio()
    finally:
        gateway.close()


if __name__ == "__main__":
    raise SystemExit(main())
