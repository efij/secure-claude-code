#!/usr/bin/env python3
import argparse
import copy
import hashlib
import json
import os
import pathlib
import queue
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


def request_fingerprint(server_id: str, tool_name: str, arguments: dict[str, Any], profile: str) -> str:
    digest = hashlib.sha256()
    digest.update(safe_json_dumps({
        "server_id": server_id,
        "tool_name": tool_name,
        "arguments": arguments,
        "profile": profile,
    }).encode("utf-8"))
    return digest.hexdigest()


def first_reason(result: dict[str, Any], fallback: str) -> str:
    for hit in result.get("hits", []):
        if hit.get("output"):
            return hit["output"].splitlines()[0]
    return fallback


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
        module = (query.get("module") or [""])[0]
        if runtime:
            events = [event for event in events if event.get("runtime") == runtime]
        if server_id:
            events = [event for event in events if event.get("server_id") == server_id]
        if tool_name:
            events = [event for event in events if event.get("tool_name") == tool_name]
        if decision:
            events = [event for event in events if event.get("decision") == decision]
        if module:
            events = [event for event in events if event.get("module") == module]
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


class UpstreamSession:
    def __init__(self, server_id: str, spec: dict[str, Any]):
        self.server_id = server_id
        self.spec = spec
        self.proc: subprocess.Popen | None = None
        self.initialized = False
        self._request_id = 0
        self._lock = threading.Lock()

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
        self.request("initialize", {})
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
        self.upstreams: dict[str, UpstreamSession] = {}
        self.asset_root = root / "web" / "gateway"
        self.httpd: ThreadingHTTPServer | None = None

    def audit_gateway_event(self, event: dict[str, Any]) -> None:
        self.event_store.add_event(event)
        runwall_policy.write_audit_event(
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
        )

    def approval_url(self, prompt_id: str) -> str:
        return f"http://127.0.0.1:{self.api_port}/#prompt={prompt_id}"

    def start_http_server(self) -> None:
        gateway = self

        class Handler(BaseHTTPRequestHandler):
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
                    return self._json({"events": gateway.event_store.list_events(parse_qs(parsed.query))})
                if parsed.path == "/api/pending-prompts":
                    return self._json({"pending": gateway.event_store.list_pending()})
                if parsed.path == "/api/events/stream":
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Cache-Control", "no-cache")
                    self.send_header("Connection", "keep-alive")
                    self.end_headers()
                    subscriber = gateway.event_store.subscribe()
                    try:
                        for event in gateway.event_store.list_events({})[-50:]:
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
                        "tool_input": safe_json_dumps(resolved["arguments"]),
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
        for server_id, spec in sorted(self.registry_servers().items()):
            if not self.registry_allowed(server_id, spec):
                continue
            upstream = self.get_upstream(server_id)
            for tool in upstream.list_tools():
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
                exposed = copy.deepcopy(tool)
                exposed["name"] = f"{server_id}__{tool['name']}"
                tools.append(exposed)
        return tools

    def handle_internal_tool(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        profile = args.get("profile") or self.profile
        if name == "preflight_bash":
            result = runwall_policy.evaluate(self.root, profile, "PreToolUse", "Bash", args["command"])
        elif name == "preflight_read":
            result = runwall_policy.evaluate(self.root, profile, "PreToolUse", "Read", args["path"])
        elif name == "preflight_write":
            payload = f"{args['target']} {args.get('content', '')}".strip()
            result = runwall_policy.evaluate(self.root, profile, "PreToolUse", "Write", payload)
        elif name == "inspect_output":
            payload = safe_json_dumps(
                {
                    "tool_name": args["tool_name"],
                    "tool_input": {},
                    "tool_response": {"content": args["content"]},
                }
            )
            result = runwall_policy.evaluate(self.root, profile, "PostToolUse", args["tool_name"], payload)
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
        for item in redacted.get("content", []):
            if isinstance(item, dict) and item.get("type") == "text":
                item["text"] = "[runwall] sensitive or malicious upstream content was redacted"
        structured = redacted.get("structuredContent")
        if isinstance(structured, dict):
            structured["runwall_redacted"] = True
            structured["runwall_redactions"] = redactions
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
    ) -> dict[str, Any]:
        prompt = self.event_store.create_prompt(
            {
                "fingerprint": fingerprint,
                "profile": self.profile,
                "server_id": server_id,
                "tool_name": tool_name,
                "arguments": arguments,
                "hits": evaluation["hits"],
                "created_at": time.time(),
            }
        )
        payload = {
            "allowed": False,
            "action": "prompt",
            "review_required": True,
            "prompt_id": prompt["id"],
            "approval_url": self.approval_url(prompt["id"]),
            "hits": evaluation["hits"],
        }
        self.audit_gateway_event(
            {
                "module": "runwall-gateway",
                "decision": "prompt",
                "reason": first_reason(evaluation, f"Review required for {server_id}__{tool_name}"),
                "runtime": "gateway",
                "server_id": server_id,
                "tool_name": tool_name,
                "direction": "request",
                "prompt_id": prompt["id"],
                "tool_input": safe_json_dumps(arguments),
                "hits": evaluation["hits"],
            }
        )
        return tool_result(payload, is_error=True)

    def handle_upstream_tool(self, full_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
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
        fingerprint = request_fingerprint(server_id, tool_name, arguments, self.profile)
        request_eval = runwall_policy.evaluate(
            self.root,
            self.profile,
            "PreToolUse",
            matcher,
            safe_json_dumps(request_payload),
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
                }
            )
            return tool_result(request_eval, is_error=True)

        if request_eval["action"] == "prompt" and not self.event_store.approved(fingerprint):
            return self.prompt_result(server_id, tool_name, arguments, request_eval, fingerprint)

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
        )
        if response_eval["action"] == "allow":
            fallback = secret_redaction_fallback(result)
            if fallback is not None:
                response_eval = fallback
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
                }
            )
            return tool_result(response_eval, is_error=True)

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
                            "serverInfo": {"name": "runwall-gateway", "version": "3.3.5"},
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
                try:
                    if name in {tool["name"] for tool in INTERNAL_TOOLS}:
                        result = self.handle_internal_tool(name, arguments)
                    else:
                        result = self.handle_upstream_tool(name, arguments)
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
