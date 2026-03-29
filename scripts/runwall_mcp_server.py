#!/usr/bin/env python3
import argparse
import json
import pathlib
import sys
from typing import Any

import runwall_policy


TOOLS = [
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


def read_message() -> dict[str, Any] | None:
    headers = {}
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            return None
        if line in (b"\r\n", b"\n"):
            break
        key, _, value = line.decode("utf-8").partition(":")
        headers[key.strip().lower()] = value.strip()
    length = int(headers.get("content-length", "0"))
    if length <= 0:
        return None
    body = sys.stdin.buffer.read(length)
    if not body:
        return None
    return json.loads(body.decode("utf-8"))


def write_message(payload: dict[str, Any]) -> None:
    body = json.dumps(payload).encode("utf-8")
    sys.stdout.buffer.write(f"Content-Length: {len(body)}\r\n\r\n".encode("utf-8"))
    sys.stdout.buffer.write(body)
    sys.stdout.buffer.flush()


def tool_result(result: dict[str, Any]) -> dict[str, Any]:
    text = json.dumps(result, indent=2)
    return {
        "content": [{"type": "text", "text": text}],
        "structuredContent": result,
        "isError": not result["allowed"],
    }


def handle_tool_call(root: pathlib.Path, default_profile: str, name: str, args: dict[str, Any]):
    profile = args.get("profile") or default_profile
    if name == "preflight_bash":
        return runwall_policy.evaluate(root, profile, "PreToolUse", "Bash", args["command"])
    if name == "preflight_read":
        return runwall_policy.evaluate(root, profile, "PreToolUse", "Read", args["path"])
    if name == "preflight_write":
        payload = f"{args['target']} {args.get('content', '')}".strip()
        return runwall_policy.evaluate(root, profile, "PreToolUse", "Write", payload)
    if name == "inspect_output":
        payload = json.dumps(
            {
                "tool_name": args["tool_name"],
                "tool_input": {},
                "tool_response": {"content": args["content"]},
            }
        )
        return runwall_policy.evaluate(root, profile, "PostToolUse", args["tool_name"], payload)
    raise KeyError(name)


def main() -> int:
    parser = argparse.ArgumentParser(description="Runwall MCP policy server")
    parser.add_argument("--root", required=True)
    parser.add_argument("--profile", default="balanced")
    args = parser.parse_args()

    root = pathlib.Path(args.root)
    while True:
        message = read_message()
        if message is None:
            return 0
        method = message.get("method")
        request_id = message.get("id")
        if method == "initialize":
            write_message(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "runwall", "version": "1.0.0"},
                    },
                }
            )
            continue
        if method == "notifications/initialized":
            continue
        if method == "tools/list":
            write_message(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {"tools": TOOLS},
                }
            )
            continue
        if method == "tools/call":
            params = message.get("params", {})
            name = params.get("name")
            arguments = params.get("arguments", {})
            try:
                result = handle_tool_call(root, args.profile, name, arguments)
                write_message(
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "result": tool_result(result),
                    }
                )
            except Exception as exc:  # pragma: no cover
                write_message(
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "error": {"code": -32000, "message": str(exc)},
                    }
                )
            continue
        if method == "ping":
            write_message({"jsonrpc": "2.0", "id": request_id, "result": {}})
            continue
        if request_id is not None:
            write_message(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32601, "message": f"Method not found: {method}"},
                }
            )


if __name__ == "__main__":
    raise SystemExit(main())
