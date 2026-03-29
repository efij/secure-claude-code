#!/usr/bin/env python3
import ipaddress
import json
import os
import pathlib
import re
import sys
from typing import Any

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
SHELL_PATTERNS = [
    re.compile(r"(curl|wget|iwr|irm|Invoke-WebRequest).{0,240}(\||&&|;).{0,120}(bash|sh|zsh|pwsh|powershell)", re.IGNORECASE),
    re.compile(r"(bash|sh)\s+-c.{0,200}(curl|wget|iwr|irm|Invoke-WebRequest)", re.IGNORECASE),
    re.compile(r"(powershell|pwsh)\s+-enc", re.IGNORECASE),
    re.compile(r"base64.{0,80}(-d|--decode).{0,120}(\||&&|;).{0,120}(bash|sh|zsh|pwsh|powershell)", re.IGNORECASE),
    re.compile(r"chmod\s+\+x.{0,120}(\||&&|;).{0,120}(/tmp/|Downloads|\.\/)", re.IGNORECASE),
    re.compile(r"python\s+-c.{0,200}(exec|os\.system|subprocess)", re.IGNORECASE),
    re.compile(r"node\s+-e.{0,200}(child_process|exec\()", re.IGNORECASE),
]


def runwall_home() -> pathlib.Path:
    return pathlib.Path(
        os.environ.get(
            "RUNWALL_HOME",
            os.environ.get("SECURE_CLAUDE_CODE_HOME", os.path.expanduser("~/.runwall")),
        )
    )


def collect_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        items: list[str] = []
        for nested in value.values():
            items.extend(collect_strings(nested))
        return items
    if isinstance(value, list):
        items: list[str] = []
        for nested in value:
            items.extend(collect_strings(nested))
        return items
    return []


def load_payload(raw: str) -> dict[str, Any]:
    try:
        payload = json.loads(raw)
        if isinstance(payload, dict):
            return payload
    except json.JSONDecodeError:
        pass
    return {"tool_response": {"content": raw}}


def first_match(patterns: list[re.Pattern[str]], haystack: str) -> str | None:
    for pattern in patterns:
        match = pattern.search(haystack)
        if match:
            return match.group(0)
    return None


def classify_url(url: str) -> str | None:
    lowered = url.lower()
    if any(token in lowered for token in ("discord.com/api/webhooks", "hooks.slack.com/services", "webhook.office.com", "outlook.office.com/webhook")):
        return "webhook"
    if any(token in lowered for token in ("pastebin.com", "paste.rs", "transfer.sh", "file.io", "0x0.st")):
        return "paste"
    if any(token in lowered for token in ("gist.githubusercontent.com", "raw.githubusercontent.com")):
        return "gist"
    if any(token in lowered for token in ("s3.amazonaws.com", "storage.googleapis.com", "blob.core.windows.net", "r2.cloudflarestorage.com")):
        return "blob"
    host = lowered.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    if host in {"localhost", "127.0.0.1"}:
        return "private-network"
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return None
    if address.is_private or address.is_loopback or address.is_link_local:
        return "private-network"
    return None


def emit(decision: str, reason: str, label: str, evidence: str, exit_code: int) -> int:
    payload = {
        "decision": decision,
        "reason": reason,
        "evidence": [{"type": label, "value": evidence[:200]}],
    }
    print(f"RUNWALL_JSON:{json.dumps(payload, separators=(',', ':'))}")
    if decision == "prompt":
        print("[runwall] review required for suspicious MCP response URL", file=sys.stderr)
    else:
        print("[runwall] blocked risky MCP response shell snippet", file=sys.stderr)
    print(f"reason: {reason}", file=sys.stderr)
    return exit_code


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        return 0
    mode = argv[1]
    payload = load_payload(argv[2])
    strings = collect_strings(payload.get("tool_response", payload))
    joined = "\n".join(strings)

    if mode == "urls":
        for url in URL_RE.findall(joined):
            classification = classify_url(url)
            if classification is None:
                continue
            return emit(
                "prompt",
                f"The upstream response contains a {classification} URL that should be reviewed before the runtime sees it.",
                "url",
                url,
                0,
            )
        return 0

    if mode == "shell":
        matched = first_match(SHELL_PATTERNS, joined)
        if not matched:
            return 0
        return emit(
            "block",
            "The upstream response contains a staged shell or interpreter execution snippet and should be blocked.",
            "shell-snippet",
            matched,
            1,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
