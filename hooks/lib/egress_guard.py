#!/usr/bin/env python3
import ipaddress
import json
import os
import pathlib
import re
import sys
from typing import Any


URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def runwall_home() -> pathlib.Path:
    return pathlib.Path(
        os.environ.get(
            "RUNWALL_HOME",
            os.environ.get("SECURE_CLAUDE_CODE_HOME", os.path.expanduser("~/.runwall")),
        )
    )


def current_profile() -> str:
    return os.environ.get("RUNWALL_PROFILE", "balanced")


def load_policy() -> dict[str, Any]:
    path = runwall_home() / "config" / "egress-policy.json"
    if not path.exists():
        return {"profiles": {}}
    return json.loads(path.read_text(encoding="utf-8"))


def load_payload(raw: str) -> Any:
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw


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


def normalize_host(url: str) -> str:
    host = url.split("://", 1)[-1].split("/", 1)[0]
    if "@" in host:
        host = host.rsplit("@", 1)[-1]
    return host.split(":", 1)[0].strip().lower()


def classify_destination(host: str, url: str) -> list[str]:
    classes: list[str] = []
    if host in {"localhost"}:
        classes.append("private-network")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address and (address.is_private or address.is_loopback or address.is_link_local):
        classes.append("private-network")
    lowered = url.lower()
    if host == "169.254.169.254" or "metadata.google.internal" in host or "/latest/meta-data/" in lowered:
        classes.append("metadata")
    if any(token in lowered for token in ("discord.com/api/webhooks", "hooks.slack.com/services", "webhook.office.com", "outlook.office.com/webhook", "chat.googleapis.com/v1/spaces/")):
        classes.append("webhook")
    if any(token in host for token in ("pastebin.com", "paste.rs", "hastebin.com", "termbin.com", "0x0.st", "file.io", "transfer.sh")):
        classes.append("paste")
    if any(token in host for token in ("gist.githubusercontent.com", "raw.githubusercontent.com")):
        classes.append("gist")
    if any(token in host for token in ("s3.amazonaws.com", "storage.googleapis.com", "blob.core.windows.net", "r2.cloudflarestorage.com")):
        classes.append("blob")
    return classes


def host_matches(host: str, rule: str) -> bool:
    rule = rule.strip().lower()
    return host == rule or host.endswith(f".{rule}")


def decide(mode: str, url: str, host: str, classes: list[str], profile_policy: dict[str, Any]) -> tuple[str, str] | None:
    class_actions = profile_policy.get("class_actions", {})
    if mode == "private":
        if "metadata" in classes:
            return profile_policy.get("metadata", "block"), "metadata endpoint"
        if "private-network" in classes:
            return profile_policy.get("private_network", "prompt"), "private-network destination"
        return None

    if mode == "class":
        for kind in ("webhook", "paste", "gist", "blob"):
            if kind in classes:
                return class_actions.get(kind, "prompt"), f"{kind} destination"
        return None

    allowlist = profile_policy.get("allowlist", [])
    denylist = profile_policy.get("denylist", [])
    policy_mode = profile_policy.get("mode", "denylist")
    if policy_mode == "allowlist":
        if any(host_matches(host, rule) for rule in allowlist):
            return None
        return profile_policy.get("unknown_destination", "prompt"), "non-allowlisted destination"
    if any(host_matches(host, rule) for rule in denylist):
        return "block", "denylisted destination"
    return None


def emit(decision: str, reason: str, url: str, classes: list[str], exit_code: int) -> int:
    payload = {
        "decision": decision,
        "reason": reason,
        "egress": {"url": url[:240], "classes": classes},
        "evidence": [{"type": "destination", "value": url[:200]}],
    }
    print(f"RUNWALL_JSON:{json.dumps(payload, separators=(',', ':'))}")
    prefix = "[runwall] review required for outbound destination" if decision == "prompt" else "[runwall] blocked outbound destination"
    print(prefix, file=sys.stderr)
    print(f"reason: {reason}", file=sys.stderr)
    return exit_code


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        return 0
    mode = argv[1]
    payload = load_payload(argv[2])
    profile_policy = load_policy().get("profiles", {}).get(current_profile(), {})
    if not profile_policy:
        return 0
    for text in collect_strings(payload):
        for url in URL_RE.findall(text):
            host = normalize_host(url)
            classes = classify_destination(host, url)
            result = decide(mode, url, host, classes, profile_policy)
            if result is None:
                continue
            decision, label = result
            exit_code = 0 if decision == "prompt" else 1
            return emit(
                decision,
                f"The MCP request targets a {label} and violates the {current_profile()} outbound policy.",
                url,
                classes,
                exit_code,
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
