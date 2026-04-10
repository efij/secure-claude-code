#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import re
from typing import Any


SCHEDULE_RE = re.compile(
    r"""(?ix)
    \b(
        cron(?:tab)?
        |schedule
        |schtasks
        |launchctl
        |systemd
        |timer
        |at\s+\d
        |nightly
    )\b
    |on:\s*schedule
    """
)
BACKGROUND_RE = re.compile(r"(?ix)\b(?:nohup|disown|tmux\s+new-session\s+-d|screen\s+-dm)\b")
EXFIL_RE = re.compile(
    r"""(?ix)
    (
        curl\b[^\n\r]{0,120}(?:-F|--form|--data|--data-binary|-T|-X\s+(?:POST|PUT))
        |wget\b[^\n\r]{0,120}(?:--post-data|--body-data)
        |scp\b
        |rsync\b
        |rclone\b
        |aws\s+s3\s+(?:cp|sync)\b
        |gsutil\s+cp\b
        |gh\s+gist\s+create\b
        |gh\s+(?:issue|pr)\s+comment\b
        |chat\.postmessage
        |conversations\.replies
        |hooks\.slack\.com/services
        |webhook
        |sendgrid
        |mailgun
    )
    """
)


def _profile(context: dict[str, Any] | None) -> str:
    return str((context or {}).get("profile") or "balanced").lower()


def _path_from_payload(payload: str) -> str | None:
    if not payload:
        return None
    token = payload.split(" ", 1)[0].strip()
    if "/" in token or token.endswith((".yml", ".yaml", ".json", ".sh", ".py", ".toml")):
        return token
    return None


def _hit(module: str, identity: dict[str, Any], reason: str, safer: str) -> dict[str, Any]:
    return {
        "module": module,
        "name": module.replace("-", " ").title(),
        "category": "delayed-exfil-trust",
        "family": "Runtime, Network & Egress",
        "decision": "block",
        "exit_code": 2,
        "output": reason,
        "metadata": {
            "reason": reason,
            "confidence": 0.95,
            "safer_alternative": safer,
            "delayed_exfil_identity": identity,
        },
    }


def assess_action(
    root: pathlib.Path,
    event: str,
    matcher: str,
    payload: str,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    del root, event
    if _profile(context) != "strict":
        return {"identity": None, "hit": None}
    if matcher not in {"Bash", "Write", "Edit", "MultiEdit"}:
        return {"identity": None, "hit": None}
    if not (SCHEDULE_RE.search(payload) or BACKGROUND_RE.search(payload)):
        return {"identity": None, "hit": None}
    if not EXFIL_RE.search(payload):
        return {"identity": None, "hit": None}
    identity = {
        "surface_class": "delayed-exfil",
        "operation": "scheduled-export",
        "target": "external-destination",
        "path": _path_from_payload(payload),
        "profile": "strict",
    }
    return {
        "identity": identity,
        "hit": _hit(
            "delayed-exfil-chain-guard",
            identity,
            "Blocked delayed or background exfiltration setup that schedules a later outbound share or upload.",
            "Keep scheduled automation, workflow files, and background jobs free of outbound sharing steps unless a human has explicitly reviewed the chain.",
        ),
    }
