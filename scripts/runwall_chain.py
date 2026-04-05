#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import pathlib
import re
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from typing import Any


TRANSFER_RE = re.compile(
    r"(^|\s)(scp|sftp|ftp|rsync|rclone|nc|netcat|curl|wget|aws\s+s3\s+cp|gsutil\s+cp)(\s|$)",
    re.IGNORECASE,
)
ARCHIVE_RE = re.compile(
    r"(^|\s)(tar|zip|7z|7za|gzip|gunzip|bzip2|xz)(\s|$)|\.(zip|tar|tgz|gz|bz2|xz)",
    re.IGNORECASE,
)
REPO_TRAVERSAL_RE = re.compile(
    r"\b(rg\s+--files|find\s+\.\b|git\s+ls-files|tree\b|grep\s+-R|ls\s+-R)\b",
    re.IGNORECASE,
)
SECRET_PATH_RE = re.compile(
    r"(\.env|\.aws|\.ssh|id_rsa|id_ed25519|kubeconfig|session\.json|credentials|known_hosts|secret|secrets)",
    re.IGNORECASE,
)
EXTERNAL_URL_RE = re.compile(r"https?://(?!127\.0\.0\.1|localhost|10\.|172\.(1[6-9]|2\d|3[0-1])\.|192\.168\.)[^\s\"']+", re.IGNORECASE)
RESPONSE_INJECTION_RE = re.compile(
    r"(ignore\s+previous\s+instructions|developer\s+prompt|system\s+prompt|curl\s+https?://.+\|\s*(bash|sh)|wget\s+https?://.+\|\s*(bash|sh))",
    re.IGNORECASE,
)


def state_dir(root: pathlib.Path) -> pathlib.Path:
    home = os.environ.get("RUNWALL_HOME") or os.environ.get("SECURE_CLAUDE_CODE_HOME")
    if home:
        return pathlib.Path(home) / "state"
    return root / "state"


def db_path(root: pathlib.Path) -> pathlib.Path:
    return state_dir(root) / "session_chains.sqlite3"


def _connect(root: pathlib.Path) -> sqlite3.Connection:
    path = db_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS session_events (
          event_id TEXT PRIMARY KEY,
          session_id TEXT NOT NULL,
          ts REAL NOT NULL,
          event_json TEXT NOT NULL,
          categories_json TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS chain_alerts (
          alert_id TEXT PRIMARY KEY,
          session_id TEXT NOT NULL,
          chain_id TEXT NOT NULL,
          severity_score INTEGER NOT NULL,
          created_ts REAL NOT NULL,
          expires_ts REAL NOT NULL,
          evidence_json TEXT NOT NULL
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_session_events_session_ts ON session_events(session_id, ts)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_chain_alerts_session_expiry ON chain_alerts(session_id, expires_ts)"
    )
    return conn


def load_chain_rules(root: pathlib.Path) -> dict[str, Any]:
    path = root / "config" / "chain-rules.json"
    if not path.exists():
        return {"retention_seconds": 86400, "rules": []}
    payload = json.loads(path.read_text())
    if not isinstance(payload, dict):
        return {"retention_seconds": 86400, "rules": []}
    payload.setdefault("retention_seconds", 86400)
    payload.setdefault("rules", [])
    return payload


def iso_to_epoch(value: str | None) -> float:
    if not value:
        return time.time()
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _safe_json_dumps(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def _payload_text(event: dict[str, Any]) -> str:
    raw = event.get("raw_payload")
    if isinstance(raw, str) and raw:
        return raw
    tool_input = event.get("tool_input")
    if isinstance(tool_input, str):
        return tool_input
    return _safe_json_dumps(event)


def _modules(event: dict[str, Any]) -> set[str]:
    modules = set()
    for hit in event.get("hits", []):
        module = hit.get("module")
        if isinstance(module, str):
            modules.add(module)
    return modules


def classify_event(event: dict[str, Any]) -> list[str]:
    categories: set[str] = set()
    matcher = str(event.get("matcher") or "")
    direction = str(event.get("direction") or "")
    payload = _payload_text(event)
    modules = _modules(event)

    if matcher == "Read" and SECRET_PATH_RE.search(payload):
        categories.add("secret_read")
    if modules & {
        "protect-secrets-read",
        "agent-session-secret-guard",
        "netrc-credential-guard",
        "registry-credential-guard",
        "release-key-guard",
        "browser-cookie-guard",
        "mcp-bulk-read-exfil-guard",
    }:
        categories.add("secret_read")

    if matcher == "Write":
        categories.add("write_file")
        categories.add("privileged_tool")
    if matcher == "Bash":
        categories.add("shell_exec")
        categories.add("privileged_tool")
    if matcher.startswith("mcp__") and (
        "fetch_url" in matcher
        or "webhook" in payload.lower()
        or EXTERNAL_URL_RE.search(payload)
        or modules & {
            "mcp-egress-private-network-guard",
            "mcp-egress-destination-class-guard",
            "mcp-egress-policy-guard",
        }
    ):
        categories.add("external_call")

    if matcher == "Bash" and EXTERNAL_URL_RE.search(payload):
        categories.add("external_call")
    if matcher == "Bash" and TRANSFER_RE.search(payload):
        categories.add("upload_action")
        categories.add("external_call")
    if matcher == "Bash" and ARCHIVE_RE.search(payload):
        categories.add("archive_action")
    if matcher == "Bash" and (
        REPO_TRAVERSAL_RE.search(payload) or "repo-mass-harvest-guard" in modules
    ):
        categories.add("repo_traversal")
    if (direction == "response" or event.get("event") == "PostToolUse") and (
        modules & {
        "indirect-prompt-injection-guard",
        "mcp-response-prompt-smuggling-guard",
        "mcp-response-suspicious-url-guard",
        "mcp-response-shell-snippet-guard",
        "mcp-binary-dropper-guard",
        }
        or RESPONSE_INJECTION_RE.search(payload)
    ):
        categories.add("response_injection")

    return sorted(categories)


def _match_steps(events: list[dict[str, Any]], steps: list[str]) -> list[str]:
    evidence: list[str] = []
    start = 0
    for step in steps:
        found_index = None
        for index in range(start, len(events)):
            if step in events[index]["categories"]:
                found_index = index
                evidence.append(events[index]["event_id"])
                start = index + 1
                break
        if found_index is None:
            return []
    return evidence


def _deserialize_alert(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "alert_id": row["alert_id"],
        "chain_id": row["chain_id"],
        "severity_score": row["severity_score"],
        "session_id": row["session_id"],
        "created_ts": row["created_ts"],
        "expires_ts": row["expires_ts"],
        "evidence_event_ids": json.loads(row["evidence_json"]),
    }


def evaluate_session(root: pathlib.Path, event: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    session_id = event.get("session_id")
    if not session_id:
        return {
            "prior_active_chain_alerts": [],
            "triggered_chain_alerts": [],
            "active_chain_alerts": [],
            "categories": classify_event(event),
        }

    rules_config = load_chain_rules(root)
    retention_seconds = int(rules_config.get("retention_seconds", 86400))
    event_ts = iso_to_epoch(str(event.get("ts") or ""))
    categories = classify_event(event)

    with _connect(root) as conn:
        conn.execute(
            "DELETE FROM session_events WHERE ts < ?",
            (event_ts - retention_seconds,),
        )
        conn.execute(
            "DELETE FROM chain_alerts WHERE expires_ts < ?",
            (event_ts,),
        )
        rows = conn.execute(
            """
            SELECT alert_id, session_id, chain_id, severity_score, created_ts, expires_ts, evidence_json
            FROM chain_alerts
            WHERE session_id = ? AND expires_ts >= ?
            ORDER BY created_ts ASC
            """,
            (session_id, event_ts),
        ).fetchall()
        prior_active = [_deserialize_alert(row) for row in rows]
        active_ids = {alert["chain_id"] for alert in prior_active}

        max_window = max(
            [int(rule.get("window_seconds", 0)) for rule in rules_config.get("rules", [])] or [0]
        )
        recent_rows = conn.execute(
            """
            SELECT event_json, categories_json
            FROM session_events
            WHERE session_id = ? AND ts >= ?
            ORDER BY ts ASC
            """,
            (session_id, event_ts - max_window),
        ).fetchall()
        recent_events: list[dict[str, Any]] = []
        for row in recent_rows:
            event_payload = json.loads(row["event_json"])
            event_payload["categories"] = json.loads(row["categories_json"])
            recent_events.append(event_payload)

        current_event = dict(event)
        current_event["categories"] = categories
        recent_plus_current = [*recent_events, current_event]

        conn.execute(
            """
            INSERT OR REPLACE INTO session_events(event_id, session_id, ts, event_json, categories_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                current_event["event_id"],
                session_id,
                event_ts,
                _safe_json_dumps(current_event),
                _safe_json_dumps(categories),
            ),
        )

        triggered: list[dict[str, Any]] = []
        for rule in rules_config.get("rules", []):
            chain_id = rule.get("id")
            if not isinstance(chain_id, str) or chain_id in active_ids:
                continue
            steps = rule.get("steps") or []
            if not isinstance(steps, list) or not steps:
                continue
            window_seconds = int(rule.get("window_seconds", 0))
            eligible_events = [
                item
                for item in recent_plus_current
                if item.get("ts")
                and iso_to_epoch(str(item["ts"])) >= event_ts - window_seconds
            ]
            evidence = _match_steps(eligible_events, [str(step) for step in steps])
            if not evidence:
                continue
            alert = {
                "alert_id": uuid.uuid4().hex,
                "chain_id": chain_id,
                "severity_score": int(rule.get("severity_score", 0)),
                "session_id": session_id,
                "created_ts": event_ts,
                "expires_ts": event_ts + window_seconds,
                "evidence_event_ids": evidence,
            }
            conn.execute(
                """
                INSERT INTO chain_alerts(alert_id, session_id, chain_id, severity_score, created_ts, expires_ts, evidence_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert["alert_id"],
                    alert["session_id"],
                    alert["chain_id"],
                    alert["severity_score"],
                    alert["created_ts"],
                    alert["expires_ts"],
                    _safe_json_dumps(alert["evidence_event_ids"]),
                ),
            )
            triggered.append(alert)

    return {
        "prior_active_chain_alerts": prior_active,
        "triggered_chain_alerts": triggered,
        "active_chain_alerts": [*prior_active, *triggered],
        "categories": categories,
    }
