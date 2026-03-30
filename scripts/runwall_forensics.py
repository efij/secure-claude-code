#!/usr/bin/env python3
from __future__ import annotations

import io
import json
import os
import pathlib
import re
import sqlite3
import time
import uuid
import zipfile
from datetime import datetime, timezone
from typing import Any

import runwall_runtime


SECRET_VALUE_RE = re.compile(
    r"(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|AIza[0-9A-Za-z\-_]{20,}|-----BEGIN [A-Z ]+PRIVATE KEY-----)",
    re.IGNORECASE,
)
SENSITIVE_KEY_RE = re.compile(
    r"(token|secret|password|passwd|key|credential|cookie|session|authorization)",
    re.IGNORECASE,
)
ARTIFACT_PATH_RE = re.compile(
    r"([A-Za-z0-9_./~-]+\.(env|json|yml|yaml|toml|ini|cfg|pem|key|pub|md|sh|py|js|ts|zip|tgz|tar|gz))",
    re.IGNORECASE,
)

DECISION_CONFIDENCE = {
    "block": 0.95,
    "prompt": 0.82,
    "redact": 0.88,
    "warn": 0.7,
    "allow": 0.55,
}

DRIFT_CONFIDENCE = {
    "first_sight": 0.86,
    "server_drift": 0.9,
    "schema_drift": 0.9,
    "description_drift": 0.68,
    "same_name_collision": 0.98,
    "internal_name_collision": 0.99,
    "capability_expansion": 0.97,
}


def safe_json_dumps(payload: Any) -> str:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def state_dir(root: pathlib.Path) -> pathlib.Path:
    home = os.environ.get("RUNWALL_HOME") or os.environ.get("SECURE_CLAUDE_CODE_HOME")
    if home:
        return pathlib.Path(home) / "state"
    return root / "state"


def db_path(root: pathlib.Path) -> pathlib.Path:
    return state_dir(root) / "forensics.sqlite3"


def _connect(root: pathlib.Path) -> sqlite3.Connection:
    path = db_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS snapshots (
          snapshot_id TEXT PRIMARY KEY,
          entity_type TEXT NOT NULL,
          entity_key TEXT NOT NULL,
          fingerprint TEXT NOT NULL,
          snapshot_json TEXT NOT NULL,
          created_ts REAL NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS baselines (
          baseline_id TEXT PRIMARY KEY,
          entity_type TEXT NOT NULL,
          entity_key TEXT NOT NULL UNIQUE,
          fingerprint TEXT NOT NULL,
          snapshot_id TEXT NOT NULL,
          snapshot_json TEXT NOT NULL,
          created_ts REAL NOT NULL,
          updated_ts REAL NOT NULL,
          status TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS drifts (
          drift_id TEXT PRIMARY KEY,
          entity_type TEXT NOT NULL,
          entity_key TEXT NOT NULL,
          server_id TEXT,
          tool_name TEXT,
          drift_kind TEXT NOT NULL,
          decision TEXT NOT NULL,
          confidence REAL NOT NULL,
          baseline_id TEXT,
          baseline_fingerprint TEXT,
          current_fingerprint TEXT NOT NULL,
          baseline_snapshot_id TEXT,
          current_snapshot_id TEXT,
          diff_json TEXT NOT NULL,
          status TEXT NOT NULL,
          created_ts REAL NOT NULL,
          updated_ts REAL NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
          event_id TEXT PRIMARY KEY,
          ts TEXT NOT NULL,
          decision TEXT NOT NULL,
          module TEXT NOT NULL,
          runtime TEXT,
          profile TEXT,
          server_id TEXT,
          tool_name TEXT,
          session_id TEXT,
          agent_id TEXT,
          subagent_id TEXT,
          chain_id TEXT,
          drift_id TEXT,
          reason TEXT,
          searchable_text TEXT NOT NULL,
          event_json TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_decision ON events(decision)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_server_tool ON events(server_id, tool_name)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_drift ON events(drift_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_drifts_entity ON drifts(entity_type, entity_key)")
    return conn


def _canonicalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _canonicalize(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return [_canonicalize(item) for item in value]
    return value


def _now_ts() -> float:
    return time.time()


def _mask_string(value: str) -> str:
    masked = SECRET_VALUE_RE.sub("[runwall] masked-secret", value)
    if len(masked) > 320:
        masked = masked[:320] + "..."
    return masked


def mask_value(value: Any, *, key: str | None = None) -> Any:
    if isinstance(value, str):
        if key and SENSITIVE_KEY_RE.search(key):
            return "[runwall] masked-secret"
        return _mask_string(value)
    if isinstance(value, list):
        return [mask_value(item) for item in value]
    if isinstance(value, dict):
        masked: dict[str, Any] = {}
        for nested_key, nested_value in value.items():
            if SENSITIVE_KEY_RE.search(str(nested_key)):
                masked[nested_key] = "[runwall] masked-secret"
            elif str(nested_key) == "env" and isinstance(nested_value, dict):
                masked[nested_key] = {
                    env_key: "[runwall] masked-env"
                    for env_key in sorted(nested_value)
                }
            else:
                masked[nested_key] = mask_value(nested_value, key=str(nested_key))
        return masked
    return value


def mask_preview(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return _mask_string(value)
    return _mask_string(safe_json_dumps(mask_value(value)))


def infer_evidence(hit: dict[str, Any]) -> list[dict[str, Any]]:
    metadata = hit.get("metadata") or {}
    evidence = metadata.get("evidence")
    if isinstance(evidence, list):
        return [item for item in evidence if isinstance(item, dict)]
    output = str(hit.get("output") or "").strip()
    if output:
        return [{"type": "reason", "value": output.splitlines()[0][:200]}]
    return []


def infer_safer_alternative(hit: dict[str, Any]) -> str:
    metadata = hit.get("metadata") or {}
    alternative = metadata.get("safer_alternative")
    if isinstance(alternative, str) and alternative.strip():
        return alternative.strip()
    output = str(hit.get("output") or "")
    for line in output.splitlines():
        if line.lower().startswith("next:"):
            return line.split(":", 1)[1].strip()
    if hit.get("decision") == "block":
        return "Use the smallest reviewed action that stays inside the local trust boundary."
    if hit.get("decision") == "prompt":
        return "Review the change or request through the gateway before continuing."
    return ""


def normalize_hits(hits: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for hit in hits or []:
        metadata = dict(hit.get("metadata") or {})
        confidence = metadata.get("confidence")
        if not isinstance(confidence, (int, float)):
            confidence = DECISION_CONFIDENCE.get(str(hit.get("decision") or "allow"), 0.55)
        normalized.append(
            {
                **hit,
                "confidence": round(float(confidence), 2),
                "evidence": infer_evidence(hit),
                "safer_alternative": infer_safer_alternative(hit),
            }
        )
    return normalized


def extract_artifacts(event: dict[str, Any]) -> list[str]:
    artifacts: set[str] = set()
    payloads: list[Any] = []
    for key in ("tool_input", "request_preview", "response_preview"):
        if key in event:
            payloads.append(event[key])
    for payload in payloads:
        if isinstance(payload, dict):
            payload = safe_json_dumps(payload)
        if not isinstance(payload, str):
            continue
        for match in ARTIFACT_PATH_RE.findall(payload):
            artifacts.add(match[0])
    return sorted(artifacts)[:12]


def enrich_event(event: dict[str, Any]) -> dict[str, Any]:
    enriched = dict(event)
    hits = normalize_hits(enriched.get("hits"))
    enriched["hits"] = hits
    if not enriched.get("confidence"):
        if hits:
            enriched["confidence"] = max(hit["confidence"] for hit in hits)
        else:
            enriched["confidence"] = DECISION_CONFIDENCE.get(str(enriched.get("decision") or "allow"), 0.55)
    enriched["confidence"] = round(float(enriched["confidence"]), 2)
    if not enriched.get("safer_alternative"):
        enriched["safer_alternative"] = hits[0]["safer_alternative"] if hits else ""

    request_preview = enriched.get("request_preview")
    if request_preview is None:
        request_preview = enriched.get("tool_input", "")
    enriched["request_preview_masked"] = mask_preview(request_preview)

    response_preview = enriched.get("response_preview")
    if response_preview is not None:
        enriched["response_preview_masked"] = mask_preview(response_preview)

    enriched["artifacts_touched"] = extract_artifacts(enriched)
    if not enriched.get("call_chain"):
        call_chain: dict[str, Any] = {}
        for key in ("request_event_id", "response_event_id", "prompt_event_id", "related_event_id", "request_fingerprint"):
            if enriched.get(key):
                call_chain[key] = enriched[key]
        if call_chain:
            enriched["call_chain"] = call_chain
    return enriched


def record_event(root: pathlib.Path, event: dict[str, Any]) -> None:
    enriched = enrich_event(event)
    searchable = " ".join(
        str(item)
        for item in (
            enriched.get("reason", ""),
            enriched.get("module", ""),
            enriched.get("tool_name", ""),
            enriched.get("server_id", ""),
            enriched.get("drift_kind", ""),
            enriched.get("session_id", ""),
        )
        if item
    )
    with _connect(root) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO events(
              event_id, ts, decision, module, runtime, profile, server_id, tool_name,
              session_id, agent_id, subagent_id, chain_id, drift_id, reason, searchable_text, event_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                enriched["event_id"],
                enriched["ts"],
                enriched.get("decision", "info"),
                enriched.get("module", "runwall"),
                enriched.get("runtime"),
                enriched.get("profile"),
                enriched.get("server_id"),
                enriched.get("tool_name"),
                enriched.get("session_id"),
                enriched.get("agent_id"),
                enriched.get("subagent_id"),
                enriched.get("chain_id"),
                enriched.get("drift_id"),
                enriched.get("reason", ""),
                searchable.lower(),
                safe_json_dumps(enriched),
            ),
        )


def _query_all_events(root: pathlib.Path) -> list[dict[str, Any]]:
    with _connect(root) as conn:
        rows = conn.execute("SELECT event_json FROM events ORDER BY ts ASC").fetchall()
    return [json.loads(row["event_json"]) for row in rows]


def query_events(root: pathlib.Path, query: dict[str, list[str]] | dict[str, str]) -> list[dict[str, Any]]:
    events = _query_all_events(root)
    get_value = lambda key: (query.get(key) or [""])[0] if isinstance(query.get(key), list) else str(query.get(key) or "")
    filters = {
        "runtime": get_value("runtime"),
        "server_id": get_value("server_id"),
        "tool_name": get_value("tool_name"),
        "decision": get_value("decision"),
        "direction": get_value("direction"),
        "module": get_value("module"),
        "session_id": get_value("session_id"),
        "agent_id": get_value("agent_id"),
        "subagent_id": get_value("subagent_id"),
        "chain_id": get_value("chain_id"),
        "drift_id": get_value("drift_id"),
        "q": get_value("q"),
    }
    for key, value in filters.items():
        if not value:
            continue
        if key == "chain_id":
            events = [
                event
                for event in events
                if event.get("chain_id") == value
                or any(alert.get("chain_id") == value for alert in event.get("chain_alerts", []))
            ]
        elif key == "q":
            lowered = value.lower()
            events = [
                event for event in events
                if lowered in safe_json_dumps(event).lower()
            ]
        else:
            events = [event for event in events if str(event.get(key, "")) == value]
    return events


def get_event(root: pathlib.Path, event_id: str) -> dict[str, Any] | None:
    with _connect(root) as conn:
        row = conn.execute("SELECT event_json FROM events WHERE event_id = ?", (event_id,)).fetchone()
    if row is None:
        return None
    return json.loads(row["event_json"])


def create_snapshot(root: pathlib.Path, entity_type: str, entity_key: str, snapshot: dict[str, Any]) -> dict[str, Any]:
    normalized = _canonicalize(snapshot)
    fingerprint = safe_json_dumps(normalized)
    snapshot_id = uuid.uuid4().hex
    record = {
        "snapshot_id": snapshot_id,
        "entity_type": entity_type,
        "entity_key": entity_key,
        "fingerprint": fingerprint,
        "snapshot": normalized,
        "created_ts": _now_ts(),
    }
    with _connect(root) as conn:
        conn.execute(
            """
            INSERT INTO snapshots(snapshot_id, entity_type, entity_key, fingerprint, snapshot_json, created_ts)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                snapshot_id,
                entity_type,
                entity_key,
                fingerprint,
                safe_json_dumps(normalized),
                record["created_ts"],
            ),
        )
    return record


def get_baseline(root: pathlib.Path, entity_type: str, entity_key: str) -> dict[str, Any] | None:
    with _connect(root) as conn:
        row = conn.execute(
            """
            SELECT baseline_id, fingerprint, snapshot_id, snapshot_json, created_ts, updated_ts, status
            FROM baselines
            WHERE entity_type = ? AND entity_key = ?
            """,
            (entity_type, entity_key),
        ).fetchone()
    if row is None:
        return None
    return {
        "baseline_id": row["baseline_id"],
        "fingerprint": row["fingerprint"],
        "snapshot_id": row["snapshot_id"],
        "snapshot": json.loads(row["snapshot_json"]),
        "created_ts": row["created_ts"],
        "updated_ts": row["updated_ts"],
        "status": row["status"],
    }


def save_baseline(root: pathlib.Path, entity_type: str, entity_key: str, snapshot_record: dict[str, Any]) -> dict[str, Any]:
    baseline = get_baseline(root, entity_type, entity_key)
    baseline_id = baseline["baseline_id"] if baseline else uuid.uuid4().hex
    now = _now_ts()
    with _connect(root) as conn:
        conn.execute(
            """
            INSERT INTO baselines(
              baseline_id, entity_type, entity_key, fingerprint, snapshot_id, snapshot_json, created_ts, updated_ts, status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'approved')
            ON CONFLICT(entity_key) DO UPDATE SET
              fingerprint = excluded.fingerprint,
              snapshot_id = excluded.snapshot_id,
              snapshot_json = excluded.snapshot_json,
              updated_ts = excluded.updated_ts,
              status = 'approved'
            """,
            (
                baseline_id,
                entity_type,
                entity_key,
                snapshot_record["fingerprint"],
                snapshot_record["snapshot_id"],
                safe_json_dumps(snapshot_record["snapshot"]),
                baseline["created_ts"] if baseline else now,
                now,
            ),
        )
    return {
        "baseline_id": baseline_id,
        "fingerprint": snapshot_record["fingerprint"],
        "snapshot_id": snapshot_record["snapshot_id"],
        "snapshot": snapshot_record["snapshot"],
    }


def server_snapshot(server_id: str, spec: dict[str, Any], server_info: dict[str, Any] | None) -> dict[str, Any]:
    return {
        "server_id": server_id,
        "command": spec.get("command"),
        "args": spec.get("args", []),
        "cwd": spec.get("cwd"),
        "serverInfo": {
            "name": (server_info or {}).get("name"),
            "version": (server_info or {}).get("version"),
        },
    }


def tool_snapshot(server_id: str, tool: dict[str, Any]) -> dict[str, Any]:
    return {
        "server_id": server_id,
        "name": tool.get("name"),
        "description": tool.get("description", ""),
        "inputSchema": _canonicalize(tool.get("inputSchema", {})),
    }


def _schema_expanded(old: dict[str, Any], new: dict[str, Any]) -> bool:
    old_schema = old.get("inputSchema") or {}
    new_schema = new.get("inputSchema") or {}
    if not isinstance(old_schema, dict) or not isinstance(new_schema, dict):
        return False
    if old_schema.get("additionalProperties") is not True and new_schema.get("additionalProperties") is True:
        return True
    old_props = old_schema.get("properties") or {}
    new_props = new_schema.get("properties") or {}
    if isinstance(old_props, dict) and isinstance(new_props, dict) and set(new_props) - set(old_props):
        return True
    old_required = set(old_schema.get("required") or [])
    new_required = set(new_schema.get("required") or [])
    if old_required - new_required:
        return True
    return False


def _diff_payload(kind: str, baseline_snapshot: dict[str, Any] | None, current_snapshot: dict[str, Any], **extra: Any) -> dict[str, Any]:
    payload = {
        "kind": kind,
        "baseline": mask_value(baseline_snapshot) if baseline_snapshot else None,
        "current": mask_value(current_snapshot),
    }
    payload.update({key: value for key, value in extra.items() if value is not None})
    return payload


def _record_drift(
    root: pathlib.Path,
    *,
    entity_type: str,
    entity_key: str,
    server_id: str | None,
    tool_name: str | None,
    drift_kind: str,
    decision: str,
    baseline: dict[str, Any] | None,
    current_snapshot: dict[str, Any],
    current_record: dict[str, Any],
    diff: dict[str, Any],
    status: str,
) -> dict[str, Any]:
    confidence = DRIFT_CONFIDENCE.get(drift_kind, DECISION_CONFIDENCE.get(decision, 0.7))
    with _connect(root) as conn:
        existing = conn.execute(
            """
            SELECT drift_id, status FROM drifts
            WHERE entity_type = ? AND entity_key = ? AND current_fingerprint = ? AND drift_kind = ?
            ORDER BY created_ts DESC LIMIT 1
            """,
            (entity_type, entity_key, current_record["fingerprint"], drift_kind),
        ).fetchone()
        drift_id = existing["drift_id"] if existing else uuid.uuid4().hex
        now = _now_ts()
        conn.execute(
            """
            INSERT OR REPLACE INTO drifts(
              drift_id, entity_type, entity_key, server_id, tool_name, drift_kind, decision, confidence,
              baseline_id, baseline_fingerprint, current_fingerprint, baseline_snapshot_id, current_snapshot_id,
              diff_json, status, created_ts, updated_ts
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE((SELECT created_ts FROM drifts WHERE drift_id = ?), ?), ?)
            """,
            (
                drift_id,
                entity_type,
                entity_key,
                server_id,
                tool_name,
                drift_kind,
                decision,
                confidence,
                baseline["baseline_id"] if baseline else None,
                baseline["fingerprint"] if baseline else None,
                current_record["fingerprint"],
                baseline["snapshot_id"] if baseline else None,
                current_record["snapshot_id"],
                safe_json_dumps(diff),
                status,
                drift_id,
                now,
                now,
            ),
        )
    return {
        "drift_id": drift_id,
        "entity_type": entity_type,
        "entity_key": entity_key,
        "server_id": server_id,
        "tool_name": tool_name,
        "drift_kind": drift_kind,
        "decision": decision,
        "confidence": round(float(confidence), 2),
        "baseline_fingerprint": baseline["fingerprint"] if baseline else None,
        "current_fingerprint": current_record["fingerprint"],
        "baseline_snapshot_id": baseline["snapshot_id"] if baseline else None,
        "current_snapshot_id": current_record["snapshot_id"],
        "diff": diff,
        "status": status,
    }


def get_drift(root: pathlib.Path, drift_id: str) -> dict[str, Any] | None:
    with _connect(root) as conn:
        row = conn.execute(
            """
            SELECT drift_id, entity_type, entity_key, server_id, tool_name, drift_kind, decision, confidence,
                   baseline_id, baseline_fingerprint, current_fingerprint, baseline_snapshot_id, current_snapshot_id,
                   diff_json, status, created_ts, updated_ts
            FROM drifts WHERE drift_id = ?
            """,
            (drift_id,),
        ).fetchone()
    if row is None:
        return None
    return {
        "drift_id": row["drift_id"],
        "entity_type": row["entity_type"],
        "entity_key": row["entity_key"],
        "server_id": row["server_id"],
        "tool_name": row["tool_name"],
        "drift_kind": row["drift_kind"],
        "decision": row["decision"],
        "confidence": row["confidence"],
        "baseline_id": row["baseline_id"],
        "baseline_fingerprint": row["baseline_fingerprint"],
        "current_fingerprint": row["current_fingerprint"],
        "baseline_snapshot_id": row["baseline_snapshot_id"],
        "current_snapshot_id": row["current_snapshot_id"],
        "diff": json.loads(row["diff_json"]),
        "status": row["status"],
        "created_ts": row["created_ts"],
        "updated_ts": row["updated_ts"],
    }


def _mark_drift(root: pathlib.Path, drift_id: str, status: str) -> None:
    with _connect(root) as conn:
        conn.execute("UPDATE drifts SET status = ?, updated_ts = ? WHERE drift_id = ?", (status, _now_ts(), drift_id))


def approve_drift(root: pathlib.Path, entity_type: str, entity_key: str, snapshot_id: str, drift_id: str | None = None) -> dict[str, Any] | None:
    with _connect(root) as conn:
        row = conn.execute(
            "SELECT snapshot_id, fingerprint, snapshot_json FROM snapshots WHERE snapshot_id = ?",
            (snapshot_id,),
        ).fetchone()
    if row is None:
        return None
    record = {
        "snapshot_id": row["snapshot_id"],
        "fingerprint": row["fingerprint"],
        "snapshot": json.loads(row["snapshot_json"]),
    }
    baseline = save_baseline(root, entity_type, entity_key, record)
    if drift_id:
        _mark_drift(root, drift_id, "approved")
    return baseline


def reject_drift(root: pathlib.Path, drift_id: str | None) -> None:
    if drift_id:
        _mark_drift(root, drift_id, "denied")


def assess_server(
    root: pathlib.Path,
    server_id: str,
    spec: dict[str, Any],
    server_info: dict[str, Any] | None,
) -> dict[str, Any]:
    snapshot = server_snapshot(server_id, spec, server_info)
    current_record = create_snapshot(root, "server", server_id, snapshot)
    baseline = get_baseline(root, "server", server_id)
    if baseline is None:
        drift = _record_drift(
            root,
            entity_type="server",
            entity_key=server_id,
            server_id=server_id,
            tool_name=None,
            drift_kind="first_sight",
            decision="prompt",
            baseline=None,
            current_snapshot=snapshot,
            current_record=current_record,
            diff=_diff_payload("first_sight", None, snapshot),
            status="pending",
        )
        return {"action": "prompt", "drift": drift, "snapshot_id": current_record["snapshot_id"], "baseline_action": "store"}
    if baseline["fingerprint"] == current_record["fingerprint"]:
        save_baseline(root, "server", server_id, current_record)
        return {"action": "allow", "snapshot_id": current_record["snapshot_id"]}
    drift = _record_drift(
        root,
        entity_type="server",
        entity_key=server_id,
        server_id=server_id,
        tool_name=None,
        drift_kind="server_drift",
        decision="prompt",
        baseline=baseline,
        current_snapshot=snapshot,
        current_record=current_record,
        diff=_diff_payload("server_drift", baseline["snapshot"], snapshot),
        status="pending",
    )
    return {"action": "prompt", "drift": drift, "snapshot_id": current_record["snapshot_id"], "baseline_action": "update"}


def assess_tool(root: pathlib.Path, server_id: str, tool: dict[str, Any]) -> dict[str, Any]:
    entity_key = f"{server_id}::{tool.get('name')}"
    snapshot = tool_snapshot(server_id, tool)
    current_record = create_snapshot(root, "tool", entity_key, snapshot)
    baseline = get_baseline(root, "tool", entity_key)
    if baseline is None:
        drift = _record_drift(
            root,
            entity_type="tool",
            entity_key=entity_key,
            server_id=server_id,
            tool_name=tool.get("name"),
            drift_kind="first_sight",
            decision="prompt",
            baseline=None,
            current_snapshot=snapshot,
            current_record=current_record,
            diff=_diff_payload("first_sight", None, snapshot),
            status="pending",
        )
        return {"action": "prompt", "drift": drift, "snapshot_id": current_record["snapshot_id"], "baseline_action": "store"}
    if baseline["fingerprint"] == current_record["fingerprint"]:
        save_baseline(root, "tool", entity_key, current_record)
        return {"action": "allow", "snapshot_id": current_record["snapshot_id"]}

    old_snapshot = baseline["snapshot"]
    new_snapshot = snapshot
    if old_snapshot.get("inputSchema") != new_snapshot.get("inputSchema"):
        drift_kind = "capability_expansion" if _schema_expanded(old_snapshot, new_snapshot) else "schema_drift"
        decision = "block" if drift_kind == "capability_expansion" else "prompt"
    elif old_snapshot.get("description", "") != new_snapshot.get("description", ""):
        drift_kind = "description_drift"
        decision = "warn"
    else:
        drift_kind = "schema_drift"
        decision = "prompt"
    drift = _record_drift(
        root,
        entity_type="tool",
        entity_key=entity_key,
        server_id=server_id,
        tool_name=tool.get("name"),
        drift_kind=drift_kind,
        decision=decision,
        baseline=baseline,
        current_snapshot=snapshot,
        current_record=current_record,
        diff=_diff_payload(drift_kind, old_snapshot, new_snapshot),
        status="approved" if decision == "warn" else "pending",
    )
    if decision == "warn":
        save_baseline(root, "tool", entity_key, current_record)
    return {"action": decision, "drift": drift, "snapshot_id": current_record["snapshot_id"], "baseline_action": "update"}


def build_collision(
    root: pathlib.Path,
    *,
    drift_kind: str,
    decision: str,
    server_id: str | None,
    tool_name: str,
    owners: list[str],
) -> dict[str, Any]:
    entity_key = f"collision::{tool_name}"
    current_record = create_snapshot(
        root,
        "collision",
        entity_key,
        {"tool_name": tool_name, "owners": sorted(owners), "server_id": server_id},
    )
    drift = _record_drift(
        root,
        entity_type="collision",
        entity_key=entity_key,
        server_id=server_id,
        tool_name=tool_name,
        drift_kind=drift_kind,
        decision=decision,
        baseline=None,
        current_snapshot={"tool_name": tool_name, "owners": sorted(owners)},
        current_record=current_record,
        diff=_diff_payload(drift_kind, None, {"tool_name": tool_name, "owners": sorted(owners)}),
        status="approved",
    )
    return drift


def export_incident(root: pathlib.Path, selector: str, *, output_path: pathlib.Path | None = None, format_name: str = "zip") -> pathlib.Path:
    selector = selector.strip()
    if ":" not in selector:
        raise SystemExit("selector must use one of: event:<id>, session:<id>, chain:<id>, drift:<id>")
    kind, value = selector.split(":", 1)
    events = _query_all_events(root)
    drifts: list[dict[str, Any]] = []
    if kind == "event":
        events = [event for event in events if event.get("event_id") == value]
    elif kind == "session":
        events = [event for event in events if event.get("session_id") == value]
    elif kind == "chain":
        events = [
            event for event in events
            if event.get("chain_id") == value or any(alert.get("chain_id") == value for alert in event.get("chain_alerts", []))
        ]
    elif kind == "drift":
        drift = get_drift(root, value)
        drifts = [drift] if drift else []
        events = [event for event in events if event.get("drift_id") == value]
    else:
        raise SystemExit("unknown selector prefix")

    drift_ids = {event.get("drift_id") for event in events if event.get("drift_id")}
    if not drifts:
        drifts = [get_drift(root, drift_id) for drift_id in drift_ids if drift_id]
        drifts = [drift for drift in drifts if drift]
    artifacts = sorted({artifact for event in events for artifact in event.get("artifacts_touched", [])})
    manifest = {
        "selector": selector,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "event_count": len(events),
        "drift_count": len(drifts),
        "artifact_count": len(artifacts),
    }
    summary_lines = [
        "# Runwall Incident Bundle",
        "",
        f"- Selector: `{selector}`",
        f"- Events: {len(events)}",
        f"- Drift records: {len(drifts)}",
        f"- Artifacts: {len(artifacts)}",
    ]
    payloads = {
        "manifest.json": json.dumps(manifest, indent=2) + "\n",
        "summary.md": "\n".join(summary_lines) + "\n",
        "events.jsonl": "".join(json.dumps(event, separators=(",", ":")) + "\n" for event in events),
        "drifts.json": json.dumps(drifts, indent=2) + "\n",
        "artifacts.json": json.dumps(artifacts, indent=2) + "\n",
    }
    if output_path is None:
        suffix = ".zip" if format_name == "zip" else ".json"
        output_path = state_dir(root) / f"incident-{kind}-{value}{suffix}"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if format_name == "json":
        output_path.write_text(json.dumps(payloads, indent=2), encoding="utf-8")
        return output_path
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for name, content in payloads.items():
            bundle.writestr(name, content)
    output_path.write_bytes(buffer.getvalue())
    return output_path


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Runwall forensics utilities")
    subparsers = parser.add_subparsers(dest="command", required=True)

    export_parser = subparsers.add_parser("export", help="Export a masked incident bundle")
    export_parser.add_argument("--root", required=True)
    export_parser.add_argument("selector")
    export_parser.add_argument("--output")
    export_parser.add_argument("--format", choices=["zip", "json"], default="zip")

    args = parser.parse_args(argv)
    if args.command == "export":
        output = export_incident(
            pathlib.Path(args.root),
            args.selector,
            output_path=pathlib.Path(args.output) if args.output else None,
            format_name=args.format,
        )
        print(output)
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
