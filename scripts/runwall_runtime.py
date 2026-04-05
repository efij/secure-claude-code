#!/usr/bin/env python3
from __future__ import annotations

import os
import pathlib
import uuid
from typing import Any


CONTEXT_FIELDS = (
    "runtime",
    "agent_id",
    "subagent_id",
    "parent_agent_id",
    "session_id",
    "background",
)

ENV_FIELD_MAP = {
    "RUNWALL_RUNTIME": "runtime",
    "RUNWALL_AGENT_ID": "agent_id",
    "RUNWALL_SUBAGENT_ID": "subagent_id",
    "RUNWALL_PARENT_AGENT_ID": "parent_agent_id",
    "RUNWALL_SESSION_ID": "session_id",
    "RUNWALL_BACKGROUND": "background",
}

TRUTHY = {"1", "true", "yes", "on"}
FALSY = {"0", "false", "no", "off"}


def normalize_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in TRUTHY:
            return True
        if lowered in FALSY:
            return False
    return None


def _normalize_scalar(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        cleaned = value.strip()
        return cleaned or None
    if isinstance(value, (int, float)):
        return str(value)
    return None


def normalize_context(raw: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {}
    normalized: dict[str, Any] = {}
    for field in CONTEXT_FIELDS:
        value = raw.get(field)
        if field == "background":
            parsed = normalize_bool(value)
            if parsed is not None:
                normalized[field] = parsed
            continue
        scalar = _normalize_scalar(value)
        if scalar is not None:
            normalized[field] = scalar
    return normalized


def context_from_env(env: dict[str, str] | None = None) -> dict[str, Any]:
    source = env or os.environ
    raw = {
        field: source.get(env_name)
        for env_name, field in ENV_FIELD_MAP.items()
        if source.get(env_name) is not None
    }
    return normalize_context(raw)


def context_from_cli_values(values: dict[str, Any] | None) -> dict[str, Any]:
    return normalize_context(values or {})


def merge_contexts(*contexts: dict[str, Any] | None) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for context in contexts:
        merged.update(normalize_context(context))
    return merged


def runtime_default(root: pathlib.Path, explicit: str | None = None) -> str | None:
    if explicit:
        return explicit
    env_runtime = context_from_env().get("runtime")
    if isinstance(env_runtime, str):
        return env_runtime
    if (root / "web" / "gateway").exists():
        return "gateway"
    return None


def with_event_context(
    event: dict[str, Any],
    context: dict[str, Any] | None,
    *,
    default_runtime: str | None = None,
) -> dict[str, Any]:
    enriched = dict(event)
    enriched.setdefault("event_id", uuid.uuid4().hex)
    normalized = normalize_context(context)
    for field, value in normalized.items():
        enriched[field] = value
    if not enriched.get("runtime") and default_runtime:
        enriched["runtime"] = default_runtime
    return enriched


def actor_label(event: dict[str, Any]) -> str:
    if event.get("subagent_id"):
        return "subagent"
    if event.get("agent_id"):
        return "parent"
    return "unknown"
