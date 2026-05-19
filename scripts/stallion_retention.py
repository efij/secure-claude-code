#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import re
from typing import Any

import stallion_exposure
import stallion_flow


RETENTION_ACTION_RE = re.compile(
    r"""(?ix)
    \b(
        backup
        |export
        |sync
        |replicat(?:e|ion)
        |mirror
        |archive
        |snapshot
        |index
        |ingest
        |embed
        |upsert
        |vector
        |transcript
        |persist
    )\b
    """
)
RETENTION_TARGET_RE = re.compile(
    r"""(?ix)
    (
        pinecone
        |qdrant
        |weaviate
        |langsmith
        |dropbox
        |onedrive
        |icloud
        |drive\.google\.com
        |notion\.so
        |s3://
        |gs://
        |blob\.core\.windows\.net
        |remote:
        |mcp__.*(?:backup|export|vector|index|ingest|transcript)
    )
    """
)


def _profile(context: dict[str, Any] | None) -> str:
    return str((context or {}).get("profile") or "balanced").lower()


def _repo_scope(root: pathlib.Path) -> str:
    try:
        return str(root.resolve(strict=False))
    except Exception:
        return str(root)


def _session_labels(root: pathlib.Path, context: dict[str, Any] | None) -> list[str]:
    session_id = str((context or {}).get("session_id") or "")
    if not session_id:
        return []
    session = stallion_flow.explain_session(root, session_id)
    if not isinstance(session, dict):
        return []
    return sorted(
        str(item.get("label"))
        for item in session.get("labels", [])
        if isinstance(item, dict) and item.get("label") in {"secret_data", "prod_data", "browser_session", "browser_export"}
    )


def _hit(module: str, decision: str, identity: dict[str, Any], reason: str, safer: str) -> dict[str, Any]:
    return {
        "module": module,
        "name": module.replace("-", " ").title(),
        "category": "retention-trust",
        "family": "Runtime, Network & Egress",
        "decision": decision,
        "exit_code": 2 if decision == "block" else 0,
        "output": reason,
        "metadata": {
            "reason": reason,
            "confidence": 0.95 if decision == "block" else 0.82,
            "safer_alternative": safer,
            "retention_identity": identity,
        },
    }


def assess_command(root: pathlib.Path, matcher: str, payload: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
    if matcher != "Bash" and not matcher.startswith("mcp__"):
        return {"identity": None, "hit": None}
    if stallion_exposure._is_read_only(matcher, payload):
        return {"identity": None, "hit": None}
    if not RETENTION_ACTION_RE.search(payload) and not RETENTION_TARGET_RE.search(matcher.lower()):
        return {"identity": None, "hit": None}
    if not RETENTION_TARGET_RE.search(payload) and not RETENTION_TARGET_RE.search(matcher.lower()):
        return {"identity": None, "hit": None}

    direct_sensitive = stallion_exposure._has_direct_sensitive(root, payload)
    session_labels = _session_labels(root, context)
    if not direct_sensitive and not session_labels:
        return {"identity": None, "hit": None}

    visibility = stallion_exposure._visibility_from_payload(payload)
    target = stallion_exposure._host(payload) or "external-retention"
    profile = _profile(context)
    identity = {
        "surface_class": "retention-export",
        "visibility": visibility,
        "operation": "replicate",
        "target": target,
        "repo": _repo_scope(root),
        "direct_sensitive": direct_sensitive,
        "session_labels": session_labels,
        "profile": profile,
    }

    if visibility in {"public", "external-shared"}:
        return {
            "identity": identity,
            "hit": _hit(
                "public-retention-export-guard",
                "block",
                identity,
                f"Blocked sensitive durable export to {visibility} retention target {target}.",
                "Keep backups, indexing, and transcript replication private and reviewed when the session already touched sensitive material.",
            ),
        }

    if profile == "strict":
        return {
            "identity": identity,
            "hit": _hit(
                "retention-replication-guard",
                "prompt",
                identity,
                f"Review required before replicating sensitive session material into durable external target {target}.",
                "Confirm the backup, sync, vector index, or transcript target is expected and approved for sensitive data.",
            ),
        }

    return {"identity": identity, "hit": None}
