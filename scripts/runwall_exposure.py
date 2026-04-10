#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
from functools import lru_cache
from typing import Any

import runwall_flow
import runwall_approvals


PUBLIC_VISIBILITY_RE = re.compile(
    r"""(?ix)
    \b(
        public(?:ly)?
        |world[-_ ]readable
        |public[-_ ]repo
        |public[-_ ]channel
        |allusers
        |allauthenticatedusers
        |anon(?:ymous)?
    )\b
    """
)
EXTERNAL_SHARED_RE = re.compile(r"(?ix)\b(external(?:ly)?[-_ ]shared|shared[-_ ]externally|shared[-_ ]channel)\b")
PRIVATE_VISIBILITY_RE = re.compile(r"(?ix)\b(private(?:ly)?|private[-_ ]channel|dm|direct[-_ ]message)\b")
INTERNAL_VISIBILITY_RE = re.compile(r"(?ix)\b(internal|org[-_ ]internal|team[-_ ]only|members[-_ ]only)\b")
COMMENT_OPERATION_RE = re.compile(r"(?ix)\b(comment|review[ -]?comment|reply|post[ -]?message|chat\.postmessage|conversations\.replies)\b")
PUBLISH_OPERATION_RE = re.compile(r"(?ix)\b(push|publish|upload|share|attach|export|create)\b")
GITHUB_GIST_RE = re.compile(r"(?ix)\bgh\s+gist\s+create\b|gist\.github(?:usercontent)?\.com")
GITHUB_COMMENT_RE = re.compile(
    r"""(?ix)
    \bgh\s+(?:issue|pr)\s+comment\b
    |/issues/\d+/comments\b
    |/pulls/\d+/reviews\b
    |/pulls/\d+/comments\b
    |mcp__.*github.*(?:comment|review)
    """
)
GITHUB_REPO_RE = re.compile(
    r"""(?ix)
    \bgh\s+repo\s+(?:create|edit)\b
    |\bgit\s+push\b[^\n\r]{0,200}github\.com
    |mcp__.*github
    """
)
SLACK_CHANNEL_RE = re.compile(
    r"""(?ix)
    \bslack\b[^\n\r]{0,200}\b(?:chat\.postmessage|conversations\.replies|post[ -]?message|reply)\b
    |mcp__.*slack.*(?:post|message|reply)
    """
)
WEBHOOK_RE = re.compile(
    r"(?ix)(?:discord\.com/api/webhooks|hooks\.slack\.com/services|webhook\.office\.com|outlook\.office\.com/webhook|chat\.googleapis\.com/v1/spaces/|api\.telegram\.org/bot)"
)
PUBLIC_BUCKET_RE = re.compile(
    r"""(?ix)
    \b(?:aws\s+s3\s+cp|aws\s+s3api\s+put-object-acl|gsutil\s+(?:cp|acl\s+ch)|az\s+storage\s+blob\s+upload)\b
    [^\n\r]{0,220}
    (?:
        --acl(?:=|\s+)public-read
        |allusers:
        |allauthenticatedusers:
        |x-goog-acl:[^\n\r]{0,40}public-read
        |blobpublicaccess
    )
    """
)
PUBLIC_ARTIFACT_RE = re.compile(r"(?ix)\b(?:pages\s+deploy|github\s+pages|public/|dist/|build/|release/|artifacts?/)\b")
SECRET_INLINE_RE = re.compile(
    r"""(?ix)
    (?:database_url|redis_url|amqp_url|mongodb_uri|postgres_url)\s*[:=]\s*["'][^"']+["']
    |authorization\s*:\s*bearer\s+[A-Za-z0-9._-]{16,}
    |postgres(?:ql)?://[^\s"']+:[^\s"']+@
    |mysql://[^\s"']+:[^\s"']+@
    |mongodb(?:\+srv)?://[^\s"']+:[^\s"']+@
    |amqp://[^\s"']+:[^\s"']+@
    """
)
SECRET_PATH_RE = re.compile(
    r"""(?ix)
    (?:^|[=\s'"])
    (
        \.env(?:\.[A-Za-z0-9._-]+)?
        |\.aws/(?:credentials|config)
        |\.ssh/(?:id_(?:rsa|dsa|ecdsa|ed25519)|config|known_hosts)
        |\.kube/config
        |\.npmrc
        |\.pypirc
        |\.netrc
        |[^/\s"'=]*(?:secrets?|credentials?)\.(?:json|ya?ml|toml|env)
        |[^/\s"'=]*\.(?:pem|p12|pfx|key)
    )
    (?:$|[\s'"])
    """
)


def _runwall_home(root: pathlib.Path) -> pathlib.Path:
    return pathlib.Path(
        os.environ.get(
            "RUNWALL_HOME",
            os.environ.get("SECURE_CLAUDE_CODE_HOME", str(root)),
        )
    )


def _state_dir(root: pathlib.Path) -> pathlib.Path:
    return _runwall_home(root) / "state"


def _store_path(root: pathlib.Path) -> pathlib.Path:
    return _state_dir(root) / "exposure.json"


def _load_store(root: pathlib.Path) -> dict[str, Any]:
    path = _store_path(root)
    if not path.exists():
        return {"version": 1, "sessions": {}}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"version": 1, "sessions": {}}
    if not isinstance(payload, dict):
        return {"version": 1, "sessions": {}}
    payload.setdefault("version", 1)
    payload.setdefault("sessions", {})
    return payload


def _save_store(root: pathlib.Path, store: dict[str, Any]) -> None:
    path = _store_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(store, indent=2, sort_keys=True) + "\n", encoding="utf-8")


@lru_cache(maxsize=16)
def _live_token_patterns(home: str) -> list[re.Pattern[str]]:
    path = pathlib.Path(home) / "config" / "live-token-patterns.regex"
    patterns: list[re.Pattern[str]] = []
    if not path.exists():
        return patterns
    for line in path.read_text(encoding="utf-8").splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue
        try:
            patterns.append(re.compile(raw))
        except re.error:
            continue
    return patterns


def _has_live_token(root: pathlib.Path, payload: str) -> bool:
    for pattern in _live_token_patterns(str(_runwall_home(root))):
        if pattern.search(payload):
            return True
    return False


def _host(payload: str) -> str | None:
    match = re.search(r"(?i)https?://(?P<host>[^/\s:\"']+)", payload)
    if match:
        return match.group("host").lower()
    if "github.com" in payload.lower():
        return "github.com"
    if "slack" in payload.lower():
        return "slack.com"
    return None


def _operation(payload: str, matcher: str) -> str | None:
    lowered_matcher = matcher.lower()
    if "comment" in lowered_matcher or COMMENT_OPERATION_RE.search(payload):
        return "comment"
    if re.search(r"(?ix)\b(?:post[ -]?message|reply)\b", payload):
        return "post"
    if re.search(r"(?ix)\bgit\s+push\b", payload):
        return "push"
    if re.search(r"(?ix)\b(?:upload|attach)\b", payload):
        return "upload"
    if re.search(r"(?ix)\bpublish\b", payload):
        return "publish"
    if PUBLISH_OPERATION_RE.search(payload):
        return "share"
    return None


def _visibility_from_payload(payload: str) -> str:
    if PUBLIC_VISIBILITY_RE.search(payload):
        return "public"
    if EXTERNAL_SHARED_RE.search(payload):
        return "external-shared"
    if INTERNAL_VISIBILITY_RE.search(payload):
        return "internal"
    if PRIVATE_VISIBILITY_RE.search(payload):
        return "private"
    return "unknown"


def detect_surface(matcher: str, payload: str) -> dict[str, Any] | None:
    lowered_matcher = matcher.lower()
    visibility = _visibility_from_payload(payload)
    if WEBHOOK_RE.search(payload):
        return {
            "surface_class": "webhook",
            "visibility": "external-shared",
            "operation": _operation(payload, matcher) or "post",
            "target": _host(payload) or "webhook",
            "platform": "webhook",
        }
    if PUBLIC_BUCKET_RE.search(payload):
        return {
            "surface_class": "object-store",
            "visibility": "public",
            "operation": _operation(payload, matcher) or "upload",
            "target": _host(payload) or "object-store",
            "platform": "storage",
        }
    if (GITHUB_GIST_RE.search(payload) or "gist" in lowered_matcher) and (
        "--public" in payload.lower() or visibility == "public"
    ):
        return {
            "surface_class": "github-gist",
            "visibility": "public",
            "operation": _operation(payload, matcher) or "publish",
            "target": _host(payload) or "gist.github.com",
            "platform": "github",
        }
    if GITHUB_COMMENT_RE.search(payload) or ("mcp__github" in lowered_matcher and "comment" in lowered_matcher):
        return {
            "surface_class": "github-comment",
            "visibility": visibility,
            "operation": _operation(payload, matcher) or "comment",
            "target": _host(payload) or "github.com",
            "platform": "github",
        }
    if GITHUB_REPO_RE.search(payload) or (
        "mcp__github" in lowered_matcher
        and visibility != "unknown"
        and any(token in lowered_matcher for token in ("repo", "release", "push", "publish"))
    ):
        return {
            "surface_class": "github-repo",
            "visibility": visibility,
            "operation": _operation(payload, matcher) or "push",
            "target": _host(payload) or "github.com",
            "platform": "github",
        }
    if SLACK_CHANNEL_RE.search(payload) or (
        "mcp__slack" in lowered_matcher and any(token in lowered_matcher for token in ("post", "message", "reply", "send"))
    ):
        return {
            "surface_class": "slack-channel",
            "visibility": visibility,
            "operation": _operation(payload, matcher) or "post",
            "target": _host(payload) or "slack.com",
            "platform": "slack",
        }
    if visibility == "public" and PUBLIC_ARTIFACT_RE.search(payload):
        return {
            "surface_class": "public-artifact",
            "visibility": visibility,
            "operation": _operation(payload, matcher) or "publish",
            "target": _host(payload) or "artifact",
            "platform": "artifact",
        }
    return None


def _repo_scope(root: pathlib.Path) -> str:
    try:
        return str(root.resolve(strict=False))
    except Exception:
        return str(root)


def _session_labels(root: pathlib.Path, context: dict[str, Any] | None) -> set[str]:
    session_id = str((context or {}).get("session_id") or "")
    if not session_id:
        return set()
    session = runwall_flow.explain_session(root, session_id)
    if not isinstance(session, dict):
        return set()
    return {
        str(item.get("label"))
        for item in session.get("labels", [])
        if isinstance(item, dict) and item.get("label")
    }


def _has_direct_sensitive(root: pathlib.Path, payload: str) -> bool:
    return _has_live_token(root, payload) or bool(SECRET_INLINE_RE.search(payload) or SECRET_PATH_RE.search(payload))


def _sensitivity_mode(*, direct_sensitive: bool, sensitive_labels: list[str]) -> str | None:
    if direct_sensitive:
        return "direct"
    if sensitive_labels:
        return "session"
    return None


def approval_fingerprint(
    *,
    surface_class: str,
    target: str,
    operation: str,
    visibility: str,
    repo: str,
    runtime: str | None,
    sensitivity_mode: str,
) -> str:
    payload = {
        "surface_class": surface_class,
        "target": target,
        "operation": operation,
        "visibility": visibility,
        "repo": repo,
        "runtime": runtime or "",
        "sensitivity_mode": sensitivity_mode,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def _prompt_seen(root: pathlib.Path, session_id: str, fingerprint: str) -> bool:
    if not session_id:
        return False
    session = _load_store(root).get("sessions", {}).get(session_id, {})
    prompted = session.get("prompted", [])
    return fingerprint in prompted if isinstance(prompted, list) else False


def _record_prompt(root: pathlib.Path, session_id: str, fingerprint: str) -> None:
    if not session_id:
        return
    store = _load_store(root)
    session = store.setdefault("sessions", {}).setdefault(session_id, {"prompted": [], "updated_at": ""})
    prompted = [item for item in session.get("prompted", []) if isinstance(item, str)]
    if fingerprint not in prompted:
        prompted.append(fingerprint)
    session["prompted"] = prompted[-200:]
    session["updated_at"] = runwall_flow.utc_now()
    _save_store(root, store)


def _hit(module: str, decision: str, identity: dict[str, Any], reason: str, safer: str) -> dict[str, Any]:
    return {
        "module": module,
        "name": module.replace("-", " ").title(),
        "category": "exposure-trust",
        "family": "Runtime, Network & Egress",
        "decision": decision,
        "exit_code": 2 if decision == "block" else 0,
        "output": reason,
        "metadata": {
            "reason": reason,
            "confidence": 0.96 if decision == "block" else 0.82,
            "safer_alternative": safer,
            "exposure_identity": identity,
        },
    }


def assess_command(root: pathlib.Path, matcher: str, payload: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
    identity = detect_surface(matcher, payload)
    if not identity:
        return {"identity": None, "hit": None}

    labels = _session_labels(root, context)
    sensitive_labels = sorted(
        label
        for label in labels
        if label in {"secret_data", "prod_data", "browser_session", "browser_export"}
    )
    direct_sensitive = _has_direct_sensitive(root, payload)
    sensitivity_mode = _sensitivity_mode(direct_sensitive=direct_sensitive, sensitive_labels=sensitive_labels)
    if sensitivity_mode is None:
        return {"identity": None, "hit": None}

    repo_scope = _repo_scope(root)
    runtime = str((context or {}).get("runtime") or "")
    session_id = str((context or {}).get("session_id") or "")
    operation = str(identity.get("operation") or "")
    target = str(identity["target"])
    visibility = str(identity["visibility"])
    surface_class = str(identity["surface_class"])
    fingerprint = approval_fingerprint(
        surface_class=surface_class,
        target=target,
        operation=operation,
        visibility=visibility,
        repo=repo_scope,
        runtime=runtime,
        sensitivity_mode=sensitivity_mode,
    )
    identity = {
        **identity,
        "direct_sensitive": direct_sensitive,
        "session_labels": sensitive_labels,
        "sensitivity_mode": sensitivity_mode,
        "fingerprint": fingerprint,
    }

    if visibility in {"public", "external-shared"} and (direct_sensitive or sensitive_labels):
        reason = f"Blocked sensitive data flow to {visibility} exposure surface {surface_class} at {target}."
        if direct_sensitive and sensitive_labels:
            reason = f"Blocked direct and session-derived sensitive data flow to {visibility} exposure surface {surface_class} at {target}."
        elif direct_sensitive:
            reason = f"Blocked direct sensitive content from being sent to {visibility} exposure surface {surface_class} at {target}."
        else:
            reason = f"Blocked session-derived sensitive data flow to {visibility} exposure surface {surface_class} at {target}."
        return {
            "identity": identity,
            "hit": _hit(
                "public-exposure-surface-guard",
                "block",
                identity,
                reason,
                "Keep secrets, production data, and session material inside reviewed private surfaces and move any public sharing to a sanitized manual step.",
            ),
        }

    if visibility == "unknown" and surface_class in {"github-comment", "github-repo", "slack-channel"} and (direct_sensitive or sensitive_labels):
        approval_assessment = runwall_approvals.assess_match(
            root,
            kind="exposure",
            target=surface_class,
            value=fingerprint,
            runtime=runtime or None,
            repo=repo_scope,
            agent_id=session_id or None,
            fingerprint=fingerprint,
            consume=False,
        )
        if approval_assessment.get("approval"):
            return {"identity": identity, "hit": None}
        approval_hit = approval_assessment.get("hit")
        if approval_hit:
            return {"identity": identity, "hit": approval_hit}
        if _prompt_seen(root, session_id, fingerprint):
            return {"identity": identity, "hit": None}
        _record_prompt(root, session_id, fingerprint)
        return {
            "identity": identity,
            "hit": _hit(
                "broad-exposure-surface-guard",
                "prompt",
                identity,
                f"Review required before sending potentially sensitive material to broad exposure surface {surface_class} at {target} without confirmed private visibility.",
                "Confirm the destination is private and appropriate, or switch to a reviewed internal channel before sending the content.",
            ),
        }

    return {"identity": identity, "hit": None}
