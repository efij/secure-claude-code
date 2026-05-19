#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
from functools import lru_cache
from typing import Any

import stallion_approvals
import stallion_flow


PUBLIC_VISIBILITY_RE = re.compile(
    r"""(?ix)
    \b(
        public(?:ly)?
        |world[-_ ]readable
        |public[-_ ]repo
        |public[-_ ]channel
        |public[-_ ]share
        |public[-_ ]link
        |anyone(?:\s+with\s+the\s+link)?
        |allusers
        |allauthenticatedusers
        |anon(?:ymous)?
        |discoverable
    )\b
    """
)
EXTERNAL_SHARED_RE = re.compile(
    r"(?ix)\b(external(?:ly)?[-_ ]shared|shared[-_ ]externally|shared[-_ ]channel|external[-_ ]guest|outside[-_ ]guest)\b"
)
PRIVATE_VISIBILITY_RE = re.compile(r"(?ix)\b(private(?:ly)?|private[-_ ]channel|dm|direct[-_ ]message)\b")
INTERNAL_VISIBILITY_RE = re.compile(r"(?ix)\b(internal|org[-_ ]internal|team[-_ ]only|members[-_ ]only)\b")
COMMENT_OPERATION_RE = re.compile(r"(?ix)\b(comment|review[ -]?comment|reply)\b")
POST_OPERATION_RE = re.compile(r"(?ix)\b(post[ -]?message|chat\.postmessage|conversations\.replies|reply)\b")
UPLOAD_OPERATION_RE = re.compile(r"(?ix)\b(upload|attach|attachment|file[-_ ]?upload|put[-_ ]file)\b")
SEND_OPERATION_RE = re.compile(r"(?ix)\b(send|forward|mail)\b")
SHARE_OPERATION_RE = re.compile(r"(?ix)\b(share|shared|share[-_ ]link|link[-_ ]sharing|grant\s+access)\b")
PUBLISH_OPERATION_RE = re.compile(r"(?ix)\b(push|publish|export)\b")
READ_ONLY_MATCHER_RE = re.compile(r"(?ix)\b(get|list|fetch|read|history|status|search|open|view|preview|diff)\b")
PUBLIC_SHARE_LINK_RE = re.compile(
    r"""(?ix)
    \b(
        anyone(?:\s+with\s+the\s+link)?
        |public[-_ ]link
        |public[-_ ]share
        |share(?:d)?[-_ ]public(?:ly)?
        |link[-_ ]sharing(?:\s+on)?
        |discoverable
    )\b
    """
)
GUEST_INVITE_RE = re.compile(
    r"""(?ix)
    \b(?:invite|add|share)\b[^\n\r]{0,120}\b(?:guest|external|outside|vendor|shared[-_ ]externally)\b
    |mcp__.*(?:invite|member|share)
    """
)
WEBHOOK_ADMIN_RE = re.compile(
    r"""(?ix)
    \b(?:create|add|update|edit|patch|set|configure|retarget)\b[^\n\r]{0,140}\bwebhook\b
    |\bgh\s+api\b[^\n\r]{0,220}/hooks\b
    |mcp__.*(?:create|update|edit).*(?:webhook)
    """
)
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
GITHUB_REPO_ADMIN_RE = re.compile(
    r"""(?ix)
    \bgh\s+repo\s+edit\b[^\n\r]{0,180}\b--visibility\b
    |mcp__.*github.*(?:repo|repository).*(?:edit|update|create)
    """
)
SLACK_CHANNEL_RE = re.compile(
    r"""(?ix)
    \bslack\b[^\n\r]{0,200}\b(?:chat\.postmessage|conversations\.replies|post[ -]?message|reply)\b
    |mcp__.*slack.*(?:post|message|reply|send)
    """
)
GOOGLE_DOCS_RE = re.compile(r"(?ix)(?:docs\.google\.com|mcp__.*(?:google_docs|gdocs|docs))")
GOOGLE_DRIVE_RE = re.compile(r"(?ix)(?:drive\.google\.com|mcp__.*(?:google_drive|gdrive|drive))")
NOTION_RE = re.compile(r"(?ix)(?:notion\.so|api\.notion\.com|mcp__.*notion)")
ATLASSIAN_RE = re.compile(r"(?ix)(?:atlassian\.net|mcp__.*(?:jira|confluence)|\bjira\b|\bconfluence\b)")
ZENDESK_RE = re.compile(r"(?ix)(?:zendesk\.com|mcp__.*zendesk)")
LINEAR_RE = re.compile(r"(?ix)(?:linear\.app|mcp__.*linear)")
EMAIL_RE = re.compile(r"(?ix)(?:gmail|outlook|sendgrid|mailgun|mcp__.*(?:email|gmail|mail|outlook|sendgrid|mailgun))")
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
OBJECT_STORE_ADMIN_RE = re.compile(
    r"""(?ix)
    \b(
        aws\s+s3api\s+(?:put-bucket-acl|put-object-acl|put-public-access-block)
        |aws\s+s3\s+website
        |gsutil\s+(?:acl\s+ch|iam\s+ch|web\s+set)
        |az\s+storage\s+(?:container\s+set-permission|blob\s+service-properties\s+update)
    )\b
    [^\n\r]{0,240}
    (?:
        public-read
        |public-read-write
        |allUsers:
        |allAuthenticatedUsers:
        |blobpublicaccess
        |--public-access
    )
    """
)
PUBLIC_ARTIFACT_RE = re.compile(r"(?ix)\b(?:pages\s+deploy|github\s+pages|public/|dist/|build/|release/|artifacts?/)\b")
SECRET_INLINE_RE = re.compile(
    r"""(?ix)
    (?:database_url|redis_url|amqp_url|mongodb_uri|postgres_url)\s*[:=]\s*["'][^"']+["']
    |authorization\s*:\s*bearer\s+[A-Za-z0-9._-]{12,}
    |postgres(?:ql)?://[^\s"']+:[^\s"']+@
    |mysql://[^\s"']+:[^\s"']+@
    |mongodb(?:\+srv)?://[^\s"']+:[^\s"']+@
    |amqp://[^\s"']+:[^\s"']+@
    """
)
SECRET_URL_RE = re.compile(
    r"(?ix)[?&](?:access_token|token|auth(?:orization)?|api[_-]?key|key|sig|signature)=[A-Za-z0-9._%:-]{12,}"
)
SECRET_HEADER_RE = re.compile(
    r"(?ix)\b(?:x-api-key|api-key|x-auth-token|authorization)\b\s*[:=]\s*[A-Za-z0-9._ -]{12,}"
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
SECRET_FILENAME_RE = re.compile(
    r"""(?ix)
    (?:^|[=\s'"])
    (
        [^/\s"'=]*(?:token|secret|credential|api[_-]?key|access[_-]?key)[^/\s"'=]*\.(?:txt|json|csv|log|env)
    )
    (?:$|[\s'"])
    """
)


def _stallion_home(root: pathlib.Path) -> pathlib.Path:
    return pathlib.Path(
        os.environ.get(
            "STALLION_HOME",
            os.environ.get("STALLION_HOME", str(root)),
        )
    )


def _state_dir(root: pathlib.Path) -> pathlib.Path:
    return _stallion_home(root) / "state"


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
    for pattern in _live_token_patterns(str(_stallion_home(root))):
        if pattern.search(payload):
            return True
    return False


def _profile(context: dict[str, Any] | None) -> str:
    return str((context or {}).get("profile") or "balanced").lower()


def _host(payload: str) -> str | None:
    match = re.search(r"(?i)https?://(?P<host>[^/\s:\"']+)", payload)
    if match:
        return match.group("host").lower()
    lowered = payload.lower()
    known_hosts = (
        "github.com",
        "slack.com",
        "docs.google.com",
        "drive.google.com",
        "notion.so",
        "api.notion.com",
        "atlassian.net",
        "zendesk.com",
        "linear.app",
        "gmail.com",
        "outlook.com",
        "sendgrid.com",
        "mailgun.com",
        "pinecone",
        "qdrant",
        "weaviate",
        "dropbox.com",
        "onedrive.live.com",
        "icloud.com",
    )
    for host in known_hosts:
        if host in lowered:
            return host
    return None


def _operation(payload: str, matcher: str) -> str | None:
    lowered_matcher = matcher.lower()
    if "comment" in lowered_matcher or COMMENT_OPERATION_RE.search(payload):
        return "comment"
    if "upload" in lowered_matcher or "attach" in lowered_matcher or UPLOAD_OPERATION_RE.search(payload):
        return "upload"
    if "post" in lowered_matcher or "reply" in lowered_matcher or POST_OPERATION_RE.search(payload):
        return "post"
    if "send" in lowered_matcher or "mail" in lowered_matcher or SEND_OPERATION_RE.search(payload):
        return "send"
    if re.search(r"(?ix)\bgit\s+push\b", payload):
        return "push"
    if "publish" in lowered_matcher or re.search(r"(?ix)\bpublish\b", payload):
        return "publish"
    if "share" in lowered_matcher or SHARE_OPERATION_RE.search(payload):
        return "share"
    if PUBLISH_OPERATION_RE.search(payload):
        return "share"
    return None


def _is_read_only(matcher: str, payload: str) -> bool:
    lowered_matcher = matcher.lower()
    if not READ_ONLY_MATCHER_RE.search(lowered_matcher):
        return False
    return _operation(payload, matcher) is None


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
    if _is_read_only(matcher, payload):
        return None
    lowered_matcher = matcher.lower()
    visibility = _visibility_from_payload(payload)
    operation = _operation(payload, matcher)
    if operation is None:
        return None

    if WEBHOOK_RE.search(payload):
        return {
            "surface_class": "webhook",
            "visibility": "external-shared",
            "operation": operation or "post",
            "target": _host(payload) or "webhook",
            "platform": "webhook",
        }
    if PUBLIC_BUCKET_RE.search(payload):
        return {
            "surface_class": "object-store",
            "visibility": "public",
            "operation": operation or "upload",
            "target": _host(payload) or "object-store",
            "platform": "storage",
        }
    if (GITHUB_GIST_RE.search(payload) or "gist" in lowered_matcher) and (
        "--public" in payload.lower() or visibility == "public"
    ):
        return {
            "surface_class": "github-gist",
            "visibility": "public",
            "operation": operation or "publish",
            "target": _host(payload) or "gist.github.com",
            "platform": "github",
        }
    if GITHUB_COMMENT_RE.search(payload) or ("mcp__github" in lowered_matcher and "comment" in lowered_matcher):
        return {
            "surface_class": "github-comment",
            "visibility": visibility,
            "operation": operation or "comment",
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
            "operation": operation or "push",
            "target": _host(payload) or "github.com",
            "platform": "github",
        }
    if SLACK_CHANNEL_RE.search(payload) or (
        "mcp__slack" in lowered_matcher and any(token in lowered_matcher for token in ("post", "message", "reply", "send"))
    ):
        return {
            "surface_class": "slack-channel",
            "visibility": visibility,
            "operation": operation or "post",
            "target": _host(payload) or "slack.com",
            "platform": "slack",
        }
    if (GOOGLE_DRIVE_RE.search(payload) or "google_drive" in lowered_matcher or "gdrive" in lowered_matcher) and operation in {"upload", "share", "send"}:
        return {
            "surface_class": "file-share",
            "visibility": visibility,
            "operation": operation,
            "target": _host(payload) or "drive.google.com",
            "platform": "google-drive",
        }
    if (GOOGLE_DOCS_RE.search(payload) or "google_docs" in lowered_matcher or "gdocs" in lowered_matcher) and operation in {"comment", "share", "post", "send"}:
        return {
            "surface_class": "doc-surface",
            "visibility": visibility,
            "operation": operation,
            "target": _host(payload) or "docs.google.com",
            "platform": "google-docs",
        }
    if (NOTION_RE.search(payload) or "notion" in lowered_matcher) and operation in {"comment", "share", "post", "send", "upload"}:
        return {
            "surface_class": "shared-note",
            "visibility": visibility,
            "operation": operation,
            "target": _host(payload) or "notion.so",
            "platform": "notion",
        }
    if (
        ATLASSIAN_RE.search(payload)
        or ZENDESK_RE.search(payload)
        or LINEAR_RE.search(payload)
        or any(token in lowered_matcher for token in ("jira", "confluence", "zendesk", "linear"))
    ) and operation in {"comment", "share", "post", "upload", "send"}:
        return {
            "surface_class": "ticket-surface",
            "visibility": visibility,
            "operation": operation,
            "target": _host(payload) or "ticket-surface",
            "platform": (
                "jira-confluence"
                if ATLASSIAN_RE.search(payload)
                else "zendesk"
                if ZENDESK_RE.search(payload)
                else "linear"
            ),
        }
    if (EMAIL_RE.search(payload) or any(token in lowered_matcher for token in ("email", "gmail", "mail", "outlook", "sendgrid", "mailgun"))) and operation in {"send", "upload", "share"}:
        return {
            "surface_class": "email-send",
            "visibility": visibility,
            "operation": operation,
            "target": _host(payload) or "email",
            "platform": "email",
        }
    if visibility == "public" and PUBLIC_ARTIFACT_RE.search(payload):
        return {
            "surface_class": "public-artifact",
            "visibility": visibility,
            "operation": operation or "publish",
            "target": _host(payload) or "artifact",
            "platform": "artifact",
        }
    return None


def detect_precursor(matcher: str, payload: str) -> dict[str, Any] | None:
    if _is_read_only(matcher, payload):
        return None
    lowered_matcher = matcher.lower()
    combined = f"{matcher} {payload}"
    visibility = _visibility_from_payload(payload)
    if WEBHOOK_ADMIN_RE.search(combined) or (
        "webhook" in lowered_matcher and any(token in lowered_matcher for token in ("create", "update", "edit", "add"))
    ):
        return {
            "surface_class": "webhook-admin",
            "visibility": "external-shared",
            "operation": "retarget",
            "target": _host(payload) or "webhook",
            "platform": "webhook",
        }
    if OBJECT_STORE_ADMIN_RE.search(payload):
        return {
            "surface_class": "object-store-admin",
            "visibility": "public",
            "operation": "acl-change",
            "target": _host(payload) or "object-store",
            "platform": "storage",
        }
    if (
        GITHUB_REPO_ADMIN_RE.search(combined)
        or ("mcp__github" in lowered_matcher and "repo" in lowered_matcher and visibility in {"public", "external-shared"})
    ) and visibility in {"public", "external-shared"}:
        return {
            "surface_class": "github-repo-admin",
            "visibility": visibility,
            "operation": "visibility-change",
            "target": _host(payload) or "github.com",
            "platform": "github",
        }
    if (
        PUBLIC_SHARE_LINK_RE.search(combined)
        or ("share" in lowered_matcher and "link" in lowered_matcher and visibility in {"public", "external-shared"})
    ):
        target = _host(payload)
        if (
            target
            or GOOGLE_DOCS_RE.search(payload)
            or GOOGLE_DRIVE_RE.search(payload)
            or NOTION_RE.search(payload)
            or any(token in lowered_matcher for token in ("google_docs", "gdocs", "google_drive", "gdrive", "drive", "notion"))
        ):
            return {
                "surface_class": "share-link-admin",
                "visibility": visibility if visibility != "unknown" else "public",
                "operation": "share-link",
                "target": target or "shared-surface",
                "platform": (
                    "google-drive"
                    if GOOGLE_DRIVE_RE.search(payload) or any(token in lowered_matcher for token in ("google_drive", "gdrive", "drive"))
                    else "google-docs"
                    if GOOGLE_DOCS_RE.search(payload) or any(token in lowered_matcher for token in ("google_docs", "gdocs"))
                    else "notion"
                    if NOTION_RE.search(payload) or "notion" in lowered_matcher
                    else "shared-surface"
                ),
            }
    if (GUEST_INVITE_RE.search(combined) or any(token in lowered_matcher for token in ("invite", "member", "share"))) and re.search(
        r"(?ix)\b(?:guest|external|outside|vendor|shared[-_ ]externally)\b",
        combined,
    ):
        return {
            "surface_class": "guest-invite",
            "visibility": "external-shared",
            "operation": "invite",
            "target": _host(payload) or "shared-surface",
            "platform": "shared-surface",
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
    session = stallion_flow.explain_session(root, session_id)
    if not isinstance(session, dict):
        return set()
    return {
        str(item.get("label"))
        for item in session.get("labels", [])
        if isinstance(item, dict) and item.get("label")
    }


def _has_direct_sensitive(root: pathlib.Path, payload: str) -> bool:
    return _has_live_token(root, payload) or bool(
        SECRET_INLINE_RE.search(payload)
        or SECRET_URL_RE.search(payload)
        or SECRET_HEADER_RE.search(payload)
        or SECRET_PATH_RE.search(payload)
        or SECRET_FILENAME_RE.search(payload)
    )


def _sensitivity_mode(*, direct_sensitive: bool, sensitive_labels: list[str], default: str | None = None) -> str | None:
    if direct_sensitive:
        return "direct"
    if sensitive_labels:
        return "session"
    return default


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
    session["updated_at"] = stallion_flow.utc_now()
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


def _prompt_with_approval(
    root: pathlib.Path,
    *,
    identity: dict[str, Any],
    module: str,
    reason: str,
    safer: str,
    session_id: str,
    repo_scope: str,
    runtime: str,
) -> dict[str, Any]:
    fingerprint = str(identity["fingerprint"])
    approval_assessment = stallion_approvals.assess_match(
        root,
        kind="exposure",
        target=str(identity["surface_class"]),
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
        "hit": _hit(module, "prompt", identity, reason, safer),
    }


def assess_command(root: pathlib.Path, matcher: str, payload: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
    profile = _profile(context)
    labels = _session_labels(root, context)
    sensitive_labels = sorted(
        label
        for label in labels
        if label in {"secret_data", "prod_data", "browser_session", "browser_export"}
    )
    direct_sensitive = _has_direct_sensitive(root, payload)
    repo_scope = _repo_scope(root)
    runtime = str((context or {}).get("runtime") or "")
    session_id = str((context or {}).get("session_id") or "")

    precursor = detect_precursor(matcher, payload)
    if precursor:
        precursor_balanced_surfaces = {"github-repo-admin", "share-link-admin", "object-store-admin"}
        surface_class = str(precursor["surface_class"])
        visibility = str(precursor["visibility"])
        sensitivity_mode = _sensitivity_mode(
            direct_sensitive=direct_sensitive,
            sensitive_labels=sensitive_labels,
            default="precursor",
        )
        fingerprint = approval_fingerprint(
            surface_class=surface_class,
            target=str(precursor["target"]),
            operation=str(precursor["operation"]),
            visibility=visibility,
            repo=repo_scope,
            runtime=runtime,
            sensitivity_mode=sensitivity_mode or "precursor",
        )
        identity = {
            **precursor,
            "direct_sensitive": direct_sensitive,
            "session_labels": sensitive_labels,
            "sensitivity_mode": sensitivity_mode,
            "fingerprint": fingerprint,
        }
        if visibility in {"public", "external-shared"} and (direct_sensitive or sensitive_labels):
            if profile == "strict" or surface_class in precursor_balanced_surfaces:
                reason = f"Blocked sensitive context from widening {visibility} exposure through precursor surface {surface_class} at {identity['target']}."
                return {
                    "identity": identity,
                    "hit": _hit(
                        "public-exposure-precursor-guard",
                        "block",
                        identity,
                        reason,
                        "Keep visibility changes, sharing toggles, and ACL expansion out of sensitive sessions unless a human explicitly reviews the action.",
                    ),
                }
        should_prompt_precursor = profile == "strict" or (
            profile == "balanced"
            and surface_class in precursor_balanced_surfaces
            and visibility in {"public", "external-shared"}
        )
        if should_prompt_precursor:
            return _prompt_with_approval(
                root,
                identity=identity,
                module="access-widening-precursor-guard",
                reason=(
                    f"Review required before widening access through precursor surface {surface_class} "
                    f"at {identity['target']} with visibility {visibility}."
                ),
                safer="Confirm the destination or audience should actually widen before enabling public sharing, external delivery, or ACL expansion.",
                session_id=session_id,
                repo_scope=repo_scope,
                runtime=runtime,
            )

    identity = detect_surface(matcher, payload)
    if not identity:
        return {"identity": None, "hit": None}

    sensitivity_mode = _sensitivity_mode(direct_sensitive=direct_sensitive, sensitive_labels=sensitive_labels)
    if sensitivity_mode is None:
        return {"identity": None, "hit": None}

    surface_class = str(identity["surface_class"])
    visibility = str(identity["visibility"])
    fingerprint = approval_fingerprint(
        surface_class=surface_class,
        target=str(identity["target"]),
        operation=str(identity.get("operation") or ""),
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
        reason = f"Blocked sensitive data flow to {visibility} exposure surface {surface_class} at {identity['target']}."
        if direct_sensitive and sensitive_labels:
            reason = f"Blocked direct and session-derived sensitive data flow to {visibility} exposure surface {surface_class} at {identity['target']}."
        elif direct_sensitive:
            reason = f"Blocked direct sensitive content from being sent to {visibility} exposure surface {surface_class} at {identity['target']}."
        else:
            reason = f"Blocked session-derived sensitive data flow to {visibility} exposure surface {surface_class} at {identity['target']}."
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

    unknown_prompt_surfaces = {"github-comment", "github-repo", "slack-channel"}
    if profile == "strict":
        unknown_prompt_surfaces.update({"doc-surface", "ticket-surface", "shared-note", "file-share", "email-send"})
    if visibility == "unknown" and surface_class in unknown_prompt_surfaces:
        return _prompt_with_approval(
            root,
            identity=identity,
            module="broad-exposure-surface-guard",
            reason=(
                f"Review required before sending potentially sensitive material to broad exposure surface "
                f"{surface_class} at {identity['target']} without confirmed private visibility."
            ),
            safer="Confirm the destination is private and appropriate, or switch to a reviewed internal channel before sending the content.",
            session_id=session_id,
            repo_scope=repo_scope,
            runtime=runtime,
        )

    return {"identity": identity, "hit": None}
