#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shlex
from datetime import datetime, timezone
from typing import Any


REVIEW_PATH_RE = re.compile(
    r"(?i)(?:^|/)(?:"
    r"\.github/(?:pull_request_template(?:\.[^/]+)?|issue_template(?:/|/[^/]+)?|PULL_REQUEST_TEMPLATE(?:\.[^/]+)?)|"
    r"(?:CHANGELOG|RELEASE_NOTES|SECURITY_REVIEW|REVIEW_NOTES|MERGE_NOTES|APPROVALS?)(?:\.[^/]+)?|"
    r"(?:docs|review|reviews|notes|tasks|tickets|incident|incidents|ops|release)/(?:[^/]+/)*[^/]*"
    r"(?:review|approval|merge|release|changelog|task|ticket|incident|postmortem|signoff)[^/]*\.(?:md|txt|yaml|yml|json)"
    r")$"
)
TEXT_SURFACE_RE = re.compile(r"(?i)\.(?:md|txt|json|yaml|yml)$")
PR_BYPASS_RE = re.compile(
    r"(?i)(?:no review required|merge without review|skip review|ship directly|approve immediately|rubber[- ]stamp|ignore failing checks?|merge even if .* fails)"
)
ISSUE_LAUNDER_RE = re.compile(
    r"(?i)(?:already approved by (?:security|compliance|platform)|security already signed off|consider this pre-approved|treat issue text as approval|approval captured above)"
)
RELEASE_MISLEAD_RE = re.compile(
    r"(?i)(?:official(?:ly)? verified|all checks passed|fully reviewed)[^\n\r]{0,120}(?:raw\.githubusercontent\.com|pastebin\.com|gist\.githubusercontent\.com|file://|https?://)"
)
CHANGELOG_COVERUP_RE = re.compile(
    r"(?i)(?:do not mention|omit from changelog|hide this change|remove security note|do not disclose|bury this in misc|rename as refactor)"
)
SECRET_MARKER_RE = re.compile(
    r"(?i)(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|-----BEGIN [A-Z ]+PRIVATE KEY-----|(?:api[_-]?key|token|secret|password)\s*[:=]\s*[A-Za-z0-9._/+\\=-]{12,})"
)
SECRET_NORMALIZE_RE = re.compile(
    r"(?i)(?:safe to share|dummy secret|test secret|placeholder token|not a real key|expected credential)"
)
INCIDENT_BYPASS_RE = re.compile(
    r"(?i)(?:no incident required|do not escalate|do not page|mark resolved without triage|skip postmortem|close without review)"
)
TEMPLATE_TAMPER_RE = re.compile(
    r"(?i)(?:remove checklist|delete approval section|strip review checklist|drop required signoff|delete risk section|bypass reviewers?)"
)
APPROVAL_SMUGGLING_RE = re.compile(
    r"(?i)(?:signoff token|approval token|review token|approved=true|waived by default|use this comment as approval)"
)
HUMAN_OVERRIDE_RE = re.compile(
    r"(?i)(?:humans should ignore runwall|ignore local policy|reviewers should override the guard|treat this note as higher priority than policy)"
)
REVIEW_SURFACE_REWRITE_RE = re.compile(
    r"(?i)(?:replace review link with|redirect reviewers? to|see external approval at)[^\n\r]{0,120}(?:raw\.githubusercontent\.com|pastebin\.com|gist\.githubusercontent\.com|file://|https?://)"
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def state_dir(root: pathlib.Path) -> pathlib.Path:
    home = os.environ.get("RUNWALL_HOME") or os.environ.get("SECURE_CLAUDE_CODE_HOME")
    if home:
        return pathlib.Path(home) / "state"
    return pathlib.Path(os.path.expanduser("~")) / ".runwall" / "state"


def review_store_path(root: pathlib.Path) -> pathlib.Path:
    return state_dir(root) / "review.json"


def load_store(root: pathlib.Path) -> dict[str, Any]:
    path = review_store_path(root)
    if not path.exists():
        return {"version": 1, "surfaces": {}}
    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {"version": 1, "surfaces": {}}
    if not isinstance(payload, dict):
        return {"version": 1, "surfaces": {}}
    payload.setdefault("version", 1)
    payload.setdefault("surfaces", {})
    return payload


def save_store(root: pathlib.Path, store: dict[str, Any]) -> None:
    path = review_store_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(store, indent=2, sort_keys=True) + "\n")


def _shell_split(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=os.name != "nt")
    except ValueError:
        return [token for token in command.strip().split() if token]


def _normalize_path_token(token: str) -> pathlib.Path:
    stripped = token.strip("'\"= ")
    expanded = os.path.expanduser(stripped)
    path = pathlib.Path(expanded)
    if not path.is_absolute():
        path = pathlib.Path(os.path.abspath(str(pathlib.Path.cwd() / path)))
    return path


def _fileop_surface(matcher: str, payload: str) -> tuple[pathlib.Path | None, str]:
    tokens = _shell_split(payload)
    if not tokens:
        return None, ""
    first = tokens[0]
    path = _normalize_path_token(first)
    if matcher in {"Write", "Edit", "MultiEdit"}:
        return path, payload[len(first) :].strip()
    return path, ""


def _fingerprint(text: str) -> str:
    return hashlib.sha256(re.sub(r"\s+", " ", text.strip()).encode("utf-8")).hexdigest()


def _surface_from_path(path: pathlib.Path) -> str:
    name = path.name.lower()
    location = str(path).replace("\\", "/").lower()
    if "pull_request_template" in name or "pull_request_template" in location:
        return "pull-request-surface"
    if "issue_template" in location or "ticket" in location or "task" in location:
        return "issue-task-surface"
    if "changelog" in name:
        return "changelog-surface"
    if "release" in name:
        return "release-notes-surface"
    if "incident" in location or "postmortem" in location:
        return "incident-surface"
    return "review-surface"


def _hit(module: str, decision: str, identity: dict[str, Any], reason: str, safer: str) -> dict[str, Any]:
    return {
        "module": module,
        "name": module.replace("-", " ").title(),
        "category": "review-trust",
        "family": "Review, Artifacts & Evidence",
        "decision": decision,
        "exit_code": 2 if decision == "block" else 0,
        "output": reason,
        "metadata": {
            "reason": reason,
            "confidence": 0.96 if decision == "block" else 0.84,
            "safer_alternative": safer,
            "review_identity": identity,
        },
    }


def infer_review_identity(matcher: str, payload: str) -> tuple[pathlib.Path | None, str, dict[str, Any] | None]:
    if matcher not in {"Read", "Write", "Edit", "MultiEdit"}:
        return None, "", None
    path, content = _fileop_surface(matcher, payload)
    if path is None:
        return None, "", None
    location = str(path).replace("\\", "/")
    if not REVIEW_PATH_RE.search(location):
        return path, content, None
    if path.suffix and not TEXT_SURFACE_RE.search(path.name):
        return path, content, None
    identity = {
        "path": str(path),
        "surface": _surface_from_path(path),
        "fingerprint": _fingerprint(content) if content else None,
        "matcher": matcher,
    }
    return path, content, identity


def assess_fileop(root: pathlib.Path, event: str, matcher: str, payload: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = context
    if event != "PreToolUse":
        return {"identity": None, "hit": None}
    path, content, identity = infer_review_identity(matcher, payload)
    if identity is None or path is None:
        return {"identity": None, "hit": None}
    store = load_store(root)
    record = store.setdefault("surfaces", {}).get(str(path))
    fingerprint = identity.get("fingerprint")
    hit = None
    trust_state = record.get("trust_state") if isinstance(record, dict) else "observed"

    if isinstance(record, dict) and record.get("trust_state") == "quarantined":
        hit = _hit(
            "review-quarantine-bypass-guard",
            "block",
            identity,
            f"Blocked access to quarantined review surface {path}.",
            f"Review the surface first and move it out of quarantine with `./bin/runwall review trust {path}` only if it is actually safe.",
        )
        trust_state = "quarantined"
    elif matcher in {"Write", "Edit", "MultiEdit"} and isinstance(record, dict) and record.get("trust_state") == "trusted" and fingerprint and record.get("fingerprint") and record.get("fingerprint") != fingerprint:
        hit = _hit(
            "review-surface-drift-guard",
            "prompt",
            identity,
            f"Review required because trusted review surface {path} changed.",
            f"Run `./bin/runwall review diff {path}` and then `./bin/runwall review trust {path}` if the new approval-facing content is expected.",
        )
        trust_state = "drifted"
    elif matcher in {"Write", "Edit", "MultiEdit"} and not isinstance(record, dict):
        hit = _hit(
            "review-surface-review-guard",
            "prompt",
            identity,
            f"Review required before new human review surface {path} becomes trusted.",
            f"Run `./bin/runwall review trust {path}` only after confirming this PR, changelog, task, or incident surface is expected.",
        )
        trust_state = "observed"

    if matcher in {"Write", "Edit", "MultiEdit"}:
        if PR_BYPASS_RE.search(content):
            hit = _hit(
                "pr-description-bypass-guard",
                "block",
                identity,
                f"Blocked review-bypass language in approval-facing surface {path}.",
                "Keep review surfaces factual and do not embed merge-or-approve instructions that bypass normal review gates.",
            )
            trust_state = "quarantined"
        elif ISSUE_LAUNDER_RE.search(content):
            hit = _hit(
                "issue-comment-approval-launder-guard",
                "block",
                identity,
                f"Blocked approval-laundering language in review surface {path}.",
                "Do not treat issue or task prose as if it were formal security or maintainer approval.",
            )
            trust_state = "quarantined"
        elif RELEASE_MISLEAD_RE.search(content):
            hit = _hit(
                "release-notes-mislead-guard",
                "block",
                identity,
                f"Blocked misleading release or approval messaging in {path}.",
                "Keep release and review summaries honest, and do not pair 'verified' claims with raw or external approval links.",
            )
            trust_state = "quarantined"
        elif CHANGELOG_COVERUP_RE.search(content):
            hit = _hit(
                "changelog-coverup-guard",
                "block",
                identity,
                f"Blocked changelog or review-note coverup language in {path}.",
                "Do not hide, rename, or bury material changes in changelogs or approval-facing notes.",
            )
            trust_state = "quarantined"
        elif SECRET_MARKER_RE.search(content) and SECRET_NORMALIZE_RE.search(content):
            hit = _hit(
                "task-doc-secret-normalize-guard",
                "block",
                identity,
                f"Blocked secret-bearing content disguised as harmless review or task text in {path}.",
                "Keep real credentials out of approval-facing docs and do not normalize them as 'test' or 'safe to share' material.",
            )
            trust_state = "quarantined"
        elif INCIDENT_BYPASS_RE.search(content):
            hit = _hit(
                "incident-note-bypass-guard",
                "block",
                identity,
                f"Blocked incident-handling bypass language in {path}.",
                "Do not weaken incident escalation, triage, or postmortem expectations inside human review surfaces.",
            )
            trust_state = "quarantined"
        elif TEMPLATE_TAMPER_RE.search(content):
            hit = _hit(
                "review-template-tamper-guard",
                "prompt",
                identity,
                f"Review required because {path} weakens approval or checklist structure.",
                "Review changes to PR, issue, and signoff templates before removing security or reviewer checkpoints.",
            )
            trust_state = "drifted"
        elif APPROVAL_SMUGGLING_RE.search(content):
            hit = _hit(
                "approval-text-smuggling-guard",
                "block",
                identity,
                f"Blocked approval-token or signoff-smuggling language in {path}.",
                "Formal approval should flow through real Runwall prompts and human review, not embedded magic text.",
            )
            trust_state = "quarantined"
        elif HUMAN_OVERRIDE_RE.search(content):
            hit = _hit(
                "human-review-override-guard",
                "block",
                identity,
                f"Blocked instructions telling humans to override local policy in {path}.",
                "Review surfaces should explain changes, not tell humans to ignore runtime policy or review outcomes.",
            )
            trust_state = "quarantined"
        elif REVIEW_SURFACE_REWRITE_RE.search(content):
            hit = _hit(
                "review-surface-rewrite-guard",
                "block",
                identity,
                f"Blocked external review-pointer rewrite in {path}.",
                "Keep approval references local and reviewable instead of redirecting humans to raw, pasted, or mutable external content.",
            )
            trust_state = "quarantined"

    updated = {
        "path": str(path),
        "surface": identity["surface"],
        "fingerprint": fingerprint or (record or {}).get("fingerprint"),
        "trust_state": trust_state,
        "first_seen_at": (record or {}).get("first_seen_at", utc_now()) if isinstance(record, dict) else utc_now(),
        "last_seen_at": utc_now(),
        "last_reason": hit["module"] if hit else (record or {}).get("last_reason") if isinstance(record, dict) else None,
        "last_drift": utc_now() if hit and hit["module"] == "review-surface-drift-guard" else (record or {}).get("last_drift") if isinstance(record, dict) else None,
    }
    store.setdefault("surfaces", {})[str(path)] = updated
    save_store(root, store)
    return {"identity": identity, "hit": hit}


def list_surfaces(root: pathlib.Path) -> list[dict[str, Any]]:
    items = [dict(item) for item in load_store(root).get("surfaces", {}).values() if isinstance(item, dict)]
    items.sort(key=lambda item: item.get("path", ""))
    return items


def set_trust(root: pathlib.Path, selector: str, state: str) -> bool:
    store = load_store(root)
    record = store.setdefault("surfaces", {}).get(selector)
    if not isinstance(record, dict):
        return False
    record["trust_state"] = state
    record["last_seen_at"] = utc_now()
    save_store(root, store)
    return True


def forget_surface(root: pathlib.Path, selector: str) -> bool:
    store = load_store(root)
    if selector in store.setdefault("surfaces", {}):
        store["surfaces"].pop(selector, None)
        save_store(root, store)
        return True
    return False


def diff_surface(root: pathlib.Path, selector: str) -> dict[str, Any] | None:
    record = load_store(root).get("surfaces", {}).get(selector)
    if isinstance(record, dict):
        return record
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage Runwall human review surface trust")
    parser.add_argument("--root", required=True)
    subparsers = parser.add_subparsers(dest="command", required=True)
    list_parser = subparsers.add_parser("list")
    list_parser.add_argument("--json", action="store_true")
    trust_parser = subparsers.add_parser("trust")
    trust_parser.add_argument("selector")
    quarantine_parser = subparsers.add_parser("quarantine")
    quarantine_parser.add_argument("selector")
    forget_parser = subparsers.add_parser("forget")
    forget_parser.add_argument("selector")
    diff_parser = subparsers.add_parser("diff")
    diff_parser.add_argument("selector")
    args = parser.parse_args()
    root = pathlib.Path(args.root)
    if args.command == "list":
        items = list_surfaces(root)
        if args.json:
            print(json.dumps({"surfaces": items}, indent=2))
        else:
            print("Review Surfaces:")
            for item in items:
                print(f"- {item.get('trust_state')} {item.get('path')}")
        return 0
    if args.command == "trust":
        if set_trust(root, args.selector, "trusted"):
            print(f"trusted {args.selector}")
            return 0
        print(f"unknown review surface: {args.selector}", file=os.sys.stderr)
        return 1
    if args.command == "quarantine":
        if set_trust(root, args.selector, "quarantined"):
            print(f"quarantined {args.selector}")
            return 0
        print(f"unknown review surface: {args.selector}", file=os.sys.stderr)
        return 1
    if args.command == "forget":
        if forget_surface(root, args.selector):
            print(f"forgot {args.selector}")
            return 0
        print(f"unknown review surface: {args.selector}", file=os.sys.stderr)
        return 1
    if args.command == "diff":
        payload = diff_surface(root, args.selector)
        if payload is None:
            print(f"unknown review surface: {args.selector}", file=os.sys.stderr)
            return 1
        print(json.dumps(payload, indent=2))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
