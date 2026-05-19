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


STALLION_STATE_PATH_RE = re.compile(r"(?i)(?:^|/)\.stallion/(?:state|config)(?:/|$)|(?:^|/)(?:state|dist)/(?:audit\.jsonl|incident|forensics|evidence)")
AUDIT_PATH_RE = re.compile(r"(?i)(?:^|/)(?:audit(?:d|\.rules|\.jsonl)?|cloudtrail|rsyslog|syslog-ng|fluent-bit|promtail|vector|otel(?:col)?|falco|osquery|eventlog)[^/]*")
RECOVERY_PATH_RE = re.compile(r"(?i)(?:^|/).*(?:backup|restore|rollback|recovery|snapshot)[^/]*\.(?:sh|py|yml|yaml|json|toml|conf|ini|txt|md)$")
MONITORING_PATH_RE = re.compile(r"(?i)(?:^|/).*(?:monitor|alert|alertmanager|prometheus|grafana|datadog|newrelic|sentry|pagerduty|opsgenie)[^/]*\.(?:yml|yaml|json|toml|conf|ini|sh|py)$")
WORKFLOW_PATH_RE = re.compile(r"(?i)(?:^|/)\.github/workflows/[^/]+\.(?:yml|yaml)$")
INCIDENT_PATH_RE = re.compile(r"(?i)(?:^|/).*(?:incident|runbook|forensics|postmortem|evidence)[^/]*\.(?:md|yml|yaml|json|sh|py)$")

AUDIT_DISABLE_RE = re.compile(
    r"(?i)(?:wevtutil\s+cl\b|auditpol\b[^\n\r]{0,80}(?:/clear|disable)|systemctl\s+(?:stop|disable)\s+(?:auditd|rsyslog|syslog-ng|fluent-bit|promtail|vector|falco|osquery)|service\s+(?:auditd|rsyslog)\s+stop|launchctl\s+(?:unload|disable)[^\n\r]{0,80}(?:auditd|syslog)|cloudtrail\s+stop-logging|logging\s+sinks?\s+delete|(?:audit|logging)\s*[:=]\s*(?:false|off|disabled))"
)
BACKUP_DISABLE_RE = re.compile(
    r"(?i)(?:delete-snapshot|disable-backup|disable backup|backup\s*[:=]\s*(?:false|off|disabled)|retention\s*[:=]\s*0\b|snapshot\s+delete|prune backups?)"
)
ROLLBACK_TAMPER_RE = re.compile(
    r"(?i)(?:disable rollback|skip rollback|rollback\s*[:=]\s*(?:false|off|disabled)|exit\s+0\b|return\s+0\b[^\n\r]{0,40}(?:rollback|restore|recovery)?)"
)
MONITORING_DISABLE_RE = re.compile(
    r"(?i)(?:systemctl\s+(?:stop|disable)\s+(?:prometheus|grafana|datadog-agent|newrelic-infra|fluent-bit|promtail|vector)|kubectl\s+delete\s+(?:daemonset|deployment)[^\n\r]{0,120}(?:fluent-bit|prometheus|grafana)|monitoring\s*[:=]\s*(?:false|off|disabled)|alerts?\s*[:=]\s*(?:false|off|disabled)|disable monitoring|disable alerts?)"
)
ALERT_REWIRE_RE = re.compile(
    r"(?i)(?:alertmanager|pagerduty|opsgenie|slack|discord|webhook)[^\n\r]{0,120}(?:https?://|hooks\.slack\.com|api\.pagerduty\.com)"
)
STALLION_STATE_WIPE_RE = re.compile(
    r"(?i)(?:rm\s+-[A-Za-z]*[rf][A-Za-z]*\s+[^\n\r]*(?:\.stallion/state|audit\.jsonl|approvals\.json|hooks\.json|tools\.json|memory\.json|knowledge\.json|services\.json|browser\.json|apps\.json)|:\s*>\s*[^\n\r]*audit\.jsonl|truncate\s+-s\s+0\s+[^\n\r]*audit\.jsonl|shred\s+[^\n\r]*(?:audit\.jsonl|approvals\.json|hooks\.json|tools\.json))"
)
FORENSICS_DELETE_RE = re.compile(
    r"(?i)(?:rm\s+-[A-Za-z]*[rf][A-Za-z]*\s+[^\n\r]*(?:incident|forensic|bundle|evidence|sarif|sbom|provenance)|shred\s+[^\n\r]*(?:incident|forensic|bundle|evidence|sarif|sbom|provenance))"
)
RUNBOOK_TAMPER_RE = re.compile(
    r"(?i)(?:skip incident response|do not page|disable escalation|ignore rollback|no approval required|bypass review|suppress alerts during incident)"
)
RELEASE_SAFETY_DISABLE_RE = re.compile(
    r"(?i)(?:SKIP_SECURITY\s*=\s*1|DISABLE_(?:CHECKS|SAFETY)\s*=\s*1|--no-verify\b|disable (?:sbom|provenance|attest(?:ation)?|verify|codeql|trivy|sast|dast|audit checks?)|skip (?:sbom|provenance|attest(?:ation)?|verify|security checks?))"
)
RECOVERY_DESTROY_RE = re.compile(
    r"(?i)(?:rm\s+-[A-Za-z]*[rf][A-Za-z]*\s+[^\n\r]*(?:backup|restore|rollback|recovery)|chmod\s+-x\s+[^\n\r]*(?:backup|restore|rollback|recovery)|>\s*[^\n\r]*(?:backup|restore|rollback|recovery)[^\n\r]*\.(?:sh|py|yml|yaml))"
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def state_dir(root: pathlib.Path) -> pathlib.Path:
    home = os.environ.get("STALLION_HOME") or os.environ.get("STALLION_HOME")
    if home:
        return pathlib.Path(home) / "state"
    return pathlib.Path(os.path.expanduser("~")) / ".stallion" / "state"


def safety_store_path(root: pathlib.Path) -> pathlib.Path:
    return state_dir(root) / "safety.json"


def load_store(root: pathlib.Path) -> dict[str, Any]:
    path = safety_store_path(root)
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
    path = safety_store_path(root)
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


def _fingerprint(text: str) -> str:
    normalized = re.sub(r"\s+", " ", text.strip())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _hit(module: str, decision: str, identity: dict[str, Any], reason: str, safer: str) -> dict[str, Any]:
    return {
        "module": module,
        "name": module.replace("-", " ").title(),
        "category": "safety-trust",
        "family": "Recovery, Audit & Safety Controls",
        "decision": decision,
        "exit_code": 2 if decision == "block" else 0,
        "output": reason,
        "metadata": {
            "reason": reason,
            "confidence": 0.95 if decision == "block" else 0.84,
            "safer_alternative": safer,
            "safety_identity": identity,
        },
    }


def _surface_from_path(path: pathlib.Path) -> str | None:
    location = str(path).replace("\\", "/")
    if STALLION_STATE_PATH_RE.search(location):
        return "stallion-state"
    if AUDIT_PATH_RE.search(location):
        return "audit-control"
    if RECOVERY_PATH_RE.search(location):
        return "recovery-control"
    if MONITORING_PATH_RE.search(location):
        return "monitoring-control"
    if WORKFLOW_PATH_RE.search(location):
        return "release-control"
    if INCIDENT_PATH_RE.search(location):
        return "incident-control"
    return None


def infer_safety_identity(event: str, matcher: str, payload: str) -> tuple[pathlib.Path | None, str, dict[str, Any] | None]:
    if event != "PreToolUse":
        return None, "", None
    if matcher in {"Write", "Edit", "MultiEdit", "Read"}:
        tokens = _shell_split(payload)
        if not tokens:
            return None, "", None
        path = _normalize_path_token(tokens[0])
        content = payload[len(tokens[0]) :].strip() if matcher != "Read" else ""
        surface = _surface_from_path(path)
        if not surface:
            return path, content, None
        return path, content, {
            "path": str(path),
            "surface": surface,
            "matcher": matcher,
            "fingerprint": _fingerprint(content) if content else None,
        }
    if matcher == "Bash":
        surface = None
        target = "shell"
        if STALLION_STATE_WIPE_RE.search(payload):
            surface = "stallion-state"
            target = ".stallion/state"
        elif AUDIT_DISABLE_RE.search(payload):
            surface = "audit-control"
            target = "audit"
        elif BACKUP_DISABLE_RE.search(payload):
            surface = "recovery-control"
            target = "backup"
        elif ROLLBACK_TAMPER_RE.search(payload) or RECOVERY_DESTROY_RE.search(payload):
            surface = "recovery-control"
            target = "rollback"
        elif MONITORING_DISABLE_RE.search(payload) or ALERT_REWIRE_RE.search(payload):
            surface = "monitoring-control"
            target = "monitoring"
        elif RELEASE_SAFETY_DISABLE_RE.search(payload):
            surface = "release-control"
            target = "release-safety"
        elif FORENSICS_DELETE_RE.search(payload) or RUNBOOK_TAMPER_RE.search(payload):
            surface = "incident-control"
            target = "incident"
        if not surface:
            return None, "", None
        return None, payload, {
            "path": target,
            "surface": surface,
            "matcher": matcher,
            "fingerprint": _fingerprint(payload),
        }
    return None, "", None


def _record(store: dict[str, Any], selector: str) -> dict[str, Any] | None:
    item = store.setdefault("surfaces", {}).get(selector)
    if isinstance(item, dict):
        return item
    return None


def assess_action(root: pathlib.Path, event: str, matcher: str, payload: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = context
    path, content, identity = infer_safety_identity(event, matcher, payload)
    if identity is None:
        return {"identity": None, "hit": None}
    store = load_store(root)
    selector = str(path) if path is not None else str(identity.get("path"))
    record = _record(store, selector)
    hit = None
    trust_state = "observed"
    combined = content if matcher in {"Write", "Edit", "MultiEdit"} else payload
    location = str(path) if path is not None else str(identity.get("path"))

    checks: list[tuple[str, str, re.Pattern[str], str, str]] = [
        (
            "stallion-state-wipe-guard",
            "block",
            STALLION_STATE_WIPE_RE,
            f"Blocked tampering with Stallion state or audit records at {location}.",
            "Do not delete or truncate Stallion state, approvals, or audit evidence from inside the runtime.",
        ),
        (
            "audit-disable-guard",
            "block",
            AUDIT_DISABLE_RE,
            f"Blocked audit or logging disable path touching {location}.",
            "Keep auditd, logging, CloudTrail, and local evidence collection enabled during agent activity.",
        ),
        (
            "backup-disable-guard",
            "block",
            BACKUP_DISABLE_RE,
            f"Blocked backup or snapshot disable path touching {location}.",
            "Backups and snapshot retention should only be changed through a reviewed recovery workflow.",
        ),
        (
            "rollback-tamper-guard",
            "block",
            ROLLBACK_TAMPER_RE,
            f"Blocked rollback or restore tamper path touching {location}.",
            "Keep rollback and restore logic intact so recovery stays available if something goes wrong.",
        ),
        (
            "monitoring-disable-guard",
            "block",
            MONITORING_DISABLE_RE,
            f"Blocked monitoring or alert disable path touching {location}.",
            "Do not disable monitoring, telemetry, or alerting from inside the coding runtime.",
        ),
        (
            "alert-sink-rewire-guard",
            "prompt",
            ALERT_REWIRE_RE,
            f"Review required before rewiring alert or incident sinks in {location}.",
            "Alert destinations should only change through a reviewed operational change, not ad hoc runtime edits.",
        ),
        (
            "forensics-bundle-delete-guard",
            "block",
            FORENSICS_DELETE_RE,
            f"Blocked deletion of incident, forensics, or evidence artifacts at {location}.",
            "Keep incident bundles, SARIF, provenance, and other evidence artifacts intact for review and recovery.",
        ),
        (
            "incident-runbook-automation-tamper-guard",
            "prompt",
            RUNBOOK_TAMPER_RE,
            f"Review required before weakening incident-response or runbook automation in {location}.",
            "Keep runbooks and incident automation honest, especially around escalation, rollback, and review boundaries.",
        ),
        (
            "release-safety-check-disable-guard",
            "block",
            RELEASE_SAFETY_DISABLE_RE,
            f"Blocked release-safety check disable path touching {location}.",
            "Keep provenance, attestation, signing, and release verification checks in place for production and release workflows.",
        ),
        (
            "recovery-script-destroy-guard",
            "block",
            RECOVERY_DESTROY_RE,
            f"Blocked destructive change against recovery scripts or controls at {location}.",
            "Do not delete, truncate, or de-executable backup, restore, rollback, or recovery scripts from the runtime.",
        ),
    ]

    for module, decision, regex, reason, safer in checks:
        if regex.search(combined):
            hit = _hit(module, decision, identity, reason, safer)
            trust_state = "blocked" if decision == "block" else "prompted"
            break

    updated = {
        "path": selector,
        "surface": identity.get("surface"),
        "fingerprint": identity.get("fingerprint") or (record or {}).get("fingerprint"),
        "trust_state": trust_state,
        "first_seen_at": (record or {}).get("first_seen_at", utc_now()),
        "last_seen_at": utc_now(),
        "last_reason": hit["module"] if hit else (record or {}).get("last_reason"),
    }
    store.setdefault("surfaces", {})[selector] = updated
    save_store(root, store)
    return {"identity": identity, "hit": hit}


def list_surfaces(root: pathlib.Path) -> list[dict[str, Any]]:
    items = [dict(item) for item in load_store(root).get("surfaces", {}).values() if isinstance(item, dict)]
    items.sort(key=lambda item: item.get("path", ""))
    return items


def diff_surface(root: pathlib.Path, selector: str) -> dict[str, Any] | None:
    payload = load_store(root).get("surfaces", {}).get(selector)
    if isinstance(payload, dict):
        return payload
    return None


def forget_surface(root: pathlib.Path, selector: str) -> bool:
    store = load_store(root)
    if selector in store.setdefault("surfaces", {}):
        store["surfaces"].pop(selector, None)
        save_store(root, store)
        return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect Stallion safety-control trust state")
    parser.add_argument("--root", required=True)
    subparsers = parser.add_subparsers(dest="command", required=True)
    list_parser = subparsers.add_parser("list")
    list_parser.add_argument("--json", action="store_true")
    diff_parser = subparsers.add_parser("diff")
    diff_parser.add_argument("selector")
    forget_parser = subparsers.add_parser("forget")
    forget_parser.add_argument("selector")
    args = parser.parse_args()
    root = pathlib.Path(args.root)
    if args.command == "list":
        items = list_surfaces(root)
        if args.json:
            print(json.dumps({"surfaces": items}, indent=2))
        else:
            print("Safety Surfaces:")
            for item in items:
                print(f"- {item.get('trust_state')} {item.get('surface')} {item.get('path')}")
        return 0
    if args.command == "diff":
        payload = diff_surface(root, args.selector)
        if payload is None:
            print(f"unknown safety surface: {args.selector}", file=os.sys.stderr)
            return 1
        print(json.dumps(payload, indent=2))
        return 0
    if args.command == "forget":
        if forget_surface(root, args.selector):
            print(f"forgot {args.selector}")
            return 0
        print(f"unknown safety surface: {args.selector}", file=os.sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
