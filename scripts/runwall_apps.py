#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
from datetime import datetime, timezone
from typing import Any

import runwall_approvals


APP_PATTERNS = {
    "github": re.compile(r"(?i)\bgh\b|github\.com"),
    "vercel": re.compile(r"(?i)\bvercel\b|vercel\.com"),
    "stripe": re.compile(r"(?i)\bstripe\b|dashboard\.stripe\.com"),
    "supabase": re.compile(r"(?i)\bsupabase\b|app\.supabase\.com"),
    "aws": re.compile(r"(?i)\baws\b|console\.aws\.amazon\.com"),
    "gcloud": re.compile(r"(?i)\bgcloud\b|cloud\.google\.com"),
    "azure": re.compile(r"(?i)\baz\b|portal\.azure\.com"),
}
AUTOMATION_RE = re.compile(r"(?i)\b(playwright|puppeteer|selenium|chromedp|browser-use|openclaw browser|codex browser)\b")
TOKEN_MINT_RE = re.compile(r"(?i)(create-access-key|token create|tokens create|pat create|api[- ]?key create|personal access token|auth token)")
SECRET_ADMIN_RE = re.compile(r"(?i)(secret set|secret create|secrets set|env add|env pull|get-secret-value|config set token)")
ROLE_GRANT_RE = re.compile(r"(?i)(add-member|invite member|invite user|add collaborator|grant admin|attach-user-policy|add-iam-policy-binding|role assignment create)")
PROD_DEPLOY_RE = re.compile(r"(?i)(--prod\b|deploy (?:to )?prod|promote to production|release production|deploy production)")
BULK_EXPORT_RE = re.compile(r"(?i)(export .*csv|download all|dump all|bulk export|list .*--limit\s+[5-9]\d\d|customers list .*--limit\s+[5-9]\d\d)")
PROTECTION_DISABLE_RE = re.compile(r"(?i)(disable protection|disable branch protection|remove ruleset|turn off checks|disable audit|bypass rules|/protection\b.*--method\s+DELETE|rulesets?.*delete)")
DESTROY_RE = re.compile(r"(?i)(repo delete|project delete|team delete|organization delete|destroy --force|remove --yes|delete production)")
WEBHOOK_RE = re.compile(r"(?i)(webhook create|webhook add|webhook update|hook add|hook update)")
INVITE_RE = re.compile(r"(?i)(invite member|invite user|add-member|add collaborator)")
BROWSER_MUTATION_RE = re.compile(r"(?i)(create token|generate token|invite|delete|disable|remove protection|export all|download all|change role)")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def state_dir(root: pathlib.Path) -> pathlib.Path:
    home = os.environ.get("RUNWALL_HOME") or os.environ.get("SECURE_CLAUDE_CODE_HOME")
    if home:
        return pathlib.Path(home) / "state"
    return pathlib.Path(os.path.expanduser("~")) / ".runwall" / "state"


def apps_store_path(root: pathlib.Path) -> pathlib.Path:
    return state_dir(root) / "apps.json"


def load_store(root: pathlib.Path) -> dict[str, Any]:
    path = apps_store_path(root)
    if not path.exists():
        return {"version": 1, "events": []}
    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {"version": 1, "events": []}
    if not isinstance(payload, dict):
        return {"version": 1, "events": []}
    payload.setdefault("version", 1)
    payload.setdefault("events", [])
    return payload


def save_store(root: pathlib.Path, store: dict[str, Any]) -> None:
    path = apps_store_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(store, indent=2, sort_keys=True) + "\n")


def _app_from_payload(payload: str) -> str | None:
    for app, regex in APP_PATTERNS.items():
        if regex.search(payload):
            return app
    return None


def _identity(app: str, payload: str, module: str) -> dict[str, Any]:
    return {"app": app, "module": module, "preview": payload[:200]}


def _hit(module: str, decision: str, identity: dict[str, Any], reason: str, safer: str) -> dict[str, Any]:
    return {
        "module": module,
        "name": module.replace("-", " ").title(),
        "category": "app-trust",
        "family": "SaaS & Control Planes",
        "decision": decision,
        "exit_code": 2 if decision == "block" else 0,
        "output": reason,
        "metadata": {
            "reason": reason,
            "confidence": 0.95 if decision == "block" else 0.84,
            "safer_alternative": safer,
            "app_identity": identity,
        },
    }


def _approval_assessment(root: pathlib.Path, module: str, app: str, context: dict[str, Any] | None) -> dict[str, Any]:
    ctx = context or {}
    return runwall_approvals.assess_match(
        root,
        kind="app",
        target=module,
        value=app,
        runtime=str(ctx.get("runtime")) if ctx.get("runtime") else None,
        repo=str(root.resolve(strict=False)),
        agent_id=str(ctx.get("subagent_id") or ctx.get("agent_id")) if (ctx.get("subagent_id") or ctx.get("agent_id")) else None,
    )


def assess_command(root: pathlib.Path, payload: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
    app = _app_from_payload(payload)
    if not app:
        return {"identity": None, "hit": None}
    checks = [
        ("app-protection-disable-guard", "block", PROTECTION_DISABLE_RE, "Blocked security-control disable action against a sensitive app.", "Keep branch protection, audit, and other safety controls behind explicit human review."),
        ("app-destroy-action-guard", "block", DESTROY_RE, "Blocked destructive app action against a sensitive control plane.", "Use reviewed deletion or teardown workflows instead of direct destructive app actions from the runtime."),
        ("app-token-mint-guard", "prompt", TOKEN_MINT_RE, "Review required before minting or creating new app credentials or tokens.", "Create or rotate tokens through a reviewed path and use one-shot approvals if the action is expected."),
        ("app-secret-admin-guard", "prompt", SECRET_ADMIN_RE, "Review required before reading or mutating app secrets or environment variables.", "Keep secret administration behind a reviewed human step or a narrowly scoped approval."),
        ("app-role-grant-guard", "prompt", ROLE_GRANT_RE, "Review required before changing app roles, collaborators, or IAM-style bindings.", "Use a reviewed admin path before granting roles or collaborator access."),
        ("app-prod-deploy-guard", "prompt", PROD_DEPLOY_RE, "Review required before a production deployment or promotion through a control-plane app.", "Use a reviewed production deployment path or a one-shot approval for this exact action."),
        ("app-bulk-export-guard", "prompt", BULK_EXPORT_RE, "Review required before bulk export from a control-plane app.", "Reduce the export scope or use a reviewed reporting path before bulk data export."),
        ("app-webhook-admin-guard", "prompt", WEBHOOK_RE, "Review required before creating or changing a webhook on a control-plane app.", "Webhooks should be created through a reviewed configuration path, not ad hoc runtime automation."),
        ("app-member-invite-guard", "prompt", INVITE_RE, "Review required before inviting or adding members through a control-plane app.", "Keep membership and collaborator changes behind a reviewed admin step."),
    ]
    for module, decision, regex, reason, safer in checks:
        if regex.search(payload):
            approval_assessment = _approval_assessment(root, module, app, context)
            approval_hit = approval_assessment.get("hit")
            if approval_hit:
                return {"identity": _identity(app, payload, module), "hit": approval_hit}
            if approval_assessment.get("approval"):
                return {"identity": _identity(app, payload, module), "hit": None}
            return {"identity": _identity(app, payload, module), "hit": _hit(module, decision, _identity(app, payload, module), f"{reason} App={app}.", safer)}

    if AUTOMATION_RE.search(payload) and _app_from_payload(payload) and BROWSER_MUTATION_RE.search(payload):
        module = "app-admin-browser-mutation-guard"
        approval_assessment = _approval_assessment(root, module, app, context)
        approval_hit = approval_assessment.get("hit")
        if approval_hit:
            return {"identity": _identity(app, payload, module), "hit": approval_hit}
        if approval_assessment.get("approval"):
            return {"identity": _identity(app, payload, module), "hit": None}
        return {
            "identity": _identity(app, payload, module),
            "hit": _hit(
                module,
                "prompt",
                _identity(app, payload, module),
                f"Review required before browser automation performs a high-risk admin mutation on {app}.",
                "Keep browser-driven admin mutations behind explicit review or a very narrow one-shot approval.",
            ),
        }
    return {"identity": _identity(app, payload, "observed"), "hit": None}


def record_action(root: pathlib.Path, result: dict[str, Any], payload: str) -> None:
    app_identity = result.get("app_identity")
    if not isinstance(app_identity, dict) or not app_identity.get("app"):
        return
    store = load_store(root)
    store.setdefault("events", []).append(
        {
            "event_id": result.get("event_id"),
            "app": app_identity.get("app"),
            "module": app_identity.get("module"),
            "preview": payload[:180],
            "decision": result.get("action"),
            "ts": utc_now(),
        }
    )
    store["events"] = store["events"][-200:]
    save_store(root, store)


def list_events(root: pathlib.Path) -> list[dict[str, Any]]:
    items = [item for item in load_store(root).get("events", []) if isinstance(item, dict)]
    items.sort(key=lambda item: item.get("ts", ""), reverse=True)
    return items


def explain_event(root: pathlib.Path, selector: str) -> dict[str, Any] | None:
    for item in list_events(root):
        if item.get("event_id") == selector:
            return item
    return None


def policy_payload() -> dict[str, Any]:
    return {"apps": sorted(APP_PATTERNS.keys()), "guards": [
        "app-token-mint-guard",
        "app-secret-admin-guard",
        "app-role-grant-guard",
        "app-prod-deploy-guard",
        "app-bulk-export-guard",
        "app-protection-disable-guard",
        "app-destroy-action-guard",
        "app-webhook-admin-guard",
        "app-member-invite-guard",
        "app-admin-browser-mutation-guard",
    ]}


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect Runwall SaaS action trust state")
    parser.add_argument("--root", required=True)
    subparsers = parser.add_subparsers(dest="command", required=True)
    list_parser = subparsers.add_parser("list")
    list_parser.add_argument("--json", action="store_true")
    explain_parser = subparsers.add_parser("explain")
    explain_parser.add_argument("selector")
    policy_parser = subparsers.add_parser("policy")
    policy_parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    root = pathlib.Path(args.root)
    if args.command == "list":
        items = list_events(root)
        if args.json:
            print(json.dumps({"events": items}, indent=2))
        else:
            print("App Actions:")
            for item in items:
                print(f"- {item.get('decision')} {item.get('app')} {item.get('module')} {item.get('event_id')}")
        return 0
    if args.command == "explain":
        payload = explain_event(root, args.selector)
        if payload is None:
            print(f"unknown app event: {args.selector}", file=os.sys.stderr)
            return 1
        print(json.dumps(payload, indent=2))
        return 0
    if args.command == "policy":
        payload = policy_payload()
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print("Sensitive Apps:")
            for item in payload["apps"]:
                print(f"- {item}")
            print("Guards:")
            for item in payload["guards"]:
                print(f"- {item}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
