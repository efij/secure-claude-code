#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shlex
import shutil
from datetime import datetime, timezone
from typing import Any

import stallion_approvals


PROVIDER_PATTERNS: dict[str, re.Pattern[str]] = {
    "github": re.compile(r"(?i)\bgh\b|github\.com"),
    "aws": re.compile(r"(?i)\baws\b|amazonaws\.com"),
    "gcloud": re.compile(r"(?i)\bgcloud\b|googleapis\.com|cloud\.google\.com"),
    "azure": re.compile(r"(?i)\baz\b|microsoftonline\.com|azure\.com"),
    "vercel": re.compile(r"(?i)\bvercel\b|vercel\.com"),
    "supabase": re.compile(r"(?i)\bsupabase\b|supabase\.com"),
    "vault": re.compile(r"(?i)\bvault\b|vault\."),
    "oauth": re.compile(r"(?i)\boauth\b|openid|oidc|device/code|token exchange|refresh_token"),
}

REFRESH_EXCHANGE_RE = re.compile(
    r"(?i)(grant_type=refresh_token|refresh[_-]?token|token exchange|token-exchange|requested_token_type|subject_token)"
)
SESSION_RELAY_RE = re.compile(
    r"(?i)(cookie|session|storageState|access[-_ ]?token|refresh[-_ ]?token)[^\n\r]{0,120}(curl|wget|scp|rsync|rclone|aws\s+s3\s+cp|gh\s+release\s+upload|pbcopy|xclip|wl-copy|clip|tee|>)"
)
EXPORT_RE = re.compile(
    r"(?i)(gh\s+auth\s+token|print-access-token|get-login-password|get-authorization-token|vault\s+token\s+create|supabase[^\n\r]{0,40}(access-token|login)|az\s+account\s+get-access-token)[^\n\r]{0,120}(>|tee|pbcopy|xclip|wl-copy|clip|curl|scp|rsync)"
)
SCOPE_ESCALATION_RE = re.compile(
    r"(?i)(AdministratorAccess|cluster-admin|roles/owner|owner\b|admin\b|prod(?:uction)?\b|--scope\b[^\n\r]{0,40}(admin|write|prod)|--role-arn\b[^\n\r]{0,120}(Admin|Owner))"
)
IMPERSONATION_RE = re.compile(
    r"(?i)(--impersonate-service-account|assume-role(?:-with-web-identity)?|federat(?:e|ion)|workload-identity|service-principal)"
)
STS_MINT_RE = re.compile(
    r"(?i)(\baws\s+sts\s+(get-session-token|assume-role|assume-role-with-web-identity)\b|\bgcloud\s+auth\s+print-access-token\b|\baz\s+account\s+get-access-token\b|\bvault\s+token\s+create\b)"
)
DEVICE_FLOW_RE = re.compile(
    r"(?i)(device[- ]?code|oauth/device/code|\bgh\s+auth\s+login\b[^\n\r]{0,80}(--web|--device-code)|\baz\s+login\b[^\n\r]{0,80}--use-device-code)"
)
SSO_HELPER_RE = re.compile(
    r"(?i)(\baws\s+sso\s+login\b|\bgcloud\s+auth\s+login\b|\baz\s+login\b|\bvercel\s+login\b|\bsupabase\s+login\b)"
)
CREDENTIAL_HELPER_RE = re.compile(
    r"(?i)(\bgh\s+auth\s+token\b|\baws\s+ecr\s+get-login-password\b|\bgcloud\s+auth\s+print-access-token\b|\baz\s+account\s+get-access-token\b|\bsupabase[^\n\r]{0,40}(access-token|login)\b|\bvercel\b[^\n\r]{0,120}\s--token\b)"
)
AUTH_TRIGGER_RE = re.compile(
    r"(?i)(auth\b|token\b|login\b|assume-role|impersonate|access-token|device[- ]?code|refresh[_-]?token|sso\b|service-principal)"
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def state_dir(root: pathlib.Path) -> pathlib.Path:
    home = os.environ.get("STALLION_HOME") or os.environ.get("STALLION_HOME")
    if home:
        return pathlib.Path(home) / "state"
    return pathlib.Path(os.path.expanduser("~")) / ".stallion" / "state"


def auth_store_path(root: pathlib.Path) -> pathlib.Path:
    return state_dir(root) / "auth.json"


def load_store(root: pathlib.Path) -> dict[str, Any]:
    path = auth_store_path(root)
    if not path.exists():
        return {"version": 1, "brokers": {}, "events": []}
    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {"version": 1, "brokers": {}, "events": []}
    if not isinstance(payload, dict):
        return {"version": 1, "brokers": {}, "events": []}
    payload.setdefault("version", 1)
    payload.setdefault("brokers", {})
    payload.setdefault("events", [])
    return payload


def save_store(root: pathlib.Path, store: dict[str, Any]) -> None:
    path = auth_store_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(store, indent=2, sort_keys=True) + "\n")


def _provider_from_payload(payload: str) -> str | None:
    for provider, regex in PROVIDER_PATTERNS.items():
        if regex.search(payload):
            return provider
    return None


def _command_argv0(payload: str) -> str:
    try:
        parts = shlex.split(payload)
    except ValueError:
        parts = payload.split()
    return parts[0] if parts else ""


def _resolve_executable(argv0: str) -> str | None:
    if not argv0:
        return None
    path = pathlib.Path(argv0).expanduser()
    if path.is_absolute() or str(argv0).startswith("."):
        return str(path.resolve(strict=False))
    resolved = shutil.which(argv0)
    if resolved:
        return str(pathlib.Path(resolved).resolve(strict=False))
    return None


def _fingerprint(executable: str | None, provider: str, broker_class: str) -> str:
    if executable:
        path = pathlib.Path(executable)
        try:
            if path.is_file():
                return hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            pass
        return hashlib.sha256(str(path).encode("utf-8")).hexdigest()
    return hashlib.sha256(f"{provider}:{broker_class}".encode("utf-8")).hexdigest()


def _broker_key(identity: dict[str, Any]) -> str:
    executable = identity.get("executable") or identity.get("command") or "unknown"
    return f"{identity.get('provider')}:{identity.get('broker_class')}:{pathlib.Path(str(executable)).name}"


def _scope(payload: str) -> str | None:
    match = SCOPE_ESCALATION_RE.search(payload)
    if not match:
        return None
    return match.group(0)[:80]


def _identity(provider: str, payload: str, broker_class: str) -> dict[str, Any]:
    argv0 = _command_argv0(payload)
    executable = _resolve_executable(argv0)
    return {
        "provider": provider,
        "broker_class": broker_class,
        "command": payload[:220],
        "argv0": argv0,
        "executable": executable,
        "scope": _scope(payload),
        "fingerprint": _fingerprint(executable, provider, broker_class),
    }


def _hit(module: str, decision: str, identity: dict[str, Any], reason: str, safer: str) -> dict[str, Any]:
    return {
        "module": module,
        "name": module.replace("-", " ").title(),
        "category": "auth-trust",
        "family": "Secrets & Identity",
        "decision": decision,
        "exit_code": 2 if decision == "block" else 0,
        "output": reason,
        "metadata": {
            "reason": reason,
            "confidence": 0.95 if decision == "block" else 0.84,
            "safer_alternative": safer,
            "auth_identity": identity,
        },
    }


def _approval_assessment(root: pathlib.Path, identity: dict[str, Any], context: dict[str, Any] | None) -> dict[str, Any]:
    ctx = context or {}
    return stallion_approvals.assess_match(
        root,
        kind="auth",
        target=str(identity.get("provider") or "auth"),
        value=str(identity.get("broker_class") or "general"),
        runtime=str(ctx.get("runtime")) if ctx.get("runtime") else None,
        repo=str(root.resolve(strict=False)),
        agent_id=str(ctx.get("subagent_id") or ctx.get("agent_id")) if (ctx.get("subagent_id") or ctx.get("agent_id")) else None,
        fingerprint=str(identity.get("fingerprint") or ""),
    )


def _drift_hit(root: pathlib.Path, identity: dict[str, Any]) -> dict[str, Any] | None:
    store = load_store(root)
    prior = store.get("brokers", {}).get(_broker_key(identity))
    if not isinstance(prior, dict):
        return None
    if prior.get("fingerprint") == identity.get("fingerprint"):
        return None
    return _hit(
        "broker-drift-guard",
        "prompt",
        identity,
        f"Review required because the reviewed auth broker for {identity.get('provider')} drifted from {prior.get('executable') or 'unknown'} to {identity.get('executable') or 'unknown'}.",
        "Re-approve the exact broker path only after confirming the delegated-auth helper is still the expected one.",
    )


def _match_with_approval(root: pathlib.Path, identity: dict[str, Any], context: dict[str, Any] | None, hit: dict[str, Any]) -> dict[str, Any]:
    assessment = _approval_assessment(root, identity, context)
    approval_hit = assessment.get("hit")
    if approval_hit:
        return {"identity": identity, "hit": approval_hit}
    if assessment.get("approval"):
        return {"identity": identity, "hit": None}
    return {"identity": identity, "hit": hit}


def assess_command(root: pathlib.Path, payload: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
    provider = _provider_from_payload(payload)
    if not provider or not AUTH_TRIGGER_RE.search(payload):
        return {"identity": None, "hit": None}

    checks: list[tuple[str, str, re.Pattern[str], str, str, str]] = [
        (
            "refresh-token-exchange-guard",
            "block",
            REFRESH_EXCHANGE_RE,
            "refresh-token-exchange",
            "Blocked refresh-token or token-exchange flow that would mint a fresh delegated session.",
            "Keep refresh-token and token-exchange flows behind reviewed identity brokers instead of raw runtime commands.",
        ),
        (
            "delegated-session-relay-guard",
            "block",
            SESSION_RELAY_RE,
            "delegated-session-relay",
            "Blocked delegated session relay because cookies, sessions, or tokens were being bridged into another transfer channel.",
            "Keep delegated sessions inside the reviewed login path instead of relaying them into files, uploads, or clipboard bridges.",
        ),
        (
            "broker-export-guard",
            "block",
            EXPORT_RE,
            "broker-export",
            "Blocked auth-broker export because a live token or delegated credential was being redirected or piped outward.",
            "Use the credential inside a reviewed local flow instead of printing or exporting it into another channel.",
        ),
        (
            "broker-scope-escalation-guard",
            "prompt",
            SCOPE_ESCALATION_RE,
            "scope-escalation",
            "Review required before minting or requesting an elevated delegated-auth scope.",
            "Use a narrower role, scope, or environment target unless a human explicitly approved the elevated request.",
        ),
        (
            "cloud-impersonation-broker-guard",
            "prompt",
            IMPERSONATION_RE,
            "impersonation",
            "Review required before using impersonation, role assumption, or service-principal auth to mint delegated access.",
            "Keep impersonation and role-assumption flows behind explicit approval for the exact target principal or role.",
        ),
        (
            "sts-mint-guard",
            "prompt",
            STS_MINT_RE,
            "sts",
            "Review required before minting a delegated session token or short-lived cloud credential.",
            "Use a narrow one-shot approval for the exact broker and role instead of minting delegated cloud access ad hoc.",
        ),
        (
            "device-flow-broker-guard",
            "prompt",
            DEVICE_FLOW_RE,
            "device-flow",
            "Review required before starting a device-code or browser-mediated delegated login flow.",
            "Keep device-code and browser login flows behind a reviewed step so a fresh delegated session is not minted silently.",
        ),
        (
            "sso-helper-mint-guard",
            "prompt",
            SSO_HELPER_RE,
            "sso-login",
            "Review required before using an SSO helper or browser login path to mint delegated user access.",
            "Use a reviewed SSO path or one-shot approval instead of silent agent-driven delegated login.",
        ),
        (
            "credential-helper-mint-guard",
            "prompt",
            CREDENTIAL_HELPER_RE,
            "credential-helper",
            "Review required before using a credential helper or token-printing command to mint active auth material.",
            "Prefer reviewed helper use and avoid printing delegated credentials unless the exact broker path was approved.",
        ),
    ]

    for module, decision, regex, broker_class, reason, safer in checks:
        if not regex.search(payload):
            continue
        identity = _identity(provider, payload, broker_class)
        if decision != "block":
            drift_hit = _drift_hit(root, identity)
            if drift_hit:
                return {"identity": identity, "hit": drift_hit}
        return _match_with_approval(root, identity, context, _hit(module, decision, identity, f"{reason} Provider={provider}.", safer))

    return {"identity": _identity(provider, payload, "observed"), "hit": None}


def record_action(root: pathlib.Path, result: dict[str, Any], payload: str) -> None:
    identity = result.get("auth_identity")
    if not isinstance(identity, dict) or not identity.get("provider"):
        return
    store = load_store(root)
    store.setdefault("events", []).append(
        {
            "event_id": result.get("event_id"),
            "provider": identity.get("provider"),
            "broker_class": identity.get("broker_class"),
            "executable": identity.get("executable"),
            "fingerprint": identity.get("fingerprint"),
            "decision": result.get("action"),
            "preview": payload[:180],
            "ts": utc_now(),
        }
    )
    brokers = store.setdefault("brokers", {})
    key = _broker_key(identity)
    prior = brokers.get(key) if isinstance(brokers, dict) else None
    brokers[key] = {
        "provider": identity.get("provider"),
        "broker_class": identity.get("broker_class"),
        "executable": identity.get("executable"),
        "fingerprint": identity.get("fingerprint"),
        "first_seen_at": prior.get("first_seen_at") if isinstance(prior, dict) and prior.get("first_seen_at") else utc_now(),
        "last_seen_at": utc_now(),
    }
    store["events"] = store["events"][-200:]
    save_store(root, store)


def list_events(root: pathlib.Path) -> list[dict[str, Any]]:
    items = [item for item in load_store(root).get("events", []) if isinstance(item, dict)]
    items.sort(key=lambda item: item.get("ts", ""), reverse=True)
    return items


def explain_event(root: pathlib.Path, selector: str) -> dict[str, Any] | None:
    store = load_store(root)
    for item in list_events(root):
        if item.get("event_id") == selector or f"{item.get('provider')}:{item.get('broker_class')}" == selector:
            key = f"{item.get('provider')}:{item.get('broker_class')}:{pathlib.Path(str(item.get('executable') or 'unknown')).name}"
            payload = dict(item)
            payload["broker"] = store.get("brokers", {}).get(key)
            return payload
    return None


def forget_provider(root: pathlib.Path, selector: str) -> int:
    store = load_store(root)
    removed = 0
    keep_brokers: dict[str, Any] = {}
    for key, value in store.get("brokers", {}).items():
        if selector in {key, f"{value.get('provider')}:{value.get('broker_class')}", str(value.get("provider"))}:
            removed += 1
            continue
        keep_brokers[key] = value
    store["brokers"] = keep_brokers
    if removed:
        save_store(root, store)
    return removed


def approve_selector(
    root: pathlib.Path,
    selector: str,
    *,
    once: bool,
    runtime: str | None,
    agent_id: str | None,
    ttl_hours: float | None,
) -> dict[str, Any]:
    provider, _, broker_class = selector.partition(":")
    provider = provider.strip()
    broker_class = (broker_class or "credential-helper").strip()
    return stallion_approvals.create_approval(
        root,
        kind="auth",
        target=provider,
        value=broker_class,
        runtime=runtime,
        repo=str(root.resolve(strict=False)),
        agent_id=agent_id,
        once=once,
        ttl_hours=ttl_hours,
    )


def policy_payload() -> dict[str, Any]:
    return {
        "providers": sorted(PROVIDER_PATTERNS.keys()),
        "guards": [
            "refresh-token-exchange-guard",
            "delegated-session-relay-guard",
            "broker-export-guard",
            "broker-scope-escalation-guard",
            "cloud-impersonation-broker-guard",
            "sts-mint-guard",
            "device-flow-broker-guard",
            "sso-helper-mint-guard",
            "credential-helper-mint-guard",
            "broker-drift-guard",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect Stallion delegated-auth trust state")
    parser.add_argument("--root", required=True)
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list")
    list_parser.add_argument("--json", action="store_true")

    explain_parser = subparsers.add_parser("explain")
    explain_parser.add_argument("selector")

    policy_parser = subparsers.add_parser("policy")
    policy_parser.add_argument("--json", action="store_true")

    approve_parser = subparsers.add_parser("approve")
    approve_parser.add_argument("selector")
    approve_parser.add_argument("--once", action="store_true")
    approve_parser.add_argument("--runtime")
    approve_parser.add_argument("--agent-id")
    approve_parser.add_argument("--ttl-hours", type=float)

    forget_parser = subparsers.add_parser("forget")
    forget_parser.add_argument("selector")

    args = parser.parse_args()
    root = pathlib.Path(args.root)

    if args.command == "list":
        items = list_events(root)
        if args.json:
            print(json.dumps({"events": items}, indent=2))
        else:
            print("Delegated Auth Events:")
            for item in items:
                print(f"- {item.get('decision')} {item.get('provider')}:{item.get('broker_class')} {item.get('event_id')}")
        return 0
    if args.command == "explain":
        payload = explain_event(root, args.selector)
        if payload is None:
            print(f"unknown auth event: {args.selector}", file=os.sys.stderr)
            return 1
        print(json.dumps(payload, indent=2))
        return 0
    if args.command == "policy":
        payload = policy_payload()
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print("Providers:")
            for item in payload["providers"]:
                print(f"- {item}")
            print("Guards:")
            for item in payload["guards"]:
                print(f"- {item}")
        return 0
    if args.command == "approve":
        approval = approve_selector(
            root,
            args.selector,
            once=bool(args.once),
            runtime=args.runtime,
            agent_id=args.agent_id,
            ttl_hours=args.ttl_hours,
        )
        print(json.dumps(approval, indent=2))
        return 0
    if args.command == "forget":
        removed = forget_provider(root, args.selector)
        print(f"forgot {removed} auth broker entries")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
