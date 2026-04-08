#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import runwall_approvals


SENSITIVE_DOMAINS = {
    "github.com",
    "app.terraform.io",
    "console.aws.amazon.com",
    "cloud.google.com",
    "portal.azure.com",
    "vercel.com",
    "dashboard.stripe.com",
    "app.supabase.com",
    "cloudflare.com",
}
DOMAIN_RE = re.compile(r"https?://([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
AUTOMATION_RE = re.compile(r"(?i)\b(playwright|puppeteer|selenium|chromedp|browser-use|openclaw browser|codex browser)\b")
EXPORT_RE = re.compile(r"(?i)\b(storageState|cookies|screenshot|pdf|download|save[-_ ]?storage|dump[-_ ]?dom|export)\b")
BULK_RE = re.compile(r"(?i)\b(all pages|full dom|innerhtml|outerhtml|page\.content|downloads? folder|screenshot .*(full|entire))\b")
COOKIE_RE = re.compile(r"(?i)\b(storageState|cookies?|cookie[-_ ]?jar|local[-_ ]?storage|session[-_ ]?storage)\b")
DOWNLOAD_RE = re.compile(r"(?i)\b(download|save as|get file)\b.*\.(sh|command|pkg|dmg|zip|tar(?:\.gz)?|7z|exe|msi|deb|rpm)\b|https?://[^\s'\"]+\.(sh|command|pkg|dmg|zip|tar(?:\.gz)?|7z|exe|msi|deb|rpm)\b")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def state_dir(root: pathlib.Path) -> pathlib.Path:
    home = os.environ.get("RUNWALL_HOME") or os.environ.get("SECURE_CLAUDE_CODE_HOME")
    if home:
        return pathlib.Path(home) / "state"
    return pathlib.Path(os.path.expanduser("~")) / ".runwall" / "state"


def browser_store_path(root: pathlib.Path) -> pathlib.Path:
    return state_dir(root) / "browser.json"


def load_store(root: pathlib.Path) -> dict[str, Any]:
    path = browser_store_path(root)
    if not path.exists():
        return {"version": 1, "domains": {}, "allowlist": []}
    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {"version": 1, "domains": {}, "allowlist": []}
    if not isinstance(payload, dict):
        return {"version": 1, "domains": {}, "allowlist": []}
    payload.setdefault("version", 1)
    payload.setdefault("domains", {})
    payload.setdefault("allowlist", [])
    return payload


def save_store(root: pathlib.Path, store: dict[str, Any]) -> None:
    path = browser_store_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(store, indent=2, sort_keys=True) + "\n")


def _normalize_domain(domain: str) -> str:
    lowered = domain.lower().strip()
    if lowered.startswith("www."):
        lowered = lowered[4:]
    return lowered


def _domains_from_payload(payload: str) -> list[str]:
    domains = {_normalize_domain(match.group(1)) for match in DOMAIN_RE.finditer(payload)}
    return sorted(domains)


def _hit(module: str, decision: str, identity: dict[str, Any], reason: str, safer: str) -> dict[str, Any]:
    return {
        "module": module,
        "name": module.replace("-", " ").title(),
        "category": "browser-trust",
        "family": "Secrets & Identity",
        "decision": decision,
        "exit_code": 2 if decision == "block" else 0,
        "output": reason,
        "metadata": {
            "reason": reason,
            "confidence": 0.96 if decision == "block" else 0.84,
            "safer_alternative": safer,
            "browser_identity": identity,
        },
    }


def assess_command(root: pathlib.Path, payload: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
    if not AUTOMATION_RE.search(payload):
        return {"identity": None, "hit": None}
    domains = _domains_from_payload(payload)
    if not domains:
        return {"identity": None, "hit": None}
    store = load_store(root)
    allowed = {_normalize_domain(item) for item in store.get("allowlist", []) if isinstance(item, str)}
    runtime = (context or {}).get("runtime")
    agent_id = (context or {}).get("subagent_id") or (context or {}).get("agent_id")
    repo = str(root.resolve(strict=False))
    identity = {
        "domains": domains,
        "sensitive_domains": [domain for domain in domains if domain in SENSITIVE_DOMAINS],
        "has_export": bool(EXPORT_RE.search(payload)),
        "has_bulk_capture": bool(BULK_RE.search(payload)),
        "has_cookie_export": bool(COOKIE_RE.search(payload)),
        "has_download_dropper": bool(DOWNLOAD_RE.search(payload)),
    }
    for domain in domains:
        store.setdefault("domains", {}).setdefault(domain, {"first_seen_at": utc_now(), "last_seen_at": utc_now(), "trust_state": "observed"})
        store["domains"][domain]["last_seen_at"] = utc_now()
    save_store(root, store)

    for domain in identity["sensitive_domains"]:
        approval_assessment = runwall_approvals.assess_match(
            root,
            kind="browser",
            target="domain",
            value=domain,
            runtime=str(runtime) if runtime else None,
            repo=repo,
            agent_id=str(agent_id) if agent_id else None,
        )
        approval = approval_assessment.get("approval")
        approval_hit = approval_assessment.get("hit")
        if identity["has_cookie_export"]:
            return {
                "identity": identity,
                "hit": _hit(
                    "browser-session-cookie-guard",
                    "block",
                    identity,
                    f"Blocked browser session export against sensitive domain {domain}.",
                    f"Keep cookies, storage state, and session material for {domain} out of agent automation unless a human explicitly reviews the export.",
                ),
            }
        if identity["has_bulk_capture"]:
            return {
                "identity": identity,
                "hit": _hit(
                    "browser-bulk-capture-guard",
                    "block",
                    identity,
                    f"Blocked bulk browser capture against sensitive domain {domain}.",
                    f"Reduce the browser action to a narrow reviewed task before capturing large sensitive page bodies from {domain}.",
                ),
            }
        if identity["has_download_dropper"]:
            return {
                "identity": identity,
                "hit": _hit(
                    "browser-download-dropper-guard",
                    "block",
                    identity,
                    f"Blocked browser automation download of executable or archive content from sensitive domain {domain}.",
                    "Avoid using authenticated browser sessions to fetch executable or archive payloads directly into the local runtime.",
                ),
            }
        if identity["has_export"] or identity["has_bulk_capture"]:
            return {
                "identity": identity,
                "hit": _hit(
                    "browser-sensitive-export-guard",
                    "block",
                    identity,
                    f"Blocked browser automation export against sensitive domain {domain}.",
                    f"Review the browser task and run `./bin/runwall browser allow {domain}` only if exporting from that session is expected.",
                ),
            }
        if approval_hit:
            return {"identity": identity, "hit": approval_hit}
        if domain in allowed or approval:
            continue
        return {
            "identity": identity,
            "hit": _hit(
                "browser-sensitive-domain-guard",
                "prompt",
                identity,
                f"Review required before browser automation drives sensitive domain {domain}.",
                f"Run `./bin/runwall browser allow {domain}` if this domain is part of your reviewed browser automation workflow.",
            ),
        }
    return {"identity": identity, "hit": None}


def list_domains(root: pathlib.Path) -> list[dict[str, Any]]:
    items = []
    for domain, record in load_store(root).get("domains", {}).items():
        if isinstance(record, dict):
            items.append({"domain": domain, **record})
    items.sort(key=lambda item: item["domain"])
    return items


def allow_domain(root: pathlib.Path, domain: str) -> None:
    store = load_store(root)
    normalized = _normalize_domain(domain)
    allowlist = {_normalize_domain(item) for item in store.get("allowlist", []) if isinstance(item, str)}
    allowlist.add(normalized)
    store["allowlist"] = sorted(allowlist)
    save_store(root, store)
    runwall_approvals.create_approval(
        root,
        kind="browser",
        target="domain",
        value=normalized,
        repo=str(root.resolve(strict=False)),
    )


def revoke_domain(root: pathlib.Path, domain: str) -> bool:
    store = load_store(root)
    normalized = _normalize_domain(domain)
    allowlist = [_normalize_domain(item) for item in store.get("allowlist", []) if isinstance(item, str)]
    if normalized not in allowlist:
        return False
    store["allowlist"] = [item for item in allowlist if item != normalized]
    save_store(root, store)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage Runwall browser automation trust")
    parser.add_argument("--root", required=True)
    subparsers = parser.add_subparsers(dest="command", required=True)
    sessions_parser = subparsers.add_parser("sessions")
    sessions_parser.add_argument("--json", action="store_true")
    allow_parser = subparsers.add_parser("allow")
    allow_parser.add_argument("domain")
    revoke_parser = subparsers.add_parser("revoke")
    revoke_parser.add_argument("domain")
    policy_parser = subparsers.add_parser("policy")
    policy_parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    root = pathlib.Path(args.root)
    if args.command == "sessions":
        sessions = list_domains(root)
        if args.json:
            print(json.dumps({"domains": sessions}, indent=2))
        else:
            print("Browser Domains:")
            for item in sessions:
                print(f"- {item['domain']} [{item.get('trust_state')}]")
        return 0
    if args.command == "allow":
        allow_domain(root, args.domain)
        print(f"allowed {args.domain}")
        return 0
    if args.command == "revoke":
        if revoke_domain(root, args.domain):
            print(f"revoked {args.domain}")
            return 0
        print(f"unknown domain: {args.domain}", file=os.sys.stderr)
        return 1
    if args.command == "policy":
        payload = load_store(root)
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print("Allowed Browser Domains:")
            for item in payload.get("allowlist", []):
                print(f"- {item}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
