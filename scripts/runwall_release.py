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

import runwall_approvals


URL_RE = re.compile(r"(?i)\bhttps?://[^\s'\"<>]+")
HOST_RE = re.compile(r"(?i)https?://(?P<host>[^/\s:]+)")
RAW_HOST_RE = re.compile(r"(?i)(?:raw\.githubusercontent\.com|gist\.githubusercontent\.com|pastebin\.com|transfer\.sh|tmpfiles\.org|file\.io|discord(?:app)?\.com/api/webhooks|hooks\.slack\.com)")
PROD_RE = re.compile(r"(?i)\b(prod|production|live|release|stable|primary)\b")
PACKAGE_PUBLISH_RE = re.compile(r"(?i)\b(?:npm|pnpm|yarn)\s+(?:publish|npm\s+publish)\b|\btwine\s+upload\b|\bpoetry\s+publish\b|\bcargo\s+publish\b|\bgem\s+push\b|\buv\s+publish\b")
IMAGE_PUSH_RE = re.compile(r"(?i)\b(?:docker|podman|nerdctl|buildah|oras|crane)\s+(?:push|manifest\s+push)\b|\bdocker\s+buildx\s+build\b[^\n\r]{0,120}\s--push\b")
BINARY_RELEASE_RE = re.compile(r"(?i)\bgh\s+release\s+(?:create|upload)\b|\baws\s+s3\s+cp\b[^\n\r]{0,160}\b(?:release|releases|downloads)\b|\bgsutil\s+cp\b[^\n\r]{0,160}\b(?:release|releases|downloads)\b")
SECRET_BUNDLE_RE = re.compile(r"(?i)\b(?:npm|pnpm|yarn|twine|poetry|cargo|gem|docker|podman|gh\s+release|aws\s+s3\s+cp|gsutil\s+cp)\b[^\n\r]{0,220}(?:\.env\b|id_(?:rsa|ed25519)|\.pem\b|\.p12\b|\.pfx\b|credentials?\.(?:json|ya?ml|toml|env)|secrets?\.(?:json|ya?ml|toml|env)|token\b)")
SIGNING_BYPASS_RE = re.compile(r"(?i)(?:--no-sign\b|--skip-sign\b|--skip-signing\b|--provenance\s*=\s*false|--sbom\s*=\s*false|--attest(?:ation)?\s*=\s*false|COSIGN_NO_SIGN|SKIP_SIGN(?:ING)?=1|SKIP_PROVENANCE=1)")
CHANNEL_SWAP_RE = re.compile(r"(?i)(?:--registry(?:=|\s+)|--repository(?:=|\s+)|--publish-url(?:=|\s+)|--channel(?:=|\s+)|publishConfig|registry:|repository:|upload_url|release_url)")
MANIFEST_PATH_RE = re.compile(r"(?i)(?:^|/)(?:package\.json|pyproject\.toml|Cargo\.toml|Dockerfile|docker-compose\.ya?ml|compose\.ya?ml|Chart\.yaml|values\.ya?ml|\.github/workflows/[^/]+\.(?:yml|yaml))$")
UNREVIEWED_TARGET_RE = re.compile(r"(?i)(?:raw\.githubusercontent\.com|githubusercontent\.com|pastebin\.com|tmpfiles\.org|transfer\.sh|ngrok-free\.app|trycloudflare\.com)")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def state_dir(root: pathlib.Path) -> pathlib.Path:
    home = os.environ.get("RUNWALL_HOME") or os.environ.get("SECURE_CLAUDE_CODE_HOME")
    if home:
        return pathlib.Path(home) / "state"
    return pathlib.Path(os.path.expanduser("~")) / ".runwall" / "state"


def policy_path(root: pathlib.Path) -> pathlib.Path:
    return root / "config" / "release-policy.json"


def release_store_path(root: pathlib.Path) -> pathlib.Path:
    return state_dir(root) / "releases.json"


def load_policy(root: pathlib.Path) -> dict[str, Any]:
    path = policy_path(root)
    if not path.exists():
        return {
            "reviewed_hosts": ["github.com", "npmjs.com", "registry.npmjs.org", "pypi.org", "files.pythonhosted.org", "ghcr.io", "docker.io", "pkg.go.dev", "crates.io", "rubygems.org"],
            "prod_keywords": ["prod", "production", "live", "release", "stable"],
            "manifest_paths": ["package.json", "pyproject.toml", "Cargo.toml", "Dockerfile", "docker-compose.yml", "compose.yml", "Chart.yaml", ".github/workflows/release.yml"],
        }
    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {"reviewed_hosts": [], "prod_keywords": [], "manifest_paths": []}
    if not isinstance(payload, dict):
        return {"reviewed_hosts": [], "prod_keywords": [], "manifest_paths": []}
    payload.setdefault("reviewed_hosts", [])
    payload.setdefault("prod_keywords", [])
    payload.setdefault("manifest_paths", [])
    return payload


def load_store(root: pathlib.Path) -> dict[str, Any]:
    path = release_store_path(root)
    if not path.exists():
        return {"version": 1, "targets": {}}
    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {"version": 1, "targets": {}}
    if not isinstance(payload, dict):
        return {"version": 1, "targets": {}}
    payload.setdefault("version", 1)
    payload.setdefault("targets", {})
    return payload


def save_store(root: pathlib.Path, store: dict[str, Any]) -> None:
    path = release_store_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(store, indent=2, sort_keys=True) + "\n")


def _shell_split(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=os.name != "nt")
    except ValueError:
        return [token for token in command.strip().split() if token]


def _normalize_path(token: str) -> pathlib.Path:
    cleaned = token.strip("'\"= ")
    expanded = os.path.expanduser(cleaned)
    path = pathlib.Path(expanded)
    if not path.is_absolute():
        path = pathlib.Path(os.path.abspath(str(pathlib.Path.cwd() / path)))
    return path


def _fingerprint(identity: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(identity, sort_keys=True).encode("utf-8")).hexdigest()


def _host_from_payload(payload: str) -> str | None:
    url_match = URL_RE.search(payload)
    if url_match:
        host_match = HOST_RE.search(url_match.group(0))
        if host_match:
            return host_match.group("host").lower()
    split = _shell_split(payload)
    for token in split:
        if "." in token and "/" in token and not token.startswith("/"):
            host = token.split("/", 1)[0].lower()
            if "." in host:
                return host
    return None


def _target_from_manifest(path: pathlib.Path, content: str) -> tuple[str, str] | None:
    host = _host_from_payload(content or "")
    if host:
        return (host, "manifest-target")
    if PROD_RE.search(content or ""):
        return (str(path), "manifest-prod")
    return None


def _identity_from_bash(root: pathlib.Path, payload: str) -> dict[str, Any] | None:
    host = _host_from_payload(payload)
    if PACKAGE_PUBLISH_RE.search(payload):
        return {"target": host or "package-publish", "release_class": "package-publish", "fingerprint": _fingerprint({"kind": "package", "target": host or "package-publish"})}
    if IMAGE_PUSH_RE.search(payload):
        return {"target": host or "image-push", "release_class": "image-push", "fingerprint": _fingerprint({"kind": "image", "target": host or "image-push"})}
    if BINARY_RELEASE_RE.search(payload):
        return {"target": host or "binary-release", "release_class": "binary-release", "fingerprint": _fingerprint({"kind": "binary", "target": host or "binary-release"})}
    if SIGNING_BYPASS_RE.search(payload) and (PACKAGE_PUBLISH_RE.search(payload) or IMAGE_PUSH_RE.search(payload) or BINARY_RELEASE_RE.search(payload)):
        return {"target": host or "release-signing", "release_class": "release-signing", "fingerprint": _fingerprint({"kind": "signing", "target": host or "release-signing"})}
    if CHANNEL_SWAP_RE.search(payload) and (PACKAGE_PUBLISH_RE.search(payload) or IMAGE_PUSH_RE.search(payload) or BINARY_RELEASE_RE.search(payload)):
        return {"target": host or "channel-swap", "release_class": "release-target", "fingerprint": _fingerprint({"kind": "channel", "target": host or "channel-swap"})}
    if PROD_RE.search(payload) and (PACKAGE_PUBLISH_RE.search(payload) or IMAGE_PUSH_RE.search(payload) or BINARY_RELEASE_RE.search(payload)):
        return {"target": host or "prod-release", "release_class": "prod-release", "fingerprint": _fingerprint({"kind": "prod", "target": host or "prod-release"})}
    return None


def _identity_from_fileop(payload: str) -> dict[str, Any] | None:
    tokens = _shell_split(payload)
    if not tokens:
        return None
    path = _normalize_path(tokens[0])
    if not MANIFEST_PATH_RE.search(str(path).replace("\\", "/")):
        return None
    content = payload[len(tokens[0]) :].strip()
    target = _target_from_manifest(path, content)
    if not target:
        return None
    target_value, release_class = target
    return {
        "target": target_value,
        "release_class": release_class,
        "path": str(path),
        "fingerprint": _fingerprint({"kind": "manifest", "path": str(path), "target": target_value, "class": release_class}),
    }


def _hit(module: str, decision: str, identity: dict[str, Any], reason: str, safer: str) -> dict[str, Any]:
    return {
        "module": module,
        "name": module.replace("-", " ").title(),
        "category": "release-trust",
        "family": "Publish, Release & Supply Chain",
        "decision": decision,
        "exit_code": 2 if decision == "block" else 0,
        "output": reason,
        "metadata": {
            "reason": reason,
            "confidence": 0.95 if decision == "block" else 0.84,
            "safer_alternative": safer,
            "release_identity": identity,
        },
    }


def assess_action(root: pathlib.Path, event: str, matcher: str, payload: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
    if event != "PreToolUse":
        return {"identity": None, "hit": None}
    identity = None
    if matcher == "Bash":
        identity = _identity_from_bash(root, payload)
    elif matcher in {"Write", "Edit", "MultiEdit"}:
        identity = _identity_from_fileop(payload)
    if not identity:
        return {"identity": None, "hit": None}

    policy = load_policy(root)
    reviewed_hosts = {str(item).lower() for item in policy.get("reviewed_hosts", [])}
    target = str(identity["target"])
    release_class = str(identity["release_class"])
    ctx = context or {}
    approval_assessment = runwall_approvals.assess_match(
        root,
        kind="release",
        target=release_class,
        value=target,
        runtime=str(ctx.get("runtime")) if ctx.get("runtime") else None,
        repo=str(root.resolve(strict=False)),
        agent_id=str(ctx.get("subagent_id") or ctx.get("agent_id")) if (ctx.get("subagent_id") or ctx.get("agent_id")) else None,
        fingerprint=str(identity["fingerprint"]),
    )
    approval = approval_assessment.get("approval")
    approval_hit = approval_assessment.get("hit")
    store = load_store(root)
    existing = store.setdefault("targets", {}).get(target)
    trust_state = "observed"
    hit = None

    host = _host_from_payload(payload) or (target if "." in target else None)
    unreviewed_target = bool(host) and host.lower() not in reviewed_hosts
    raw_target = bool(host) and RAW_HOST_RE.search(host or "")

    if SIGNING_BYPASS_RE.search(payload):
        trust_state = "blocked"
        hit = _hit(
            "release-signing-bypass-guard",
            "block",
            identity,
            f"Blocked release or publish command that disables signing, provenance, or attestation for {target}.",
            "Keep signing, provenance, and attestation enabled on release and publish paths.",
        )
    elif SECRET_BUNDLE_RE.search(payload):
        trust_state = "blocked"
        hit = _hit(
            "release-secret-bundle-guard",
            "block",
            identity,
            f"Blocked release or publish path that appears to bundle secrets, keys, or credentials into {target}.",
            "Keep secret-bearing files and key material out of release uploads, publishes, and image pushes.",
        )
    elif matcher in {"Write", "Edit", "MultiEdit"} and release_class == "manifest-target" and (UNREVIEWED_TARGET_RE.search(payload) or raw_target or unreviewed_target):
        trust_state = "prompted"
        hit = _hit(
            "release-manifest-target-guard",
            "prompt",
            identity,
            f"Review required before changing manifest or workflow release target to {target}.",
            "Only promote new publish registries, artifact endpoints, or workflow targets after review.",
        )
    elif CHANNEL_SWAP_RE.search(payload) and (raw_target or unreviewed_target):
        trust_state = "prompted"
        hit = _hit(
            "release-channel-swap-guard",
            "prompt",
            identity,
            f"Review required before retargeting release channel or registry to {target}.",
            "Keep publish channels and registries pinned to reviewed destinations.",
        )
    elif existing and isinstance(existing, dict) and existing.get("trust_state") == "approved" and existing.get("fingerprint") != identity["fingerprint"]:
        trust_state = "prompted"
        hit = _hit(
            "registry-publish-drift-guard",
            "prompt",
            identity,
            f"Review required because the reviewed release target drifted for {target}.",
            f"Run `./bin/runwall release diff {target}` and re-approve only if this publish target is still expected.",
        )
    elif BINARY_RELEASE_RE.search(payload):
        trust_state = "prompted"
        module = "binary-release-upload-guard"
        reason = f"Review required before uploading release artifacts to {target}."
        safer = "Use a reviewed release workflow or one-shot approval before publishing binary artifacts."
        if approval:
            trust_state = "approved"
        elif approval_hit:
            trust_state = "prompted"
            hit = approval_hit
        else:
            hit = _hit(module, "prompt", identity, reason, safer)
    elif IMAGE_PUSH_RE.search(payload):
        trust_state = "prompted"
        module = "image-push-prod-guard" if PROD_RE.search(payload) else "unexpected-publish-target-guard"
        reason = (
            f"Review required before pushing production-like container images to {target}."
            if module == "image-push-prod-guard"
            else f"Review required before pushing container images to {target}."
        )
        safer = "Keep image pushes behind reviewed registry and environment boundaries."
        if approval:
            trust_state = "approved"
        elif approval_hit:
            trust_state = "prompted"
            hit = approval_hit
        else:
            hit = _hit(module, "prompt", identity, reason, safer)
    elif PACKAGE_PUBLISH_RE.search(payload):
        trust_state = "prompted"
        module = "prod-promote-guard" if PROD_RE.search(payload) else "package-publish-prod-guard"
        reason = (
            f"Review required before promoting or publishing production-bound package artifacts to {target}."
            if module == "prod-promote-guard"
            else f"Review required before publishing package artifacts to {target}."
        )
        safer = "Use a reviewed publish path or one-shot approval before shipping package artifacts."
        if approval:
            trust_state = "approved"
        elif approval_hit:
            trust_state = "prompted"
            hit = approval_hit
        else:
            hit = _hit(module, "prompt", identity, reason, safer)
    elif unreviewed_target:
        trust_state = "prompted"
        if approval:
            trust_state = "approved"
        elif approval_hit:
            trust_state = "prompted"
            hit = approval_hit
        else:
            hit = _hit(
                "unexpected-publish-target-guard",
                "prompt",
                identity,
                f"Review required before releasing or publishing to unreviewed target {target}.",
                "Keep publish and release edges pointed at reviewed registries, artifact stores, or release hosts.",
            )
    else:
        trust_state = "trusted"

    stored_state = trust_state
    if (
        trust_state in {"blocked", "prompted"}
        and isinstance(existing, dict)
        and existing.get("trust_state") == "approved"
        and existing.get("fingerprint") == identity["fingerprint"]
    ) or approval:
        stored_state = "approved"

    record = {
        "target": target,
        "release_class": release_class,
        "fingerprint": identity["fingerprint"],
        "path": identity.get("path"),
        "trust_state": stored_state,
        "last_observed_state": trust_state,
        "first_seen_at": existing.get("first_seen_at") if isinstance(existing, dict) else utc_now(),
        "last_seen_at": utc_now(),
        "last_reason": hit["module"] if hit else (existing or {}).get("last_reason"),
    }
    store["targets"][target] = record
    save_store(root, store)
    return {"identity": identity, "hit": hit}


def list_targets(root: pathlib.Path) -> list[dict[str, Any]]:
    items = [dict(value) for value in load_store(root).get("targets", {}).values() if isinstance(value, dict)]
    items.sort(key=lambda item: (item.get("release_class", ""), item.get("target", "")))
    return items


def approve_target(root: pathlib.Path, selector: str, *, once: bool = False) -> bool:
    store = load_store(root)
    record = store.setdefault("targets", {}).get(selector)
    if not isinstance(record, dict):
        for key, value in store.get("targets", {}).items():
            if isinstance(value, dict) and value.get("target") == selector:
                selector = key
                record = value
                break
    if not isinstance(record, dict):
        return False
    runwall_approvals.create_approval(
        root,
        kind="release",
        target=str(record.get("release_class")),
        value=str(record.get("target")),
        repo=str(root.resolve(strict=False)),
        once=once,
        fingerprint=str(record.get("fingerprint")),
    )
    record["trust_state"] = "approved"
    store["targets"][selector] = record
    save_store(root, store)
    return True


def forget_target(root: pathlib.Path, selector: str) -> bool:
    store = load_store(root)
    targets = store.setdefault("targets", {})
    if selector in targets:
        targets.pop(selector, None)
        save_store(root, store)
        return True
    return False


def diff_target(root: pathlib.Path, selector: str) -> dict[str, Any] | None:
    payload = load_store(root).get("targets", {}).get(selector)
    if isinstance(payload, dict):
        return payload
    for item in load_store(root).get("targets", {}).values():
        if isinstance(item, dict) and item.get("target") == selector:
            return item
    return None


def policy_payload(root: pathlib.Path) -> dict[str, Any]:
    policy = load_policy(root)
    return {
        "reviewed_hosts": policy.get("reviewed_hosts", []),
        "guards": [
            "unexpected-publish-target-guard",
            "prod-promote-guard",
            "registry-publish-drift-guard",
            "release-manifest-target-guard",
            "image-push-prod-guard",
            "package-publish-prod-guard",
            "binary-release-upload-guard",
            "release-secret-bundle-guard",
            "release-signing-bypass-guard",
            "release-channel-swap-guard",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage Runwall publish and release trust")
    parser.add_argument("--root", required=True)
    subparsers = parser.add_subparsers(dest="command", required=True)
    list_parser = subparsers.add_parser("list")
    list_parser.add_argument("--json", action="store_true")
    approve_parser = subparsers.add_parser("approve")
    approve_parser.add_argument("selector")
    approve_parser.add_argument("--once", action="store_true")
    forget_parser = subparsers.add_parser("forget")
    forget_parser.add_argument("selector")
    diff_parser = subparsers.add_parser("diff")
    diff_parser.add_argument("selector")
    policy_parser = subparsers.add_parser("policy")
    policy_parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    root = pathlib.Path(args.root)

    if args.command == "list":
        items = list_targets(root)
        if args.json:
            print(json.dumps({"targets": items}, indent=2))
        else:
            print("Release Targets:")
            for item in items:
                print(f"- {item.get('release_class')} [{item.get('trust_state')}] {item.get('target')}")
        return 0
    if args.command == "approve":
        if approve_target(root, args.selector, once=bool(args.once)):
            print(f"approved {args.selector}")
            return 0
        print(f"unknown release target: {args.selector}", file=os.sys.stderr)
        return 1
    if args.command == "forget":
        if forget_target(root, args.selector):
            print(f"forgot {args.selector}")
            return 0
        print(f"unknown release target: {args.selector}", file=os.sys.stderr)
        return 1
    if args.command == "diff":
        payload = diff_target(root, args.selector)
        if payload is None:
            print(f"unknown release target: {args.selector}", file=os.sys.stderr)
            return 1
        print(json.dumps(payload, indent=2))
        return 0
    if args.command == "policy":
        payload = policy_payload(root)
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print("Reviewed Release Hosts:")
            for item in payload["reviewed_hosts"]:
                print(f"- {item}")
            print("Guards:")
            for item in payload["guards"]:
                print(f"- {item}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
