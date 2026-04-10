#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
from datetime import datetime, timezone
from typing import Any

import runwall_destructive_surface


MASS_DELETE_RE = re.compile(r"(?i)\brm\s+-[A-Za-z]*r[fA-Za-z]*\s+(?:/|~|\.|/\w|\.git|dist|build|release|releases)|\bgit\s+rm\s+-r\b|\bfind\b[^\n\r]{0,120}-delete\b")
ENV_DESTROY_RE = re.compile(r"(?i)(?:vercel\s+env\s+rm\b|kubectl\s+delete\s+configmap\b|kubectl\s+delete\s+secret\b|supabase\s+secrets?\s+unset\b|terraform\s+workspace\s+delete\b[^\n\r]{0,80}\bprod(?:uction)?\b)")
SECRET_REVOKE_RE = re.compile(r"(?i)(?:delete-access-key|revoke-token|tokens?\s+delete\b[^\n\r]{0,120}\ball\b|secret(?:s)?\s+(?:delete|rm)\b[^\n\r]{0,120}\ball\b|aws\s+iam\s+delete-access-key\b)")
ROLE_REMOVE_RE = re.compile(r"(?i)(?:remove-admin|remove owner|revoke admin|detach-user-policy|remove-iam-policy-binding|gh\s+api\b[^\n\r]{0,160}(?:collaborators|teams).*(?:DELETE|--method\s+DELETE))")
INFRA_TEARDOWN_RE = re.compile(r"(?i)\b(?:terraform|tofu|terragrunt)\s+destroy\b|\bpulumi\s+destroy\b|\bkubectl\s+delete\s+namespace\b[^\n\r]{0,80}\b(prod|production)\b|\bhelm\s+uninstall\b[^\n\r]{0,80}\b(prod|production)\b")
REPO_WIPE_RE = re.compile(r"(?i)(?:git\s+push\b[^\n\r]{0,120}--mirror\b[^\n\r]{0,80}--force|git\s+filter-repo\b|gh\s+repo\s+delete\b|git\s+push\b[^\n\r]{0,160}:refs/heads/)")
ARTIFACT_WIPE_RE = re.compile(r"(?i)(?:rm\s+-[A-Za-z]*r[fA-Za-z]*\s+[^\n\r]*(?:dist|build|release|releases|artifacts?|sbom|provenance|bundle)|aws\s+s3\s+rm\b[^\n\r]{0,160}(?:release|artifact)s?\b[^\n\r]{0,80}--recursive\b)")
STATE_DESTROY_RE = re.compile(r"(?i)(?:rm\s+-[A-Za-z]*f\b[^\n\r]*(?:terraform\.tfstate|Pulumi\.[^.]+\.yaml|\.pulumi|state\.json)|terraform\s+state\s+rm\b|\bpulumi\s+state\s+delete\b)")
BULK_DISABLE_RE = re.compile(r"(?i)(?:for\s+\w+\s+in\b[^\n\r]{0,160}(?:delete|disable|rm|revoke)|xargs\b[^\n\r]{0,160}(?:delete|disable|rm|revoke)|parallel\b[^\n\r]{0,160}(?:delete|disable|rm|revoke))")
BLAST_RADIUS_RE = re.compile(r"(?i)(?:--all\b|--all-namespaces\b|--prune\b|--recursive\b|delete all\b|remove all\b|revoke all\b|drop database\b)")
TRUNCATE_CLEAR_RE = re.compile(r"(?i)(?:\btruncate\s+-s\s+0\b|:\s*>\s*\S+|\bClear-Content\b|\bSet-Content\b[^\n\r]{0,120}(?:''|\"\"|'\s*'|\"\s*\")|dd\s+if=/dev/zero\b[^\n\r]{0,160}\bof=)")
DB_DESTROY_RE = re.compile(r"(?i)(?:drop\s+table\b|truncate\s+table\b|drop\s+database\b|prisma\s+migrate\s+reset\b|rails\s+db:(?:drop|reset)\b|sequelize\s+db:(?:drop|reset)\b|redis-cli\b[^\n\r]{0,80}\bflush(?:all|db)\b)")
CLOUD_DESTROY_RE = re.compile(r"(?i)(?:aws\s+s3\s+rb\b[^\n\r]{0,120}\s--force\b|aws\s+ec2\s+delete-snapshot\b|aws\s+ec2\s+delete-volume\b|aws\s+sqs\s+purge-queue\b|aws\s+sns\s+delete-topic\b|aws\s+kinesis\s+delete-stream\b|gcloud\s+storage\s+rm\b[^\n\r]{0,120}\s-r\b|gcloud\s+compute\s+disks\s+delete\b|gcloud\s+pubsub\s+topics\s+delete\b|az\s+storage\s+blob\s+delete-batch\b|az\s+disk\s+delete\b|az\s+snapshot\s+delete\b|docker\s+volume\s+rm\b|docker\s+system\s+prune\b[^\n\r]{0,120}\s--volumes\b)")
KEY_DESTROY_RE = re.compile(r"(?i)(?:aws\s+kms\s+schedule-key-deletion\b|aws\s+kms\s+disable-key\b|gcloud\s+kms\s+keys\s+versions\s+destroy\b|az\s+keyvault\s+(?:key|secret)\s+(?:delete|purge)\b|gpg\s+--delete-secret-keys\b|security\s+delete-keychain\b)")
RANSOMWARE_RE = re.compile(r"(?i)(?:openssl\s+enc\b[^\n\r]{0,200}(?:^|\s)-in\b|gpg\s+-c\b|age\s+-e\b|7z\s+a\b[^\n\r]{0,160}\s-p)")
SCHEDULED_DESTRUCTION_RE = re.compile(r"(?i)(?:crontab\b|schtasks\b|launchctl\b|systemd-run\b|at\b|onCalendar=|@reboot|postinstall|preinstall|rc\.local)[^\n\r]{0,260}(?:rm\s+-[A-Za-z]*r[fA-Za-z]*|truncate\s+-s\s+0|terraform\s+destroy|drop\s+table|openssl\s+enc|gpg\s+-c|age\s+-e|chmod\s+0{3}\b)")
RESOURCE_EXHAUST_RE = re.compile(r"(?i)(?:fallocate\s+-l\b|dd\s+if=/dev/zero\b[^\n\r]{0,160}\bof=|yes\s+>\s*\S+|:\(\)\s*\{\s*:\|:&\s*\};:|fsutil\s+file\s+createnew\b)")
ICACLS_LOCKOUT_RE = re.compile(r"(?i)\bicacls\b[^\n\r]{0,180}\b/deny\b")
SETFACL_LOCKOUT_RE = re.compile(r"(?i)\bsetfacl\b[^\n\r]{0,180}(?:---|0\b)")
CHATTR_LOCKOUT_RE = re.compile(r"(?i)\bchattr\b[^\n\r]{0,80}\+(?:i|a)\b")
LINK_SWAP_RE = re.compile(r"(?i)(?:\bln\b[^\n\r]{0,40}\s-s\b|\bmklink\b|\bNew-Item\b[^\n\r]{0,120}\bSymbolicLink\b|\bmount\b[^\n\r]{0,120}\b(?:--bind|-o\s+bind)\b)")
DELETE_FROM_RE = re.compile(r"(?i)\bdelete\s+from\b")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def state_dir(root: pathlib.Path) -> pathlib.Path:
    home = os.environ.get("RUNWALL_HOME") or os.environ.get("SECURE_CLAUDE_CODE_HOME")
    if home:
        return pathlib.Path(home) / "state"
    return pathlib.Path(os.path.expanduser("~")) / ".runwall" / "state"


def destructive_store_path(root: pathlib.Path) -> pathlib.Path:
    return state_dir(root) / "destructive.json"


def load_store(root: pathlib.Path) -> dict[str, Any]:
    path = destructive_store_path(root)
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
    path = destructive_store_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(store, indent=2, sort_keys=True) + "\n")


def _identity(module: str, payload: str, target: str) -> dict[str, Any]:
    return {"module": module, "target": target, "preview": payload[:220]}


def _hit(module: str, decision: str, identity: dict[str, Any], reason: str, safer: str) -> dict[str, Any]:
    return {
        "module": module,
        "name": module.replace("-", " ").title(),
        "category": "destructive-intent",
        "family": "Destructive Actions & Blast Radius",
        "decision": decision,
        "exit_code": 2 if decision == "block" else 0,
        "output": reason,
        "metadata": {
            "reason": reason,
            "confidence": 0.95 if decision == "block" else 0.84,
            "safer_alternative": safer,
            "destructive_identity": identity,
        },
    }


def _extract_target(payload: str) -> str:
    match = re.search(r"(?i)(?:\s|^)(/[^\s]+|~[^\s]+|[A-Za-z0-9._/-]+(?::[A-Za-z0-9._/-]+)?)", payload)
    if match:
        return match.group(1)
    return "runtime"


def _profile(context: dict[str, Any] | None) -> str:
    return str((context or {}).get("profile") or "balanced").lower()


def _identity(module: str, payload: str, target: str, *, surface: str | None = None, tier: int | None = None) -> dict[str, Any]:
    identity = {"module": module, "target": target, "preview": payload[:220]}
    if surface:
        identity["surface"] = surface
    if tier is not None:
        identity["tier"] = tier
    return identity


def _path_like(token: str) -> bool:
    return token.startswith("/") or token.startswith("~") or "/" in token or token.endswith((".json", ".yaml", ".yml", ".toml", ".conf", ".ini", ".md", ".txt", ".sh", ".py", ".sql", ".env"))


def _destructive_path_target(tokens: list[str], payload: str) -> tuple[pathlib.Path | None, str | None]:
    for token in tokens:
        if token.startswith("-"):
            continue
        if _path_like(token):
            path = runwall_destructive_surface.normalize_path_token(token)
            return path, runwall_destructive_surface.classify_path(path)
    match = re.search(r"(?i)\bof=(?P<target>[^\s]+)", payload)
    if match:
        path = runwall_destructive_surface.normalize_path_token(match.group("target"))
        return path, runwall_destructive_surface.classify_path(path)
    return None, None


def _move_away_hit(payload: str) -> dict[str, Any] | None:
    tokens = runwall_destructive_surface.shell_split(payload)
    if not tokens:
        return None
    if tokens[0] == "git" and len(tokens) >= 4 and tokens[1] == "mv":
        src_token, dest_token = tokens[-2], tokens[-1]
    elif tokens[0] in {"mv", "move", "ren", "rename"} and len(tokens) >= 3:
        src_token, dest_token = tokens[-2], tokens[-1]
    else:
        return None
    src_path = runwall_destructive_surface.normalize_path_token(src_token)
    src_surface = runwall_destructive_surface.classify_path(src_path)
    dest_lower = dest_token.lower()
    if not runwall_destructive_surface.is_critical_surface(src_surface):
        return None
    if not re.search(r"(?i)(?:\.bak\b|\.old\b|\.disabled\b|\.off\b|/tmp/|/var/tmp/|/trash/|/cache/|backup|archive)", dest_lower):
        return None
    module = "move-away-destruction-guard"
    identity = _identity(module, payload, str(src_path), surface=src_surface, tier=1)
    return _hit(
        module,
        "block",
        identity,
        f"Blocked move-away destructive path for critical surface {src_path}.",
        "Keep critical trust files in place or move them only through a reviewed recovery or migration workflow.",
    )


def _truncate_or_clear_hit(payload: str) -> dict[str, Any] | None:
    if not TRUNCATE_CLEAR_RE.search(payload):
        return None
    tokens = runwall_destructive_surface.shell_split(payload)
    path, surface = _destructive_path_target(tokens, payload)
    if path is None:
        return None
    decision = "block" if runwall_destructive_surface.is_critical_surface(surface or "") else "prompt"
    module = "truncate-clear-guard"
    identity = _identity(module, payload, str(path), surface=surface, tier=1)
    return _hit(
        module,
        decision,
        identity,
        f"Blocked destructive truncate or clear path for {path}." if decision == "block" else f"Review required before truncating or clearing {path}.",
        "Prefer reviewed file replacement or targeted cleanup over silent truncate, clear, or zero-fill behavior.",
    )


def _permission_lockout_hit(payload: str) -> dict[str, Any] | None:
    lowered = payload.lower()
    if "chmod" not in lowered and "icacls" not in lowered and "setfacl" not in lowered and "chattr" not in lowered:
        return None
    tokens = runwall_destructive_surface.shell_split(payload)
    path, surface = _destructive_path_target(tokens, payload)
    if path is None:
        return None
    lockout = False
    if re.search(r"(?i)\bchmod\b[^\n\r]{0,120}\b(?:000|0)\b", payload):
        lockout = True
    elif re.search(r"(?i)\bchmod\b[^\n\r]{0,120}\s-x\b", payload):
        lockout = True
    elif ICACLS_LOCKOUT_RE.search(payload) or SETFACL_LOCKOUT_RE.search(payload) or CHATTR_LOCKOUT_RE.search(payload):
        lockout = True
    if not lockout:
        return None
    decision = "block" if runwall_destructive_surface.is_critical_surface(surface or "") else "prompt"
    module = "permission-lockout-guard"
    identity = _identity(module, payload, str(path), surface=surface, tier=1)
    return _hit(
        module,
        decision,
        identity,
        f"Blocked destructive permission lockout on {path}." if decision == "block" else f"Review required before permission lockout style change on {path}.",
        "Keep access-control changes narrow and reviewed, especially on policy, recovery, release, and credential-bearing files.",
    )


def _tier_two_hit(payload: str) -> dict[str, Any] | None:
    tokens = runwall_destructive_surface.shell_split(payload)
    if DB_DESTROY_RE.search(payload):
        module = "database-destroy-guard"
        identity = _identity(module, payload, _extract_target(payload), tier=2)
        return _hit(
            module,
            "block",
            identity,
            "Blocked destructive database reset, drop, truncate, or flush path.",
            "Use a reviewed migration or recovery workflow instead of ad hoc destructive database commands from the runtime.",
        )
    if DELETE_FROM_RE.search(payload) and " where " not in payload.lower():
        module = "database-bulk-delete-guard"
        identity = _identity(module, payload, _extract_target(payload), tier=2)
        return _hit(
            module,
            "prompt",
            identity,
            "Review required before broad database delete without an obvious WHERE clause.",
            "Reduce the delete scope or move the data change into a reviewed migration or admin workflow.",
        )
    if CLOUD_DESTROY_RE.search(payload):
        module = "cloud-resource-destroy-guard"
        identity = _identity(module, payload, _extract_target(payload), tier=2)
        return _hit(
            module,
            "block",
            identity,
            "Blocked destructive cloud or storage resource deletion path.",
            "Keep bucket, volume, queue, topic, stream, and snapshot destruction behind reviewed operational workflows.",
        )
    if KEY_DESTROY_RE.search(payload):
        module = "key-destroy-guard"
        identity = _identity(module, payload, _extract_target(payload), tier=2)
        return _hit(
            module,
            "prompt",
            identity,
            "Review required before deleting or disabling encryption, signing, or recovery key material.",
            "Use a reviewed key lifecycle workflow and confirm all dependent systems and recovery paths first.",
        )
    if RANSOMWARE_RE.search(payload):
        path, surface = _destructive_path_target(tokens, payload)
        if path is not None and runwall_destructive_surface.is_critical_surface(surface or ""):
            module = "ransomware-intent-guard"
            identity = _identity(module, payload, str(path), surface=surface, tier=2)
            return _hit(
                module,
                "prompt",
                identity,
                f"Review required before encrypting or rewrapping critical local asset {path}.",
                "Keep encryption and rekey flows off critical local trust surfaces unless the exact backup or rotation workflow is separately reviewed.",
            )
    if LINK_SWAP_RE.search(payload):
        path, surface = _destructive_path_target(tokens[::-1], payload)
        if path is not None and runwall_destructive_surface.is_critical_surface(surface or ""):
            module = "indirection-swap-guard"
            identity = _identity(module, payload, str(path), surface=surface, tier=2)
            return _hit(
                module,
                "block",
                identity,
                f"Blocked indirection swap targeting critical surface {path}.",
                "Edit critical files directly instead of redirecting them through symlink, junction, or bind-style indirection.",
            )
    return None


def _tier_three_hit(payload: str) -> dict[str, Any] | None:
    if SCHEDULED_DESTRUCTION_RE.search(payload):
        module = "delayed-destruction-guard"
        identity = _identity(module, payload, _extract_target(payload), tier=3)
        return _hit(
            module,
            "prompt",
            identity,
            "Review required before scheduling delayed destructive automation.",
            "Keep cron, task scheduler, launch agent, and startup automation free of destructive actions unless the exact maintenance flow was reviewed.",
        )
    if RESOURCE_EXHAUST_RE.search(payload):
        module = "resource-exhaustion-destroy-guard"
        identity = _identity(module, payload, _extract_target(payload), tier=3)
        return _hit(
            module,
            "prompt",
            identity,
            "Review required before resource-exhaustion style destructive setup.",
            "Avoid disk-fill, zero-fill, or fork-bomb style commands from the runtime unless they are part of a tightly reviewed diagnostic workflow.",
        )
    return None


def assess_action(root: pathlib.Path, event: str, matcher: str, payload: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = root
    if event != "PreToolUse" or matcher != "Bash":
        return {"identity": None, "hit": None}

    checks: list[tuple[str, str, re.Pattern[str], str, str]] = [
        ("infra-teardown-guard", "block", INFRA_TEARDOWN_RE, "Blocked destructive infrastructure teardown path.", "Keep infra teardown behind a reviewed manual workflow."),
        ("bulk-disable-guard", "prompt", BULK_DISABLE_RE, "Review required before looped or bulk destructive disable/delete actions.", "Avoid fan-out destructive automation unless it has been separately reviewed."),
        ("repo-wipe-guard", "block", REPO_WIPE_RE, "Blocked repository wipe or history-destruction path.", "Use reviewed repository recovery workflows instead of destructive rewrite or delete operations."),
        ("state-destroy-guard", "block", STATE_DESTROY_RE, "Blocked destructive infrastructure or state wipe path.", "Do not delete or mutate infrastructure state directly from the runtime."),
        ("mass-delete-intent-guard", "block", MASS_DELETE_RE, "Blocked high-blast-radius delete path.", "Reduce scope and review destructive deletes before running them."),
        ("artifact-wipe-guard", "block", ARTIFACT_WIPE_RE, "Blocked destructive wipe of release or build artifacts.", "Keep release artifacts and evidence bundles intact or delete them manually after review."),
        ("env-destroy-guard", "prompt", ENV_DESTROY_RE, "Review required before destroying or removing environment-bound controls.", "Use a reviewed environment teardown path instead of ad hoc runtime deletion."),
        ("secret-revoke-all-guard", "prompt", SECRET_REVOKE_RE, "Review required before revoking or deleting broad secret or token access.", "Use a narrow secret rotation or revocation path instead of bulk destructive token changes."),
        ("role-remove-admin-guard", "prompt", ROLE_REMOVE_RE, "Review required before destructive role or admin removal.", "Keep role removal and admin teardown behind explicit human review."),
        ("blast-radius-delete-guard", "prompt", BLAST_RADIUS_RE, "Review required before a broad delete or revoke scope.", "Reduce target scope before destructive operations that act on everything or recurse broadly."),
    ]

    for module, decision, regex, reason, safer in checks:
        if regex.search(payload):
            target = _extract_target(payload)
            return {
                "identity": _identity(module, payload, target, tier=1),
                "hit": _hit(module, decision, _identity(module, payload, target, tier=1), f"{reason} Target={target}.", safer),
            }
    for handler in (_move_away_hit, _truncate_or_clear_hit, _permission_lockout_hit):
        hit = handler(payload)
        if hit:
            return {"identity": hit["metadata"]["destructive_identity"], "hit": hit}
    if _profile(context) == "strict":
        tier_two = _tier_two_hit(payload)
        if tier_two:
            return {"identity": tier_two["metadata"]["destructive_identity"], "hit": tier_two}
        tier_three = _tier_three_hit(payload)
        if tier_three:
            return {"identity": tier_three["metadata"]["destructive_identity"], "hit": tier_three}
    return {"identity": None, "hit": None}


def record_action(root: pathlib.Path, result: dict[str, Any], payload: str) -> None:
    identity = result.get("destructive_identity")
    if not isinstance(identity, dict) or not identity.get("module"):
        return
    store = load_store(root)
    store.setdefault("events", []).append(
        {
            "event_id": result.get("event_id"),
            "module": identity.get("module"),
            "target": identity.get("target") or identity.get("path"),
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
    return {
        "guards": [
            "mass-delete-intent-guard",
            "move-away-destruction-guard",
            "truncate-clear-guard",
            "permission-lockout-guard",
            "env-destroy-guard",
            "secret-revoke-all-guard",
            "role-remove-admin-guard",
            "infra-teardown-guard",
            "repo-wipe-guard",
            "artifact-wipe-guard",
            "state-destroy-guard",
            "bulk-disable-guard",
            "blast-radius-delete-guard",
            "database-destroy-guard",
            "database-bulk-delete-guard",
            "cloud-resource-destroy-guard",
            "key-destroy-guard",
            "ransomware-intent-guard",
            "indirection-swap-guard",
            "delayed-destruction-guard",
            "resource-exhaustion-destroy-guard",
            "file-nulling-guard",
            "file-stub-replacement-guard",
            "file-junk-overwrite-guard",
            "foreign-header-overwrite-guard",
            "split-step-destruction-guard",
        ]
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect Runwall destructive-intent events")
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
            print("Destructive Actions:")
            for item in items:
                print(f"- {item.get('decision')} {item.get('module')} {item.get('target')} {item.get('event_id')}")
        return 0
    if args.command == "explain":
        payload = explain_event(root, args.selector)
        if payload is None:
            print(f"unknown destructive event: {args.selector}", file=os.sys.stderr)
            return 1
        print(json.dumps(payload, indent=2))
        return 0
    if args.command == "policy":
        payload = policy_payload()
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print("Guards:")
            for item in payload["guards"]:
                print(f"- {item}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
