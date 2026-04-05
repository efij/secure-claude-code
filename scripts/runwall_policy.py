#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any

import runwall_chain
import runwall_forensics
import runwall_runtime

_HOOK_SHELL: str | None = None
_METADATA_PREFIX = "RUNWALL_JSON:"
_DECISION_PRIORITY = {
    "allow": 0,
    "assist": 1,
    "warn": 2,
    "redact": 3,
    "prompt": 4,
    "block": 5,
}


def safe_json_dumps(payload: Any) -> str:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def load_profile_modules(root: pathlib.Path, profile: str) -> list[str]:
    profile_path = root / "profiles" / f"{profile}.txt"
    if not profile_path.exists():
        raise SystemExit(f"unknown profile: {profile}")
    modules = []
    for line in profile_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        modules.append(line)
    return modules


def load_manifest(root: pathlib.Path, module_id: str) -> dict[str, Any]:
    manifest_path = root / "modules" / module_id / "module.json"
    if not manifest_path.exists():
        raise SystemExit(f"missing module manifest: {manifest_path}")
    return json.loads(manifest_path.read_text())


def iter_matching_hooks(root: pathlib.Path, profile: str, event: str, matcher: str):
    for module_id in load_profile_modules(root, profile):
        manifest = load_manifest(root, module_id)
        hook_items = manifest.get("hooks") or [manifest["hook"]]
        for hook in hook_items:
            if hook.get("event") != event:
                continue
            hook_matcher = hook.get("matcher", "")
            try:
                if not re.fullmatch(hook_matcher, matcher):
                    continue
            except re.error:
                continue
            yield manifest, hook


def extract_script(root: pathlib.Path, command: str) -> pathlib.Path | None:
    patterns = [
        r"bash\s+~/.runwall/(hooks/[^\"]+?\.sh)",
        r'bash\s+"\$\{CLAUDE_PLUGIN_ROOT\}/(hooks/[^\"]+?\.sh)"',
        r'bash\s+"\$\{RUNWALL_HOME\}/(hooks/[^\"]+?\.sh)"',
    ]
    for pattern in patterns:
        match = re.search(pattern, command)
        if match:
            return root / match.group(1)
    return None


def resolve_hook_shell() -> str:
    global _HOOK_SHELL
    if _HOOK_SHELL:
        return _HOOK_SHELL

    if os.name != "nt":
        _HOOK_SHELL = shutil.which("bash") or "bash"
        return _HOOK_SHELL

    candidates: list[str] = []
    for env_name in ("RUNWALL_BASH", "GIT_BASH", "BASH"):
        value = os.environ.get(env_name)
        if value:
            candidates.append(value)

    git_candidates = [
        pathlib.Path(os.environ.get("ProgramFiles", "")) / "Git" / "bin" / "bash.exe",
        pathlib.Path(os.environ.get("ProgramW6432", "")) / "Git" / "bin" / "bash.exe",
        pathlib.Path(os.environ.get("ProgramFiles(x86)", "")) / "Git" / "bin" / "bash.exe",
        pathlib.Path("C:/Program Files/Git/bin/bash.exe"),
        pathlib.Path("C:/Program Files (x86)/Git/bin/bash.exe"),
    ]
    candidates.extend(str(path) for path in git_candidates)

    which_bash = shutil.which("bash")
    if which_bash:
        candidates.append(which_bash)

    for candidate in candidates:
        if not candidate:
            continue
        path = pathlib.Path(candidate)
        candidate_text = str(path).lower().replace("\\", "/")
        if "system32/bash.exe" in candidate_text:
            continue
        if path.exists():
            _HOOK_SHELL = str(path)
            return _HOOK_SHELL

    raise SystemExit("could not locate Git Bash on Windows for Runwall hook execution")


def parse_hook_output(output: str) -> tuple[str, dict[str, Any]]:
    metadata: dict[str, Any] = {}
    cleaned_lines: list[str] = []
    for line in output.splitlines():
        if line.startswith(_METADATA_PREFIX):
            try:
                payload = json.loads(line[len(_METADATA_PREFIX) :])
                if isinstance(payload, dict):
                    metadata = payload
            except json.JSONDecodeError:
                cleaned_lines.append(line)
            continue
        cleaned_lines.append(line)
    cleaned = "\n".join(line for line in cleaned_lines if line.strip()).strip()
    return cleaned, metadata


def run_hook(root: pathlib.Path, profile: str, script_path: pathlib.Path, payload: str):
    env = os.environ.copy()
    env["RUNWALL_HOME"] = str(root)
    env["RUNWALL_PROFILE"] = profile
    proc = subprocess.run(
        [resolve_hook_shell(), str(script_path), payload],
        input=payload,
        text=True,
        capture_output=True,
        env=env,
        shell=False,
    )
    combined = "\n".join(
        part for part in (proc.stdout.strip(), proc.stderr.strip()) if part
    ).strip()
    cleaned_output, metadata = parse_hook_output(combined)
    return proc.returncode, cleaned_output, metadata


def audit_file_path(root: pathlib.Path) -> pathlib.Path:
    path = os.environ.get("RUNWALL_AUDIT_FILE") or os.environ.get(
        "SECURE_CLAUDE_CODE_AUDIT_FILE"
    )
    if path:
        return pathlib.Path(path)
    home = os.environ.get("RUNWALL_HOME") or os.environ.get(
        "SECURE_CLAUDE_CODE_HOME"
    )
    if home:
        return pathlib.Path(home) / "state" / "audit.jsonl"
    return root / "state" / "audit.jsonl"


def current_profile(root: pathlib.Path, explicit: str | None = None) -> str:
    if explicit:
        return explicit
    profile_file = root / "state" / "profile.txt"
    if profile_file.exists():
        return profile_file.read_text().strip()
    return "unknown"


def load_context_policy(root: pathlib.Path) -> dict[str, Any]:
    path = root / "config" / "context-policy.json"
    if not path.exists():
        return {"rules": []}
    payload = json.loads(path.read_text())
    if not isinstance(payload, dict):
        return {"rules": []}
    payload.setdefault("rules", [])
    return payload


def write_audit_event(
    root: pathlib.Path,
    *,
    module: str,
    decision: str,
    reason: str,
    tool_input: str,
    profile: str | None = None,
    extra: dict[str, Any] | None = None,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    base_event = runwall_runtime.with_event_context(
        {
        "ts": datetime.now(timezone.utc).isoformat(),
        "module": module,
        "decision": decision,
        "reason": reason,
        "profile": current_profile(root, explicit=profile),
        "cwd": os.getcwd(),
        "user": os.environ.get("USER") or os.environ.get("USERNAME") or "unknown",
        "host": socket.gethostname(),
        "tool_input": tool_input[:4000],
        },
        context,
        default_runtime=runwall_runtime.runtime_default(root),
    )
    if extra:
        base_event.update(extra)
    event = runwall_runtime.with_event_context(
        runwall_forensics.enrich_event(base_event),
        context,
        default_runtime=base_event.get("runtime") or runwall_runtime.runtime_default(root),
    )
    path = audit_file_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(event, separators=(",", ":")) + "\n")
    runwall_forensics.record_event(root, event)
    return event


def normalize_hit(
    manifest: dict[str, Any],
    returncode: int,
    output: str,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    metadata_decision = metadata.get("decision") if isinstance(metadata, dict) else None
    if metadata_decision in _DECISION_PRIORITY:
        decision = metadata_decision
    else:
        decision = "block" if returncode != 0 else manifest.get("kind", "warn")
    hit = {
        "module": manifest["id"],
        "name": manifest.get("name", manifest["id"]),
        "category": manifest.get("category", "general"),
        "decision": decision,
        "exit_code": returncode,
        "output": output,
    }
    if metadata:
        hit["metadata"] = metadata
        if metadata.get("reason") and not output:
            hit["output"] = metadata["reason"]
    if "metadata" not in hit:
        hit["metadata"] = {}
    hit["metadata"].setdefault(
        "confidence",
        runwall_forensics.DECISION_CONFIDENCE.get(decision, 0.55),
    )
    hit["metadata"].setdefault(
        "safer_alternative",
        runwall_forensics.infer_safer_alternative(hit),
    )
    return hit


def _rule_matches_matcher(rule: dict[str, Any], matcher: str, categories: list[str]) -> bool:
    explicit_matchers = rule.get("matchers") or []
    patterns = rule.get("matcher_patterns") or []
    category_allowlist = {str(item) for item in rule.get("category_allowlist") or []}

    matcher_match = matcher in explicit_matchers
    if not matcher_match:
        for pattern in patterns:
            try:
                if re.fullmatch(str(pattern), matcher):
                    matcher_match = True
                    break
            except re.error:
                continue
    if not matcher_match:
        return False
    if not category_allowlist:
        return True
    return bool(category_allowlist.intersection(categories))


def _rule_matches_context(
    rule: dict[str, Any],
    context: dict[str, Any],
    prior_active_chain_alerts: list[dict[str, Any]],
) -> bool:
    requires_active_chain = bool(rule.get("requires_active_chain"))
    if requires_active_chain and not prior_active_chain_alerts:
        return False
    if rule.get("background") and context.get("background"):
        return True
    required_fields = [str(item) for item in rule.get("requires_any_context") or []]
    if required_fields:
        return any(context.get(field) for field in required_fields)
    if requires_active_chain:
        return True
    return True


def _synthetic_hit(rule: dict[str, Any], decision: str, prior_active_chain_alerts: list[dict[str, Any]]) -> dict[str, Any]:
    module = "runwall-chain-escalation" if rule.get("requires_active_chain") else "runwall-context-policy"
    metadata: dict[str, Any] = {"rule_id": rule.get("id")}
    metadata["confidence"] = runwall_forensics.DECISION_CONFIDENCE.get(decision, 0.82)
    metadata["safer_alternative"] = str(rule.get("reason", "")).strip()
    if prior_active_chain_alerts:
        metadata["chain_alerts"] = [
            {
                "chain_id": alert["chain_id"],
                "severity_score": alert["severity_score"],
                "evidence_event_ids": alert["evidence_event_ids"],
            }
            for alert in prior_active_chain_alerts
        ]
    return {
        "module": module,
        "name": "Runwall Chain Escalation" if rule.get("requires_active_chain") else "Runwall Context Policy",
        "category": "runtime-context",
        "decision": decision,
        "exit_code": 0,
        "output": str(rule.get("reason", "")),
        "metadata": metadata,
    }


def _apply_context_overlay(
    root: pathlib.Path,
    matcher: str,
    action: str,
    hits: list[dict[str, Any]],
    context: dict[str, Any],
    categories: list[str],
    prior_active_chain_alerts: list[dict[str, Any]],
) -> tuple[str, list[dict[str, Any]]]:
    if action != "allow":
        return action, hits
    for rule in load_context_policy(root).get("rules", []):
        if not _rule_matches_context(rule, context, prior_active_chain_alerts):
            continue
        if not _rule_matches_matcher(rule, matcher, categories):
            continue
        decision = str(rule.get("decision", "prompt"))
        synthetic = _synthetic_hit(rule, decision, prior_active_chain_alerts)
        updated_hits = [*hits, synthetic]
        if _DECISION_PRIORITY.get(decision, 0) > _DECISION_PRIORITY[action]:
            return decision, updated_hits
        return action, updated_hits
    return action, hits


def emit_audit_records(root: pathlib.Path, result: dict[str, Any], payload: str) -> None:
    context = {
        field: result.get(field)
        for field in runwall_runtime.CONTEXT_FIELDS
        if result.get(field) is not None
    }
    base_event = write_audit_event(
        root,
        module=(result.get("hits") or [{}])[-1].get("module", "runwall-policy"),
        decision=result["action"],
        reason=(result.get("hits") or [{"output": "allowed"}])[-1].get("output", "allowed"),
        tool_input=payload,
        profile=result["profile"],
        extra={
            "event_id": result["event_id"],
            "event": result["event"],
            "matcher": result["matcher"],
            "hits": result["hits"],
            "chain_alerts": result.get("chain_alerts", []),
            "triggered_chain_alerts": result.get("triggered_chain_alerts", []),
            "event_categories": result.get("event_categories", []),
            "matcher": result["matcher"],
            "request_preview": payload[:320],
        },
        context=context,
    )
    for alert in result.get("triggered_chain_alerts", []):
        write_audit_event(
            root,
            module="runwall-chain-engine",
            decision="warn",
            reason=f"Detected risky chain {alert['chain_id']}",
            tool_input=payload,
            profile=result["profile"],
            extra={
                "chain_id": alert["chain_id"],
                "severity_score": alert["severity_score"],
                "session_id": alert["session_id"],
                "evidence_event_ids": alert["evidence_event_ids"],
                "related_event_id": base_event["event_id"],
                "chain_alert": True,
            },
            context=context,
        )


def evaluate(
    root: pathlib.Path,
    profile: str,
    event: str,
    matcher: str,
    payload: str,
    *,
    context: dict[str, Any] | None = None,
):
    results = []
    action = "allow"
    merged_context = runwall_runtime.merge_contexts(runwall_runtime.context_from_env(), context)
    event_record = runwall_runtime.with_event_context(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "profile": profile,
            "event": event,
            "matcher": matcher,
            "tool_input": payload[:4000],
            "raw_payload": payload[:16000],
        },
        merged_context,
        default_runtime=runwall_runtime.runtime_default(root),
    )

    for manifest, hook in iter_matching_hooks(root, profile, event, matcher):
        command = hook.get("command", "")
        script_path = extract_script(root, command)
        if script_path is None or not script_path.exists():
            continue
        returncode, output, metadata = run_hook(root, profile, script_path, payload)
        if returncode == 0 and not output and not metadata:
            continue
        hit = normalize_hit(manifest, returncode, output, metadata)
        if _DECISION_PRIORITY[hit["decision"]] > _DECISION_PRIORITY[action]:
            action = hit["decision"]
        results.append(hit)

    event_record["hits"] = results
    session_result = runwall_chain.evaluate_session(root, event_record)
    action, results = _apply_context_overlay(
        root,
        matcher,
        action,
        results,
        merged_context,
        session_result["categories"],
        session_result["prior_active_chain_alerts"],
    )

    return {
        "profile": profile,
        "event": event,
        "matcher": matcher,
        "allowed": action not in {"block", "prompt"},
        "action": action,
        "hits": results,
        "event_id": event_record["event_id"],
        "event_categories": session_result["categories"],
        "chain_alerts": session_result["active_chain_alerts"],
        "triggered_chain_alerts": session_result["triggered_chain_alerts"],
        **merged_context,
    }


def print_pretty(result: dict[str, Any]) -> None:
    if result["allowed"] and not result["hits"]:
        print("allowed")
        return
    print(f"allowed: {'yes' if result['allowed'] else 'no'}")
    print(f"action: {result['action']}")
    print(f"profile: {result['profile']}")
    print(f"event: {result['event']} / {result['matcher']}")
    for hit in result["hits"]:
        print(f"- {hit['module']} [{hit['category']}/{hit['decision']}]")
        if hit["output"]:
            print(hit["output"])


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate Runwall policy hooks")
    parser.add_argument("--root", required=True)
    parser.add_argument("--profile", default="balanced")
    parser.add_argument("--event", required=True)
    parser.add_argument("--matcher", required=True)
    parser.add_argument("--input", dest="payload", required=True)
    parser.add_argument("--runtime")
    parser.add_argument("--agent-id")
    parser.add_argument("--subagent-id")
    parser.add_argument("--parent-agent-id")
    parser.add_argument("--session-id")
    parser.add_argument("--background")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    cli_context = runwall_runtime.context_from_cli_values(
        {
            "runtime": args.runtime,
            "agent_id": args.agent_id,
            "subagent_id": args.subagent_id,
            "parent_agent_id": args.parent_agent_id,
            "session_id": args.session_id,
            "background": args.background,
        }
    )
    result = evaluate(
        pathlib.Path(args.root),
        args.profile,
        args.event,
        args.matcher,
        args.payload,
        context=cli_context,
    )
    emit_audit_records(pathlib.Path(args.root), result, args.payload)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_pretty(result)

    return 0 if result["allowed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
