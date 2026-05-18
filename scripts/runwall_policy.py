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
import runwall_data
import runwall_flow
import runwall_forensics
import runwall_hooks
import runwall_exec
import runwall_ipc
import runwall_knowledge
import runwall_memory
import runwall_promotion
import runwall_release
import runwall_runtime
import runwall_tools
import runwall_services
import runwall_exposure
import runwall_retention
import runwall_browser
import runwall_agents
import runwall_apps
import runwall_auth
import runwall_destructive
import runwall_delayed_exfil
import runwall_file_destructive
import runwall_handoff
import runwall_safety
import runwall_review
import runwall_artifacts
import runwall_stallion

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
    runwall_stallion.record_event(root, {**event, "event_type": "PolicyDecision"})
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
        "family": manifest.get("family", manifest.get("category", "general")),
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
        "family": "Quality & Workflow",
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
            "tool_identity": result.get("tool_identity"),
            "hook_identity": result.get("hook_identity"),
            "service_identity": result.get("service_identity"),
            "data_identity": result.get("data_identity"),
            "ipc_identity": result.get("ipc_identity"),
            "browser_identity": result.get("browser_identity"),
            "exec_identity": result.get("exec_identity"),
            "memory_identity": result.get("memory_identity"),
            "knowledge_identity": result.get("knowledge_identity"),
            "review_identity": result.get("review_identity"),
            "artifact_identity": result.get("artifact_identity"),
            "promotion_identity": result.get("promotion_identity"),
            "app_identity": result.get("app_identity"),
            "auth_identity": result.get("auth_identity"),
            "handoff_identity": result.get("handoff_identity"),
            "release_identity": result.get("release_identity"),
            "destructive_identity": result.get("destructive_identity"),
            "safety_identity": result.get("safety_identity"),
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
    runwall_flow.observe_result(root, result, payload)
    runwall_agents.observe_result(root, result, payload)
    runwall_apps.record_action(root, result, payload)
    runwall_auth.record_action(root, result, payload)
    runwall_handoff.observe_result(root, result, payload)
    runwall_destructive.record_action(root, result, payload)


_COMPACT_ALLOW_IDENTITY_FIELDS: dict[str, tuple[str, ...]] = {
    "tool_identity": ("display_name", "resolved_path", "origin"),
    "hook_identity": ("surface", "location", "origin"),
    "service_identity": ("service_class", "target"),
    "data_identity": ("store_class", "target"),
    "ipc_identity": ("helper_class", "target"),
    "browser_identity": ("domains",),
    "exec_identity": ("surface",),
    "memory_identity": ("path",),
    "knowledge_identity": ("path",),
    "review_identity": ("surface", "path"),
    "artifact_identity": ("surface", "path"),
    "promotion_identity": ("surface", "path"),
    "app_identity": ("app", "module"),
    "auth_identity": ("provider", "broker_class"),
    "handoff_identity": ("session_id", "actor"),
    "exposure_identity": ("surface_class", "target", "visibility"),
    "retention_identity": ("surface_class", "target", "visibility"),
    "release_identity": ("release_class", "target"),
    "destructive_identity": ("module", "target", "path"),
    "delayed_exfil_identity": ("surface_class", "path", "target"),
    "safety_identity": ("surface", "path"),
}


def compact_allow_result(result: dict[str, Any]) -> dict[str, Any]:
    if result.get("action") != "allow":
        return result

    compact: dict[str, Any] = {
        "allowed": True,
        "action": "allow",
    }
    for key, fields in _COMPACT_ALLOW_IDENTITY_FIELDS.items():
        value = result.get(key)
        if not isinstance(value, dict):
            continue
        summarized = {
            field: value[field]
            for field in fields
            if value.get(field) not in (None, [], {}, "")
        }
        if summarized:
            compact[key] = summarized
    return compact


def evaluate(
    root: pathlib.Path,
    profile: str,
    event: str,
    matcher: str,
    payload: str,
    *,
    context: dict[str, Any] | None = None,
    compact_allow: bool = False,
):
    results = []
    action = "allow"
    tool_identity: dict[str, Any] | None = None
    hook_identity: dict[str, Any] | None = None
    service_identity: dict[str, Any] | None = None
    data_identity: dict[str, Any] | None = None
    ipc_identity: dict[str, Any] | None = None
    browser_identity: dict[str, Any] | None = None
    exec_identity: dict[str, Any] | None = None
    memory_identity: dict[str, Any] | None = None
    knowledge_identity: dict[str, Any] | None = None
    review_identity: dict[str, Any] | None = None
    artifact_identity: dict[str, Any] | None = None
    promotion_identity: dict[str, Any] | None = None
    app_identity: dict[str, Any] | None = None
    auth_identity: dict[str, Any] | None = None
    handoff_identity: dict[str, Any] | None = None
    exposure_identity: dict[str, Any] | None = None
    retention_identity: dict[str, Any] | None = None
    release_identity: dict[str, Any] | None = None
    destructive_identity: dict[str, Any] | None = None
    delayed_exfil_identity: dict[str, Any] | None = None
    safety_identity: dict[str, Any] | None = None
    stallion_identity: dict[str, Any] | None = None
    merged_context = runwall_runtime.merge_contexts(runwall_runtime.context_from_env(), context)
    merged_context.setdefault("profile", profile)
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

    agent_hit = runwall_agents.assess_context(root, merged_context)
    if agent_hit:
        if _DECISION_PRIORITY[agent_hit["decision"]] > _DECISION_PRIORITY[action]:
            action = agent_hit["decision"]
        results.append(agent_hit)

    if event == "PreToolUse":
        stallion_assessment = runwall_stallion.assess_action(root, event, matcher, payload, merged_context)
        stallion_identity = stallion_assessment.get("identity")
        stallion_hit = stallion_assessment.get("hit")
        if stallion_hit:
            if _DECISION_PRIORITY[stallion_hit["decision"]] > _DECISION_PRIORITY[action]:
                action = stallion_hit["decision"]
            results.append(stallion_hit)

    if event == "PreToolUse" and (matcher == "Bash" or matcher.startswith("mcp__")):
        exposure_assessment = runwall_exposure.assess_command(root, matcher, payload, merged_context)
        exposure_identity = exposure_assessment.get("identity")
        exposure_hit = exposure_assessment.get("hit")
        if exposure_hit:
            if _DECISION_PRIORITY[exposure_hit["decision"]] > _DECISION_PRIORITY[action]:
                action = exposure_hit["decision"]
            results.append(exposure_hit)

        retention_assessment = runwall_retention.assess_command(root, matcher, payload, merged_context)
        retention_identity = retention_assessment.get("identity")
        retention_hit = retention_assessment.get("hit")
        if retention_hit:
            if _DECISION_PRIORITY[retention_hit["decision"]] > _DECISION_PRIORITY[action]:
                action = retention_hit["decision"]
            results.append(retention_hit)

    if event == "PreToolUse" and matcher == "Bash":
        flow_hit = runwall_flow.assess_preflight(root, event, matcher, payload, merged_context)
        if flow_hit:
            if _DECISION_PRIORITY[flow_hit["decision"]] > _DECISION_PRIORITY[action]:
                action = flow_hit["decision"]
            results.append(flow_hit)

        delayed_exfil_assessment = runwall_delayed_exfil.assess_action(root, event, matcher, payload, merged_context)
        delayed_exfil_identity = delayed_exfil_assessment.get("identity")
        delayed_exfil_hit = delayed_exfil_assessment.get("hit")
        if delayed_exfil_hit:
            if _DECISION_PRIORITY[delayed_exfil_hit["decision"]] > _DECISION_PRIORITY[action]:
                action = delayed_exfil_hit["decision"]
            results.append(delayed_exfil_hit)

        tool_assessment = runwall_tools.assess_command(root, payload)
        tool_identity = tool_assessment.get("identity")
        tool_hit = tool_assessment.get("hit")
        if tool_hit:
            if _DECISION_PRIORITY[tool_hit["decision"]] > _DECISION_PRIORITY[action]:
                action = tool_hit["decision"]
            results.append(tool_hit)

        data_assessment = runwall_data.assess_command(root, payload, merged_context)
        data_identity = data_assessment.get("identity")
        data_hit = data_assessment.get("hit")
        if data_hit:
            if _DECISION_PRIORITY[data_hit["decision"]] > _DECISION_PRIORITY[action]:
                action = data_hit["decision"]
            results.append(data_hit)

        ipc_assessment = runwall_ipc.assess_command(root, payload, merged_context)
        ipc_identity = ipc_assessment.get("identity")
        ipc_hit = ipc_assessment.get("hit")
        if ipc_hit:
            if _DECISION_PRIORITY[ipc_hit["decision"]] > _DECISION_PRIORITY[action]:
                action = ipc_hit["decision"]
            results.append(ipc_hit)

        service_assessment = runwall_services.assess_command(root, payload, merged_context)
        service_identity = service_assessment.get("identity")
        service_hit = service_assessment.get("hit")
        if service_hit:
            if _DECISION_PRIORITY[service_hit["decision"]] > _DECISION_PRIORITY[action]:
                action = service_hit["decision"]
            results.append(service_hit)

        browser_assessment = runwall_browser.assess_command(root, payload, merged_context)
        browser_identity = browser_assessment.get("identity")
        browser_hit = browser_assessment.get("hit")
        if browser_hit:
            if _DECISION_PRIORITY[browser_hit["decision"]] > _DECISION_PRIORITY[action]:
                action = browser_hit["decision"]
            results.append(browser_hit)

        exec_assessment = runwall_exec.assess_command(root, payload, merged_context)
        exec_identity = exec_assessment.get("identity")
        exec_hit = exec_assessment.get("hit")
        if exec_hit:
            if _DECISION_PRIORITY[exec_hit["decision"]] > _DECISION_PRIORITY[action]:
                action = exec_hit["decision"]
            results.append(exec_hit)

        app_assessment = runwall_apps.assess_command(root, payload, merged_context)
        app_identity = app_assessment.get("identity")
        app_hit = app_assessment.get("hit")
        if app_hit:
            if _DECISION_PRIORITY[app_hit["decision"]] > _DECISION_PRIORITY[action]:
                action = app_hit["decision"]
            results.append(app_hit)

        auth_assessment = runwall_auth.assess_command(root, payload, merged_context)
        auth_identity = auth_assessment.get("identity")
        auth_hit = auth_assessment.get("hit")
        if auth_hit:
            if _DECISION_PRIORITY[auth_hit["decision"]] > _DECISION_PRIORITY[action]:
                action = auth_hit["decision"]
            results.append(auth_hit)

        release_assessment = runwall_release.assess_action(root, event, matcher, payload, merged_context)
        release_identity = release_assessment.get("identity")
        release_hit = release_assessment.get("hit")
        if release_hit:
            if _DECISION_PRIORITY[release_hit["decision"]] > _DECISION_PRIORITY[action]:
                action = release_hit["decision"]
            results.append(release_hit)

        destructive_assessment = runwall_destructive.assess_action(root, event, matcher, payload, merged_context)
        destructive_identity = destructive_assessment.get("identity")
        destructive_hit = destructive_assessment.get("hit")
        if destructive_hit:
            if _DECISION_PRIORITY[destructive_hit["decision"]] > _DECISION_PRIORITY[action]:
                action = destructive_hit["decision"]
            results.append(destructive_hit)

        safety_assessment = runwall_safety.assess_action(root, event, matcher, payload, merged_context)
        safety_identity = safety_assessment.get("identity")
        safety_hit = safety_assessment.get("hit")
        if safety_hit:
            if _DECISION_PRIORITY[safety_hit["decision"]] > _DECISION_PRIORITY[action]:
                action = safety_hit["decision"]
            results.append(safety_hit)

        handoff_hit = runwall_handoff.assess_action(root, payload, merged_context)
        if handoff_hit:
            handoff_identity = handoff_hit.get("metadata", {}).get("handoff_identity")
            if _DECISION_PRIORITY[handoff_hit["decision"]] > _DECISION_PRIORITY[action]:
                action = handoff_hit["decision"]
            results.append(handoff_hit)

        agent_action_hit = runwall_agents.assess_action(root, payload, merged_context)
        if agent_action_hit:
            if _DECISION_PRIORITY[agent_action_hit["decision"]] > _DECISION_PRIORITY[action]:
                action = agent_action_hit["decision"]
            results.append(agent_action_hit)

    if event == "PreToolUse" and matcher in {"Read", "Write", "Edit", "MultiEdit"}:
        flow_hit = runwall_flow.assess_preflight(root, event, matcher, payload, merged_context)
        if flow_hit:
            if _DECISION_PRIORITY[flow_hit["decision"]] > _DECISION_PRIORITY[action]:
                action = flow_hit["decision"]
            results.append(flow_hit)

        delayed_exfil_assessment = runwall_delayed_exfil.assess_action(root, event, matcher, payload, merged_context)
        delayed_exfil_identity = delayed_exfil_assessment.get("identity")
        delayed_exfil_hit = delayed_exfil_assessment.get("hit")
        if delayed_exfil_hit:
            if _DECISION_PRIORITY[delayed_exfil_hit["decision"]] > _DECISION_PRIORITY[action]:
                action = delayed_exfil_hit["decision"]
            results.append(delayed_exfil_hit)

        memory_assessment = runwall_memory.assess_fileop(root, event, matcher, payload, merged_context)
        memory_identity = memory_assessment.get("identity")
        memory_hit = memory_assessment.get("hit")
        if memory_hit:
            if _DECISION_PRIORITY[memory_hit["decision"]] > _DECISION_PRIORITY[action]:
                action = memory_hit["decision"]
            results.append(memory_hit)

        knowledge_assessment = runwall_knowledge.assess_fileop(root, event, matcher, payload, merged_context)
        knowledge_identity = knowledge_assessment.get("identity")
        knowledge_hit = knowledge_assessment.get("hit")
        if knowledge_hit:
            if _DECISION_PRIORITY[knowledge_hit["decision"]] > _DECISION_PRIORITY[action]:
                action = knowledge_hit["decision"]
            results.append(knowledge_hit)

        review_assessment = runwall_review.assess_fileop(root, event, matcher, payload, merged_context)
        review_identity = review_assessment.get("identity")
        review_hit = review_assessment.get("hit")
        if review_hit:
            if _DECISION_PRIORITY[review_hit["decision"]] > _DECISION_PRIORITY[action]:
                action = review_hit["decision"]
            results.append(review_hit)

        artifact_assessment = runwall_artifacts.assess_fileop(root, event, matcher, payload, merged_context)
        artifact_identity = artifact_assessment.get("identity")
        artifact_hit = artifact_assessment.get("hit")
        if artifact_hit:
            if _DECISION_PRIORITY[artifact_hit["decision"]] > _DECISION_PRIORITY[action]:
                action = artifact_hit["decision"]
            results.append(artifact_hit)

        promotion_assessment = runwall_promotion.assess_fileop(root, event, matcher, payload, merged_context)
        promotion_identity = promotion_assessment.get("identity")
        promotion_hit = promotion_assessment.get("hit")
        if promotion_hit:
            if _DECISION_PRIORITY[promotion_hit["decision"]] > _DECISION_PRIORITY[action]:
                action = promotion_hit["decision"]
            results.append(promotion_hit)

        destructive_assessment = runwall_file_destructive.assess_fileop(root, event, matcher, payload, merged_context)
        destructive_identity = None
        destructive_hit = destructive_assessment.get("hit")
        if destructive_hit:
            destructive_identity = destructive_assessment.get("identity")
            if _DECISION_PRIORITY[destructive_hit["decision"]] > _DECISION_PRIORITY[action]:
                action = destructive_hit["decision"]
            results.append(destructive_hit)

        release_assessment = runwall_release.assess_action(root, event, matcher, payload, merged_context)
        release_identity = release_assessment.get("identity")
        release_hit = release_assessment.get("hit")
        if release_hit:
            if _DECISION_PRIORITY[release_hit["decision"]] > _DECISION_PRIORITY[action]:
                action = release_hit["decision"]
            results.append(release_hit)

        safety_assessment = runwall_safety.assess_action(root, event, matcher, payload, merged_context)
        safety_identity = safety_assessment.get("identity")
        safety_hit = safety_assessment.get("hit")
        if safety_hit:
            if _DECISION_PRIORITY[safety_hit["decision"]] > _DECISION_PRIORITY[action]:
                action = safety_hit["decision"]
            results.append(safety_hit)

    if event == "PreToolUse" and matcher in {"Bash", "Write", "Edit", "MultiEdit"}:
        hook_assessment = runwall_hooks.assess_change(root, event, matcher, payload)
        hook_identity = hook_assessment.get("identity")
        hook_hit = hook_assessment.get("hit")
        if hook_hit:
            if _DECISION_PRIORITY[hook_hit["decision"]] > _DECISION_PRIORITY[action]:
                action = hook_hit["decision"]
            results.append(hook_hit)

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

    result = {
        "profile": profile,
        "event": event,
        "matcher": matcher,
        "allowed": action not in {"block", "prompt"},
        "action": action,
        "hits": results,
        "event_id": event_record["event_id"],
        "tool_identity": tool_identity,
        "hook_identity": hook_identity,
        "service_identity": service_identity,
        "data_identity": data_identity,
        "ipc_identity": ipc_identity,
        "browser_identity": browser_identity,
        "exec_identity": exec_identity,
        "memory_identity": memory_identity,
        "knowledge_identity": knowledge_identity,
        "review_identity": review_identity,
        "artifact_identity": artifact_identity,
        "promotion_identity": promotion_identity,
        "app_identity": app_identity,
        "auth_identity": auth_identity,
        "handoff_identity": handoff_identity,
        "exposure_identity": exposure_identity,
        "retention_identity": retention_identity,
        "release_identity": release_identity,
        "destructive_identity": destructive_identity,
        "delayed_exfil_identity": delayed_exfil_identity,
        "safety_identity": safety_identity,
        "stallion_identity": stallion_identity,
        "event_categories": session_result["categories"],
        "chain_alerts": session_result["active_chain_alerts"],
        "triggered_chain_alerts": session_result["triggered_chain_alerts"],
        **merged_context,
    }
    if compact_allow:
        return compact_allow_result(result)
    return result


def print_pretty(result: dict[str, Any]) -> None:
    if result["allowed"] and not result["hits"]:
        print("allowed")
        tool_identity = result.get("tool_identity") or {}
        if tool_identity.get("resolved_path"):
            print(f"tool: {tool_identity.get('display_name')} -> {tool_identity.get('resolved_path')} [{tool_identity.get('origin')}]")
        hook_identity = result.get("hook_identity") or {}
        if hook_identity.get("location"):
            print(
                f"hook: {hook_identity.get('surface')} -> {hook_identity.get('location')} "
                f"[{hook_identity.get('origin')}]"
            )
        service_identity = result.get("service_identity") or {}
        if service_identity.get("target"):
            print(
                f"service: {service_identity.get('service_class')} -> {service_identity.get('target')}"
            )
        data_identity = result.get("data_identity") or {}
        if data_identity.get("target"):
            print(f"data: {data_identity.get('store_class')} -> {data_identity.get('target')}")
        ipc_identity = result.get("ipc_identity") or {}
        if ipc_identity.get("target"):
            print(f"ipc: {ipc_identity.get('helper_class')} -> {ipc_identity.get('target')}")
        browser_identity = result.get("browser_identity") or {}
        if browser_identity.get("domains"):
            print(f"browser: {', '.join(browser_identity.get('domains', []))}")
        exec_identity = result.get("exec_identity") or {}
        if exec_identity.get("surface"):
            print(f"exec: {exec_identity.get('surface')}")
        memory_identity = result.get("memory_identity") or {}
        if memory_identity.get("path"):
            print(f"memory: {memory_identity.get('path')}")
        knowledge_identity = result.get("knowledge_identity") or {}
        if knowledge_identity.get("path"):
            print(f"knowledge: {knowledge_identity.get('path')}")
        review_identity = result.get("review_identity") or {}
        if review_identity.get("path"):
            print(f"review: {review_identity.get('surface')} -> {review_identity.get('path')}")
        artifact_identity = result.get("artifact_identity") or {}
        if artifact_identity.get("path"):
            print(f"artifacts: {artifact_identity.get('surface')} -> {artifact_identity.get('path')}")
        promotion_identity = result.get("promotion_identity") or {}
        if promotion_identity.get("path"):
            print(f"promotion: {promotion_identity.get('surface')} -> {promotion_identity.get('path')}")
        app_identity = result.get("app_identity") or {}
        if app_identity.get("app"):
            print(f"app: {app_identity.get('app')} [{app_identity.get('module')}]")
        auth_identity = result.get("auth_identity") or {}
        if auth_identity.get("provider"):
            print(f"auth: {auth_identity.get('provider')} -> {auth_identity.get('broker_class')}")
        exposure_identity = result.get("exposure_identity") or {}
        if exposure_identity.get("surface_class"):
            print(
                f"exposure: {exposure_identity.get('surface_class')} -> {exposure_identity.get('target')} "
                f"[{exposure_identity.get('visibility')}]"
            )
        retention_identity = result.get("retention_identity") or {}
        if retention_identity.get("surface_class"):
            print(
                f"retention: {retention_identity.get('surface_class')} -> {retention_identity.get('target')} "
                f"[{retention_identity.get('visibility')}]"
            )
        handoff_identity = result.get("handoff_identity") or {}
        if handoff_identity.get("session_id"):
            print(f"handoff: {handoff_identity.get('session_id')} [{handoff_identity.get('actor')}]")
        release_identity = result.get("release_identity") or {}
        if release_identity.get("target"):
            print(f"release: {release_identity.get('release_class')} -> {release_identity.get('target')}")
        destructive_identity = result.get("destructive_identity") or {}
        if destructive_identity.get("target") or destructive_identity.get("path"):
            print(f"destructive: {destructive_identity.get('module')} -> {destructive_identity.get('target') or destructive_identity.get('path')}")
        delayed_exfil_identity = result.get("delayed_exfil_identity") or {}
        if delayed_exfil_identity.get("surface_class"):
            print(
                f"delayed-exfil: {delayed_exfil_identity.get('surface_class')} -> "
                f"{delayed_exfil_identity.get('path') or delayed_exfil_identity.get('target')}"
            )
        safety_identity = result.get("safety_identity") or {}
        if safety_identity.get("path"):
            print(f"safety: {safety_identity.get('surface')} -> {safety_identity.get('path')}")
        return
    print(f"allowed: {'yes' if result['allowed'] else 'no'}")
    print(f"action: {result['action']}")
    print(f"profile: {result['profile']}")
    print(f"event: {result['event']} / {result['matcher']}")
    tool_identity = result.get("tool_identity") or {}
    if tool_identity.get("resolved_path"):
        print(f"tool: {tool_identity.get('display_name')} -> {tool_identity.get('resolved_path')} [{tool_identity.get('origin')}]")
    hook_identity = result.get("hook_identity") or {}
    if hook_identity.get("location"):
        print(
            f"hook: {hook_identity.get('surface')} -> {hook_identity.get('location')} "
            f"[{hook_identity.get('origin')}]"
        )
    service_identity = result.get("service_identity") or {}
    if service_identity.get("target"):
        print(f"service: {service_identity.get('service_class')} -> {service_identity.get('target')}")
    data_identity = result.get("data_identity") or {}
    if data_identity.get("target"):
        print(f"data: {data_identity.get('store_class')} -> {data_identity.get('target')}")
    ipc_identity = result.get("ipc_identity") or {}
    if ipc_identity.get("target"):
        print(f"ipc: {ipc_identity.get('helper_class')} -> {ipc_identity.get('target')}")
    browser_identity = result.get("browser_identity") or {}
    if browser_identity.get("domains"):
        print(f"browser: {', '.join(browser_identity.get('domains', []))}")
    exec_identity = result.get("exec_identity") or {}
    if exec_identity.get("surface"):
        print(f"exec: {exec_identity.get('surface')}")
    memory_identity = result.get("memory_identity") or {}
    if memory_identity.get("path"):
        print(f"memory: {memory_identity.get('path')}")
    knowledge_identity = result.get("knowledge_identity") or {}
    if knowledge_identity.get("path"):
        print(f"knowledge: {knowledge_identity.get('path')}")
    review_identity = result.get("review_identity") or {}
    if review_identity.get("path"):
        print(f"review: {review_identity.get('surface')} -> {review_identity.get('path')}")
    artifact_identity = result.get("artifact_identity") or {}
    if artifact_identity.get("path"):
        print(f"artifacts: {artifact_identity.get('surface')} -> {artifact_identity.get('path')}")
    promotion_identity = result.get("promotion_identity") or {}
    if promotion_identity.get("path"):
        print(f"promotion: {promotion_identity.get('surface')} -> {promotion_identity.get('path')}")
    app_identity = result.get("app_identity") or {}
    if app_identity.get("app"):
        print(f"app: {app_identity.get('app')} [{app_identity.get('module')}]")
    auth_identity = result.get("auth_identity") or {}
    if auth_identity.get("provider"):
        print(f"auth: {auth_identity.get('provider')} -> {auth_identity.get('broker_class')}")
    exposure_identity = result.get("exposure_identity") or {}
    if exposure_identity.get("surface_class"):
        print(
            f"exposure: {exposure_identity.get('surface_class')} -> {exposure_identity.get('target')} "
            f"[{exposure_identity.get('visibility')}]"
        )
    retention_identity = result.get("retention_identity") or {}
    if retention_identity.get("surface_class"):
        print(
            f"retention: {retention_identity.get('surface_class')} -> {retention_identity.get('target')} "
            f"[{retention_identity.get('visibility')}]"
        )
    handoff_identity = result.get("handoff_identity") or {}
    if handoff_identity.get("session_id"):
        print(f"handoff: {handoff_identity.get('session_id')} [{handoff_identity.get('actor')}]")
    release_identity = result.get("release_identity") or {}
    if release_identity.get("target"):
        print(f"release: {release_identity.get('release_class')} -> {release_identity.get('target')}")
    destructive_identity = result.get("destructive_identity") or {}
    if destructive_identity.get("target") or destructive_identity.get("path"):
        print(f"destructive: {destructive_identity.get('module')} -> {destructive_identity.get('target') or destructive_identity.get('path')}")
    delayed_exfil_identity = result.get("delayed_exfil_identity") or {}
    if delayed_exfil_identity.get("surface_class"):
        print(
            f"delayed-exfil: {delayed_exfil_identity.get('surface_class')} -> "
            f"{delayed_exfil_identity.get('path') or delayed_exfil_identity.get('target')}"
        )
    safety_identity = result.get("safety_identity") or {}
    if safety_identity.get("path"):
        print(f"safety: {safety_identity.get('surface')} -> {safety_identity.get('path')}")
    for hit in result["hits"]:
        print(f"- {hit['module']} [{hit.get('family', hit['category'])} • {hit['category']}/{hit['decision']}]")
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
