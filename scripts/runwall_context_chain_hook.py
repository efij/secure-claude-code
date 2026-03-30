#!/usr/bin/env python3
import json
import os
import pathlib
import sys
from datetime import datetime, timezone

import runwall_chain
import runwall_policy
import runwall_runtime


def root_dir() -> pathlib.Path:
    configured = os.environ.get("RUNWALL_HOME") or os.environ.get("SECURE_CLAUDE_CODE_HOME")
    if configured:
        return pathlib.Path(configured)
    return pathlib.Path(__file__).resolve().parent.parent


def emit_prompt(reason: str, chain_alerts: list[dict]) -> None:
    payload = {
        "decision": "prompt",
        "reason": reason,
        "prompt": {"review_required": True},
    }
    if chain_alerts:
        payload["chain_alerts"] = chain_alerts
    print(f"RUNWALL_JSON:{json.dumps(payload, separators=(',', ':'))}")
    print("[runwall] review required for context-aware runtime action", file=sys.stderr)
    print(f"reason: {reason}", file=sys.stderr)


def main(argv: list[str]) -> int:
    if len(argv) < 4:
        return 0

    root = root_dir()
    event = argv[1]
    matcher = argv[2]
    payload = argv[3]
    profile = os.environ.get("RUNWALL_PROFILE", "balanced")
    context = runwall_runtime.context_from_env()

    event_record = runwall_runtime.with_event_context(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "profile": profile,
            "event": event,
            "matcher": matcher,
            "tool_input": payload[:4000],
            "raw_payload": payload[:16000],
        },
        context,
        default_runtime=runwall_runtime.runtime_default(root),
    )
    session_result = runwall_chain.evaluate_session(root, event_record)
    action, hits = runwall_policy._apply_context_overlay(
        root,
        matcher,
        "allow",
        [],
        context,
        session_result["categories"],
        session_result["prior_active_chain_alerts"],
    )

    should_audit = bool(context) or bool(session_result["active_chain_alerts"]) or action != "allow"
    if should_audit:
        base_reason = hits[-1]["output"] if hits else "Recorded runtime context for this action"
        runwall_policy.write_audit_event(
            root,
            module=hits[-1]["module"] if hits else "runwall-context-policy",
            decision=action,
            reason=base_reason,
            tool_input=payload,
            profile=profile,
            extra={
                "event_id": event_record["event_id"],
                "event": event,
                "matcher": matcher,
                "hits": hits,
                "chain_alerts": session_result["active_chain_alerts"],
                "triggered_chain_alerts": session_result["triggered_chain_alerts"],
                "event_categories": session_result["categories"],
            },
            context=context,
        )
    for alert in session_result["triggered_chain_alerts"]:
        runwall_policy.write_audit_event(
            root,
            module="runwall-chain-engine",
            decision="warn",
            reason=f"Detected risky chain {alert['chain_id']}",
            tool_input=payload,
            profile=profile,
            extra={
                "chain_id": alert["chain_id"],
                "severity_score": alert["severity_score"],
                "session_id": alert["session_id"],
                "evidence_event_ids": alert["evidence_event_ids"],
                "chain_alert": True,
            },
            context=context,
        )

    if action == "prompt":
        emit_prompt(hits[-1]["output"], session_result["active_chain_alerts"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
