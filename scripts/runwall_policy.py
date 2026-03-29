#!/usr/bin/env python3
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


def run_hook(root: pathlib.Path, script_path: pathlib.Path, payload: str):
    env = os.environ.copy()
    env["RUNWALL_HOME"] = str(root)
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


def write_audit_event(
    root: pathlib.Path,
    *,
    module: str,
    decision: str,
    reason: str,
    tool_input: str,
    profile: str | None = None,
    extra: dict[str, Any] | None = None,
) -> None:
    event = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "module": module,
        "decision": decision,
        "reason": reason,
        "profile": current_profile(root, explicit=profile),
        "cwd": os.getcwd(),
        "user": os.environ.get("USER") or os.environ.get("USERNAME") or "unknown",
        "host": socket.gethostname(),
        "tool_input": tool_input[:4000],
    }
    if extra:
        event.update(extra)
    path = audit_file_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(event, separators=(",", ":")) + "\n")


def normalize_hit(
    manifest: dict[str, Any],
    returncode: int,
    output: str,
    metadata: dict[str, Any],
) -> dict[str, Any]:
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
    return hit


def evaluate(root: pathlib.Path, profile: str, event: str, matcher: str, payload: str):
    results = []
    action = "allow"

    for manifest, hook in iter_matching_hooks(root, profile, event, matcher):
        command = hook.get("command", "")
        script_path = extract_script(root, command)
        if script_path is None or not script_path.exists():
            continue
        returncode, output, metadata = run_hook(root, script_path, payload)
        if returncode == 0 and not output and not metadata:
            continue
        hit = normalize_hit(manifest, returncode, output, metadata)
        if _DECISION_PRIORITY[hit["decision"]] > _DECISION_PRIORITY[action]:
            action = hit["decision"]
        results.append(hit)

    return {
        "profile": profile,
        "event": event,
        "matcher": matcher,
        "allowed": action not in {"block", "prompt"},
        "action": action,
        "hits": results,
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
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    result = evaluate(
        pathlib.Path(args.root),
        args.profile,
        args.event,
        args.matcher,
        args.payload,
    )

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_pretty(result)

    return 0 if result["allowed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
