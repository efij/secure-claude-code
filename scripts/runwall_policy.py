#!/usr/bin/env python3
import argparse
import json
import os
import pathlib
import re
import subprocess
import sys
from typing import Any


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
    match = re.search(r"bash\s+~/.runwall/(hooks/[^\"\s]+)", command)
    if not match:
        return None
    return root / match.group(1)


def run_hook(root: pathlib.Path, script_path: pathlib.Path, payload: str):
    env = os.environ.copy()
    env["RUNWALL_HOME"] = str(root)
    proc = subprocess.run(
        ["bash", str(script_path), payload],
        input=payload,
        text=True,
        capture_output=True,
        env=env,
    )
    combined = "\n".join(
        part for part in (proc.stdout.strip(), proc.stderr.strip()) if part
    ).strip()
    return proc.returncode, combined


def evaluate(root: pathlib.Path, profile: str, event: str, matcher: str, payload: str):
    results = []
    blocked = False

    for manifest, hook in iter_matching_hooks(root, profile, event, matcher):
        command = hook.get("command", "")
        script_path = extract_script(root, command)
        if script_path is None or not script_path.exists():
            continue
        returncode, output = run_hook(root, script_path, payload)
        if returncode == 0 and not output:
            continue
        decision = "block" if returncode != 0 else manifest.get("kind", "warn")
        blocked = blocked or decision == "block"
        results.append(
            {
                "module": manifest["id"],
                "name": manifest.get("name", manifest["id"]),
                "category": manifest.get("category", "general"),
                "decision": decision,
                "exit_code": returncode,
                "output": output,
            }
        )

    return {
        "profile": profile,
        "event": event,
        "matcher": matcher,
        "allowed": not blocked,
        "hits": results,
    }


def print_pretty(result: dict[str, Any]) -> None:
    if result["allowed"] and not result["hits"]:
        print("allowed")
        return
    print(f"allowed: {'yes' if result['allowed'] else 'no'}")
    print(f"profile: {result['profile']}")
    print(f"event: {result['event']} / {result['matcher']}")
    for hit in result["hits"]:
        print(
            f"- {hit['module']} [{hit['category']}/{hit['decision']}]"
        )
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
