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


DEFAULT_POLICY = {
    "high_trust_names": [
        "git",
        "gh",
        "kubectl",
        "terraform",
        "terragrunt",
        "tofu",
        "docker",
        "claude",
        "codex",
        "python",
        "python3",
        "node",
        "npm",
        "pnpm",
        "yarn",
        "bun",
    ],
    "auto_trust_origins": ["system", "package-managed"],
    "review_origins": ["workspace-local", "user-local", "unknown"],
    "block_origins": ["temp", "download", "cache"],
    "shadow_block_origins": [
        "workspace-local",
        "user-local",
        "unknown",
        "temp",
        "download",
        "cache",
    ],
    "wrapper_block_names": [
        "git",
        "gh",
        "kubectl",
        "terraform",
        "terragrunt",
        "tofu",
        "claude",
        "codex",
    ],
    "recent_tool_seconds": 900,
}

WRAPPER_COMMANDS = {
    "sudo",
    "doas",
    "command",
    "nohup",
    "nice",
    "stdbuf",
    "setsid",
    "time",
}

ENV_WRAPPERS = {"env"}
INTERPRETERS = {
    "bash",
    "sh",
    "zsh",
    "fish",
    "python",
    "python3",
    "node",
    "ruby",
    "perl",
    "pwsh",
    "powershell",
    "cmd",
}
INLINE_FLAGS = {
    "-c",
    "-e",
    "-ec",
    "-ce",
    "-enc",
    "-EncodedCommand",
    "-Command",
    "/c",
}
SCRIPT_EXTENSIONS = {".sh", ".py", ".js", ".mjs", ".cjs", ".rb", ".pl", ".ps1", ".cmd", ".bat"}
PACKAGE_RUNNER_COMMANDS = {"npx", "bunx", "uvx"}
RISKY_RUNNER_SOURCE_RE = (
    r"(github:|git\+|https?://|file:|\.tgz($|[^A-Za-z0-9_])|@latest($|[^A-Za-z0-9_])|^\./|^\.\./|^/)"
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def home_dir() -> pathlib.Path:
    return pathlib.Path(os.path.expanduser("~"))


def state_dir(root: pathlib.Path) -> pathlib.Path:
    home = os.environ.get("RUNWALL_HOME") or os.environ.get("SECURE_CLAUDE_CODE_HOME")
    if home:
        return pathlib.Path(home) / "state"
    return home_dir() / ".runwall" / "state"


def tool_store_path(root: pathlib.Path) -> pathlib.Path:
    return state_dir(root) / "tools.json"


def tool_policy_path(root: pathlib.Path) -> pathlib.Path:
    home = os.environ.get("RUNWALL_HOME") or os.environ.get("SECURE_CLAUDE_CODE_HOME")
    if home:
        return pathlib.Path(home) / "config" / "tool-trust-policy.json"
    return root / "config" / "tool-trust-policy.json"


def _safe_rel(path: pathlib.Path, base: pathlib.Path) -> bool:
    try:
        path.relative_to(base)
        return True
    except Exception:
        return False


def load_policy(root: pathlib.Path) -> dict[str, Any]:
    policy = json.loads(json.dumps(DEFAULT_POLICY))
    path = tool_policy_path(root)
    if not path.exists():
        return policy
    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError:
        return policy
    if not isinstance(payload, dict):
        return policy
    for key, default in DEFAULT_POLICY.items():
        value = payload.get(key, default)
        if isinstance(default, list):
            policy[key] = [str(item) for item in value if isinstance(item, (str, int, float))]
        else:
            policy[key] = value
    return policy


def load_store(root: pathlib.Path) -> dict[str, Any]:
    path = tool_store_path(root)
    if not path.exists():
        return {"version": 1, "tools": {}, "aliases": {}}
    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {"version": 1, "tools": {}, "aliases": {}}
    if not isinstance(payload, dict):
        return {"version": 1, "tools": {}, "aliases": {}}
    payload.setdefault("version", 1)
    payload.setdefault("tools", {})
    payload.setdefault("aliases", {})
    return payload


def save_store(root: pathlib.Path, store: dict[str, Any]) -> None:
    path = tool_store_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(store, indent=2, sort_keys=True) + "\n")


def _shell_split(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=os.name != "nt")
    except ValueError:
        return [token for token in command.strip().split() if token]


def _strip_assignments(tokens: list[str]) -> list[str]:
    result = list(tokens)
    while result and "=" in result[0] and not result[0].startswith(("-", "/", "./", "../")):
        key, _, value = result[0].partition("=")
        if key and value and all(ch.isalnum() or ch == "_" for ch in key):
            result = result[1:]
            continue
        break
    return result


def _sanitize_token(token: str) -> str:
    stripped = token.strip()
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in {'"', "'"}:
        return stripped[1:-1]
    return stripped


def _next_command_tokens(tokens: list[str]) -> tuple[str | None, list[str], list[str]]:
    current = _strip_assignments(tokens)
    wrappers: list[str] = []
    while current:
        head = current[0]
        if head in ENV_WRAPPERS:
            wrappers.append(head)
            current = _strip_assignments(current[1:])
            continue
        if head in WRAPPER_COMMANDS:
            wrappers.append(head)
            current = current[1:]
            while current and current[0].startswith("-"):
                current = current[1:]
            current = _strip_assignments(current)
            continue
        return head, current, wrappers
    return None, [], wrappers


def _candidate_script(tokens: list[str]) -> str | None:
    for token in tokens:
        if token.startswith("-"):
            continue
        return token
    return None


def _resolve_token(token: str, *, cwd: pathlib.Path) -> pathlib.Path | None:
    expanded = os.path.expanduser(_sanitize_token(token))
    if any(sep in expanded for sep in ("/", "\\")) or expanded.startswith("."):
        path = pathlib.Path(expanded)
        if not path.is_absolute():
            path = pathlib.Path(os.path.abspath(str(cwd / path)))
        return path
    candidates = _path_candidates(expanded, cwd=cwd)
    if candidates:
        return candidates[0]
    resolved = shutil.which(expanded)
    if resolved:
        return pathlib.Path(os.path.abspath(resolved))
    return None


def _path_candidates(token: str, *, cwd: pathlib.Path) -> list[pathlib.Path]:
    expanded = os.path.expanduser(_sanitize_token(token))
    if any(sep in expanded for sep in ("/", "\\")) or expanded.startswith("."):
        path = pathlib.Path(expanded)
        if not path.is_absolute():
            path = pathlib.Path(os.path.abspath(str(cwd / path)))
        return [path]
    results: list[pathlib.Path] = []
    seen: set[str] = set()
    path_value = os.environ.get("PATH", "")
    path_exts = [""]
    if os.name == "nt":
        raw_exts = os.environ.get("PATHEXT", "")
        for item in raw_exts.split(os.pathsep):
            ext = item.strip()
            if ext and ext.lower() not in {existing.lower() for existing in path_exts}:
                path_exts.append(ext)
    for base in path_value.split(os.pathsep):
        if not base:
            continue
        for ext in path_exts:
            candidate_name = expanded if not ext or expanded.lower().endswith(ext.lower()) else f"{expanded}{ext}"
            candidate = pathlib.Path(os.path.abspath(str(pathlib.Path(base) / candidate_name)))
            key = str(candidate).lower() if os.name == "nt" else str(candidate)
            if key in seen:
                continue
            if candidate.exists():
                results.append(candidate)
                seen.add(key)
    return results


def _classify_origin(path: pathlib.Path, root: pathlib.Path) -> str:
    normalized = pathlib.Path(os.path.abspath(str(path)))
    path_text = str(normalized).replace("\\", "/").lower()
    home = home_dir().resolve(strict=False)
    tmp_dirs = {
        pathlib.Path("/tmp"),
        pathlib.Path("/var/tmp"),
        pathlib.Path("/private/tmp"),
    }
    env_tmp = os.environ.get("TMPDIR") or os.environ.get("TEMP") or os.environ.get("TMP")
    if env_tmp:
        tmp_dirs.add(pathlib.Path(env_tmp).resolve(strict=False))

    download_dirs = {
        home / "Downloads",
    }
    cache_dirs = {
        home / ".cache",
        home / "Library" / "Caches",
    }
    package_managed_dirs = {
        pathlib.Path("/Applications"),
        pathlib.Path("/Library/Frameworks"),
        pathlib.Path("/opt/homebrew/bin"),
        pathlib.Path("/opt/homebrew/sbin"),
        pathlib.Path("/opt/homebrew/Cellar"),
        pathlib.Path("/opt/hostedtoolcache"),
        pathlib.Path("/usr/local/bin"),
        pathlib.Path("/usr/local/sbin"),
        pathlib.Path("/usr/local/Cellar"),
        pathlib.Path("/nix/store"),
        home / ".cargo" / "bin",
        home / ".local" / "bin",
        home / ".npm-global" / "bin",
        home / ".bun" / "bin",
        home / "go" / "bin",
        home / "hostedtoolcache",
        home / ".pyenv" / "shims",
        home / ".asdf" / "shims",
    }
    system_dirs = {
        pathlib.Path("/bin"),
        pathlib.Path("/Library/Apple/usr/bin"),
        pathlib.Path("/sbin"),
        pathlib.Path("/usr/bin"),
        pathlib.Path("/usr/sbin"),
    }

    if _safe_rel(normalized, root.resolve(strict=False)):
        return "workspace-local"
    for base in tmp_dirs:
        if _safe_rel(normalized, base.resolve(strict=False)):
            return "temp"
    for base in download_dirs:
        if _safe_rel(normalized, base.resolve(strict=False)):
            return "download"
    for base in cache_dirs:
        if _safe_rel(normalized, base.resolve(strict=False)):
            return "cache"
    for base in package_managed_dirs:
        if _safe_rel(normalized, base.resolve(strict=False)):
            return "package-managed"
    for base in system_dirs:
        if _safe_rel(normalized, base.resolve(strict=False)):
            return "system"
    if _safe_rel(normalized, home):
        return "user-local"
    if any(
        marker in path_text
        for marker in (
            "/program files/",
            "/program files (x86)/",
            "/hostedtoolcache/",
            "/scoop/apps/",
            "/chocolatey/bin/",
        )
    ):
        return "package-managed"
    if any(marker in path_text for marker in ("/windows/system32/", "/sysnative/")):
        return "system"
    if "appdata/local/temp" in path_text or "windows/temp" in path_text:
        return "temp"
    if "/downloads/" in path_text:
        return "download"
    return "unknown"


def _sha256_file(path: pathlib.Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _detect_kind(path: pathlib.Path) -> tuple[str, list[str]]:
    interpreter_chain: list[str] = []
    if not path.exists():
        return "missing", interpreter_chain
    if path.is_symlink():
        interpreter_chain.append("symlink")
    if path.suffix.lower() in SCRIPT_EXTENSIONS:
        return "script", interpreter_chain
    try:
        with path.open("rb") as fh:
            first = fh.readline(256)
    except OSError:
        return "binary", interpreter_chain
    if first.startswith(b"#!"):
        try:
            shebang = first[2:].decode("utf-8", errors="ignore").strip()
        except Exception:
            shebang = ""
        if shebang:
            interpreter_chain.append(shebang.split()[0])
        return "script", interpreter_chain
    return "binary", interpreter_chain


def _file_age_seconds(path: pathlib.Path) -> float | None:
    if not path.exists():
        return None
    try:
        return max(0.0, datetime.now(timezone.utc).timestamp() - path.stat().st_mtime)
    except OSError:
        return None


def _synthetic_identity(display_name: str, command: str) -> dict[str, Any]:
    return {
        "display_name": display_name,
        "resolved_path": None,
        "origin": "unknown",
        "kind": "shell",
        "interpreter_chain": [],
        "explicit_path": False,
        "bare_name": True,
        "inline_wrapper": False,
        "command": command,
    }


def _detect_shell_alias_hijack(command: str, high_trust_names: set[str]) -> dict[str, Any] | None:
    for name in sorted(high_trust_names):
        patterns = (
            rf"(^|[;&|]\s*|\s)alias\s+{re.escape(name)}=",
            rf"(^|[;&|]\s*|\s)function\s+{re.escape(name)}\s*\(",
            rf"(^|[;&|]\s*|\s){re.escape(name)}\s*\(\)\s*\{{",
        )
        if any(re.search(pattern, command) for pattern in patterns):
            return _hit(
                "shell-alias-hijack-guard",
                "block",
                f"Blocked shell alias or function override for trusted tool {name}.",
                _synthetic_identity(name, command),
                reason="The shell command defines an alias or function for a trusted tool name, which can hide the real executable behind shell-level indirection.",
                safer_alternative="Call the reviewed executable directly and keep alias or function overrides out of automated runtime sessions.",
            )
    return None


def _detect_package_runner_wrapper(command_name: str | None, current: list[str]) -> tuple[str | None, str | None]:
    if not command_name:
        return None, None
    name = pathlib.Path(command_name).name
    package_token = None
    if name in PACKAGE_RUNNER_COMMANDS:
        package_token = current[1] if len(current) > 1 else None
    elif name == "pnpm" and len(current) > 2 and current[1] == "dlx":
        package_token = current[2]
    elif name == "yarn" and len(current) > 2 and current[1] == "dlx":
        package_token = current[2]
    elif name == "pipx" and len(current) > 2 and current[1] == "run":
        package_token = current[2]
    if package_token and re.search(RISKY_RUNNER_SOURCE_RE, package_token):
        return name, package_token
    return None, None


def resolve_tool_identity(root: pathlib.Path, command: str) -> dict[str, Any] | None:
    tokens = _shell_split(command)
    command_name, current, wrappers = _next_command_tokens(tokens)
    if not command_name:
        return None
    cwd = pathlib.Path(os.getcwd()).resolve(strict=False)
    display_name = command_name
    explicit_path = any(sep in command_name for sep in ("/", "\\")) or command_name.startswith(".")
    interpreter_chain = list(wrappers)
    kind = "binary"
    script_path: pathlib.Path | None = None
    resolved_path: pathlib.Path | None = None
    inline_wrapper = False
    path_candidates = _path_candidates(command_name, cwd=cwd) if command_name else []
    launch_path: pathlib.Path | None = None

    if pathlib.Path(command_name).name in INTERPRETERS:
        interpreter_chain.append(pathlib.Path(command_name).name)
        tail = current[1:]
        if tail and tail[0] in INLINE_FLAGS:
            inline_wrapper = True
            launch_path = _resolve_token(command_name, cwd=cwd)
            resolved_path = launch_path
            kind = "interpreter-inline"
        else:
            candidate = _candidate_script(tail)
            if candidate:
                script_path = _resolve_token(candidate, cwd=cwd)
                launch_path = script_path or _resolve_token(command_name, cwd=cwd)
                resolved_path = launch_path
                if script_path:
                    display_name = pathlib.Path(candidate).name
                    explicit_path = any(sep in candidate for sep in ("/", "\\")) or candidate.startswith(".")
                    kind = "script"
                else:
                    kind = "binary"
            else:
                launch_path = _resolve_token(command_name, cwd=cwd)
                resolved_path = launch_path
                kind = "binary"
    else:
        launch_path = _resolve_token(command_name, cwd=cwd)
        resolved_path = launch_path

    if resolved_path:
        resolved_path = resolved_path.resolve(strict=False)
    effective_path = script_path or resolved_path
    launch_effective_path = script_path or launch_path or resolved_path
    if not effective_path:
        return {
            "display_name": display_name,
            "resolved_path": None,
            "origin": "unknown",
            "kind": "shell-builtin",
            "interpreter_chain": interpreter_chain,
            "explicit_path": explicit_path,
            "bare_name": not explicit_path,
            "inline_wrapper": inline_wrapper,
            "command": command,
        }

    detected_kind, detected_interpreters = _detect_kind(effective_path)
    if kind not in {"interpreter-inline", "script"}:
        kind = detected_kind
    interpreter_chain.extend(item for item in detected_interpreters if item not in interpreter_chain)
    origin = _classify_origin(effective_path, root)
    launch_origin = _classify_origin(launch_effective_path, root) if launch_effective_path else origin
    symlink_target = None
    symlink_origin = None
    if launch_effective_path and launch_effective_path.exists() and launch_effective_path.is_symlink():
        try:
            symlink_target = str(launch_effective_path.resolve(strict=False))
            symlink_origin = _classify_origin(pathlib.Path(symlink_target), root)
        except OSError:
            symlink_target = None
            symlink_origin = None
    return {
        "display_name": display_name,
        "resolved_path": str(effective_path),
        "launch_path": str(launch_effective_path) if launch_effective_path else str(effective_path),
        "origin": origin,
        "launch_origin": launch_origin,
        "kind": kind,
        "interpreter_chain": interpreter_chain,
        "explicit_path": explicit_path,
        "bare_name": not explicit_path,
        "inline_wrapper": inline_wrapper,
        "command": command,
        "argv0": command_name,
        "sha256": _sha256_file(effective_path),
        "exists": effective_path.exists(),
        "size": effective_path.stat().st_size if effective_path.exists() else None,
        "symlink_target": symlink_target,
        "symlink_origin": symlink_origin,
        "path_candidates": [str(path) for path in path_candidates[:6]],
        "path_candidate_origins": [_classify_origin(path, root) for path in path_candidates[:6]],
        "age_seconds": _file_age_seconds(effective_path),
    }


def _store_record(identity: dict[str, Any], trust_state: str, existing: dict[str, Any] | None = None) -> dict[str, Any]:
    now = utc_now()
    record = dict(existing or {})
    record.update(
        {
            "display_name": identity["display_name"],
            "resolved_path": identity.get("resolved_path"),
            "origin": identity.get("origin"),
            "kind": identity.get("kind"),
            "interpreter_chain": identity.get("interpreter_chain", []),
            "sha256": identity.get("sha256"),
            "explicit_path": bool(identity.get("explicit_path")),
            "bare_name": bool(identity.get("bare_name")),
            "trust_state": trust_state,
            "last_seen_at": now,
        }
    )
    record.setdefault("first_seen_at", now)
    record["use_count"] = int(record.get("use_count", 0)) + 1
    return record


def _hit(module: str, decision: str, output: str, identity: dict[str, Any], *, reason: str, safer_alternative: str) -> dict[str, Any]:
    return {
        "module": module,
        "name": module.replace("-", " ").title(),
        "category": "tool-trust",
        "family": "Runtime, Network & Egress",
        "decision": decision,
        "exit_code": 2 if decision == "block" else 0,
        "output": output,
        "metadata": {
            "reason": reason,
            "confidence": 0.96 if decision == "block" else 0.84,
            "safer_alternative": safer_alternative,
            "tool_identity": identity,
        },
    }


def assess_command(root: pathlib.Path, command: str) -> dict[str, Any]:
    policy = load_policy(root)
    high_trust_names = set(policy.get("high_trust_names", []))
    tokens = _shell_split(command)
    command_name, current, _ = _next_command_tokens(tokens)

    alias_hit = _detect_shell_alias_hijack(command, high_trust_names)
    if alias_hit:
        return {"identity": alias_hit["metadata"]["tool_identity"], "hit": alias_hit}

    runner_name, package_token = _detect_package_runner_wrapper(command_name, current)
    if runner_name and package_token:
        identity = _synthetic_identity(runner_name, command)
        return {
            "identity": identity,
            "hit": _hit(
                "package-runner-wrapper-guard",
                "prompt",
                f"Review required before using {runner_name} with a remote or mutable package source.",
                identity,
                reason="One-shot package runners can fetch and execute tools outside the normal reviewed install path, especially when they point at URLs, git sources, file paths, or @latest targets.",
                safer_alternative="Install the tool from a reviewed package source first, or pin it to a reviewed package version before execution.",
            ),
        }

    identity = resolve_tool_identity(root, command)
    if not identity:
        return {"identity": None, "hit": None}

    store = load_store(root)
    aliases: dict[str, Any] = store.setdefault("aliases", {})
    tools: dict[str, Any] = store.setdefault("tools", {})
    alias_key = str(identity.get("display_name") or identity.get("resolved_path") or "")
    existing = aliases.get(alias_key)
    trust_state = "observed"
    hit: dict[str, Any] | None = None

    if not identity.get("resolved_path"):
        return {"identity": identity, "hit": None}

    origin = str(identity.get("origin", "unknown"))
    launch_origin = str(identity.get("launch_origin", origin))
    symlink_origin = str(identity.get("symlink_origin") or origin)
    resolved_path = str(identity.get("resolved_path"))
    high_trust = alias_key in high_trust_names
    wrapper_block = alias_key in set(policy.get("wrapper_block_names", []))
    auto_trust_origins = set(policy.get("auto_trust_origins", []))
    review_origins = set(policy.get("review_origins", []))
    shadow_block_origins = set(policy.get("shadow_block_origins", []))
    block_origins = set(policy.get("block_origins", []))
    candidate_origins = identity.get("path_candidate_origins") or []
    path_candidates = identity.get("path_candidates") or []
    recent_tool_seconds = int(policy.get("recent_tool_seconds", 900))

    if high_trust and identity.get("bare_name") and path_candidates and len(path_candidates) > 1 and launch_origin in shadow_block_origins and any(item in auto_trust_origins for item in candidate_origins[1:]):
        trust_state = "blocked"
        hit = _hit(
            "path-prepend-hijack-guard",
            "block",
            f"Blocked {alias_key} because PATH resolves it to an unreviewed location ahead of a reviewed system or package-managed tool.",
            identity,
            reason="A trusted command name is being intercepted by PATH order rather than invoked from its reviewed location, which is a classic local hijack pattern.",
            safer_alternative="Remove the unreviewed PATH entry or call the intended tool by its explicit reviewed path.",
        )
    elif identity.get("symlink_target") and (high_trust or existing) and not (
        launch_origin in auto_trust_origins and symlink_origin in auto_trust_origins
    ):
        trust_state = "blocked"
        hit = _hit(
            "symlink-tool-swap-guard",
            "block",
            f"Blocked {alias_key} because it resolves through a symlinked local tool path.",
            identity,
            reason="A trusted or previously seen tool now executes through a symlink, which is a low-friction way to swap the target behind the same command name.",
            safer_alternative="Use a direct reviewed executable path instead of a symlinked tool shim unless that link is explicitly reviewed.",
        )
    elif origin in block_origins:
        trust_state = "blocked"
        hit = _hit(
            "temp-download-exec-guard",
            "block",
            "Blocked execution of an unreviewed tool from a temp, cache, or download path.",
            identity,
            reason="The executable resolves to a temp, cache, or download location that should not become part of the trusted tool plane.",
            safer_alternative="Move the tool into a reviewed install path or package-managed location before execution.",
        )
    elif high_trust and origin in shadow_block_origins:
        trust_state = "blocked"
        hit = _hit(
            "command-shadowing-guard",
            "block",
            f"Blocked {alias_key} because it resolves to an unreviewed path instead of a trusted system or package-managed location.",
            identity,
            reason="A high-trust command name now resolves to an unexpected local path, which is a strong sign of PATH shadowing or tool replacement.",
            safer_alternative="Restore the reviewed executable path or call the intended tool by its explicit trusted location.",
        )
    elif existing:
        if existing.get("trust_state") == "approved" and existing.get("resolved_path") == resolved_path and existing.get("sha256") == identity.get("sha256"):
            trust_state = "approved"
        elif existing.get("resolved_path") != resolved_path or existing.get("sha256") != identity.get("sha256"):
            changed_wrapper = existing.get("kind") != identity.get("kind") or existing.get("interpreter_chain") != identity.get("interpreter_chain")
            if changed_wrapper and wrapper_block:
                trust_state = "blocked"
                hit = _hit(
                    "interpreter-wrapper-guard",
                    "block",
                    f"Blocked {alias_key} because the trusted tool now resolves through a wrapper or interpreter chain.",
                    identity,
                    reason="The tool changed from its prior execution shape into a script or interpreter wrapper, which is a common way to hide hijacked behavior.",
                    safer_alternative="Review the new wrapper path and restore the original binary or explicitly approve the new tool shape only if expected.",
                )
            else:
                trust_state = "prompted"
                hit = _hit(
                    "tool-drift-guard",
                    "prompt",
                    f"Review required because {alias_key} changed path, hash, or execution shape since Runwall last saw it.",
                    identity,
                    reason="The tool identity drifted from the last trusted observation, which means its behavior or provenance may have changed.",
                    safer_alternative=f"Run `./bin/runwall tools approve {shlex.quote(alias_key)}` after reviewing the new path and hash if the change is legitimate.",
                )
        else:
            trust_state = existing.get("trust_state", "trusted")
    else:
        if identity.get("inline_wrapper") and wrapper_block:
            trust_state = "blocked"
            hit = _hit(
                "interpreter-wrapper-guard",
                "block",
                f"Blocked {alias_key} because it is executing through an inline interpreter wrapper.",
                identity,
                reason="Inline interpreter execution hides the real tool body and makes provenance much weaker than a reviewed executable or script path.",
                safer_alternative="Use a reviewed executable or script file instead of inline interpreter payloads for trusted commands.",
            )
        elif origin in review_origins and identity.get("age_seconds") is not None and float(identity["age_seconds"]) <= recent_tool_seconds:
            trust_state = "prompted"
            hit = _hit(
                "generated-tool-chain-guard",
                "prompt",
                f"Review required before trusting newly created local executable {alias_key}.",
                identity,
                reason="This tool appeared very recently in a local execution path, which often means it was just generated, dropped, or installed and has not been reviewed yet.",
                safer_alternative=f"Review the new executable and then run `./bin/runwall tools approve {shlex.quote(alias_key)}` if it is expected.",
            )
        elif identity.get("bare_name") and origin in review_origins:
            trust_state = "prompted"
            hit = _hit(
                "unknown-executable-guard",
                "prompt",
                f"Review required before trusting the first-seen tool {alias_key} from an unreviewed local path.",
                identity,
                reason="Runwall has not seen this executable before and it does not come from a clearly reviewed system or package-managed location.",
                safer_alternative=f"Review the tool and then run `./bin/runwall tools approve {shlex.quote(alias_key)}` if you want to trust it locally.",
            )
        elif high_trust and origin not in set(policy.get("auto_trust_origins", [])):
            trust_state = "blocked"
            hit = _hit(
                "command-shadowing-guard",
                "block",
                f"Blocked first-seen high-trust command {alias_key} from an unreviewed path.",
                identity,
                reason="A trusted command name should not first appear from a local, user, or otherwise unreviewed path.",
                safer_alternative="Install the trusted tool from a reviewed package path or invoke it by an explicit known-good location.",
            )
        else:
            trust_state = "trusted"

    alias_record = _store_record(identity, trust_state, existing)
    aliases[alias_key] = alias_record
    tools[resolved_path] = {
        **alias_record,
        "alias_key": alias_key,
    }
    save_store(root, store)
    return {"identity": identity, "hit": hit}


def list_tools(root: pathlib.Path) -> list[dict[str, Any]]:
    store = load_store(root)
    aliases = store.get("aliases", {})
    items = [dict(record, alias_key=key) for key, record in aliases.items() if isinstance(record, dict)]
    items.sort(key=lambda item: (item.get("trust_state", ""), item.get("alias_key", "")))
    return items


def approve_tool(root: pathlib.Path, selector: str) -> bool:
    store = load_store(root)
    aliases = store.setdefault("aliases", {})
    tools = store.setdefault("tools", {})
    record = aliases.get(selector)
    if record is None:
        for key, candidate in aliases.items():
            if candidate.get("resolved_path") == selector:
                selector = key
                record = candidate
                break
    if record is None:
        return False
    record["trust_state"] = "approved"
    record["approved_at"] = utc_now()
    aliases[selector] = record
    resolved_path = record.get("resolved_path")
    if resolved_path and resolved_path in tools:
        tools[resolved_path]["trust_state"] = "approved"
        tools[resolved_path]["approved_at"] = record["approved_at"]
    save_store(root, store)
    return True


def forget_tool(root: pathlib.Path, selector: str) -> bool:
    store = load_store(root)
    aliases = store.setdefault("aliases", {})
    tools = store.setdefault("tools", {})
    removed = False
    record = aliases.pop(selector, None)
    if record:
        removed = True
        resolved_path = record.get("resolved_path")
        if resolved_path:
            tools.pop(resolved_path, None)
    else:
        for key, candidate in list(aliases.items()):
            if candidate.get("resolved_path") == selector:
                aliases.pop(key, None)
                tools.pop(selector, None)
                removed = True
                break
    if removed:
        save_store(root, store)
    return removed


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage Runwall tool trust state")
    parser.add_argument("--root", required=True)
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list")
    list_parser.add_argument("--json", action="store_true")

    approve_parser = subparsers.add_parser("approve")
    approve_parser.add_argument("selector")

    forget_parser = subparsers.add_parser("forget")
    forget_parser.add_argument("selector")

    args = parser.parse_args()
    root = pathlib.Path(args.root)

    if args.command == "list":
        items = list_tools(root)
        if args.json:
            print(json.dumps({"tools": items}, indent=2))
        else:
            print("Trusted Tools:")
            for item in items:
                print(
                    f"- {item.get('alias_key')} [{item.get('trust_state')}] "
                    f"{item.get('origin')} -> {item.get('resolved_path')}"
                )
        return 0
    if args.command == "approve":
        if approve_tool(root, args.selector):
            print(f"approved {args.selector}")
            return 0
        print(f"unknown tool: {args.selector}", file=os.sys.stderr)
        return 1
    if args.command == "forget":
        if forget_tool(root, args.selector):
            print(f"forgot {args.selector}")
            return 0
        print(f"unknown tool: {args.selector}", file=os.sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
