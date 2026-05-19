#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
from datetime import datetime, timezone
from typing import Any

import stallion_destructive_surface


TEXT_PATH_RE = re.compile(
    r"(?i)\.(?:md|txt|json|yaml|yml|toml|ini|conf|env|sh|py|js|ts|tsx|jsx|java|go|rs|rb|php|cs|sql|xml|html|css)$"
)
STUB_RE = re.compile(
    r"(?is)^(?:"
    r"(?:#|//|/\*|\*).{0,120}(?:todo|placeholder|stub|coming soon|intentionally blank).*|"
    r"todo|placeholder|stub|coming soon|intentionally blank|"
    r"pass|raise\s+NotImplementedError(?:\(\))?|"
    r"return\s+(?:true|false|null|none|{}|\[\])|"
    r"module\.exports\s*=\s*{};?|export\s+default\s+{};?|"
    r"{}\s*|\[\]\s*"
    r")$"
)
FOREIGN_HEADER_RE = re.compile(r"(?i)^(?:<!DOCTYPE html|<html\b|%PDF-|-----BEGIN [A-Z ]+-----|Salted__|PK[\x03\x05\x07])")
ENCRYPTION_MARKER_RE = re.compile(r"(?i)(?:-----BEGIN AGE ENCRYPTED FILE-----|U2FsdGVkX1|Salted__|hQGMA|BEGIN PGP MESSAGE)")
DELAYED_DESTRUCTION_RE = re.compile(
    r"(?i)(?:crontab|schtasks|launchctl|systemd-run|onCalendar|@reboot|postinstall|preinstall|rc\.local|LaunchAgents?|ScheduledTask|schedule)[^\n\r]{0,240}"
    r"(?:rm\s+-[A-Za-z]*r[fA-Za-z]*|truncate\s+-s\s+0|chmod\s+0{3}\b|terraform\s+destroy|DROP\s+TABLE|TRUNCATE\s+TABLE|openssl\s+enc|gpg\s+-c|age\s+-e)"
)
RESOURCE_EXHAUSTION_RE = re.compile(
    r"(?i)(?:fallocate\s+-l|dd\s+if=/dev/zero|yes\s+>|:\(\)\s*\{\s*:\|:&\s*\};:|fsutil\s+file\s+createnew)"
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def state_dir(root: pathlib.Path) -> pathlib.Path:
    home = os.environ.get("STALLION_HOME") or os.environ.get("STALLION_HOME")
    if home:
        return pathlib.Path(home) / "state"
    return pathlib.Path(os.path.expanduser("~")) / ".stallion" / "state"


def store_path(root: pathlib.Path) -> pathlib.Path:
    return state_dir(root) / "file_destructive.json"


def load_store(root: pathlib.Path) -> dict[str, Any]:
    path = store_path(root)
    if not path.exists():
        return {"version": 1, "surfaces": {}, "sessions": {}}
    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {"version": 1, "surfaces": {}, "sessions": {}}
    if not isinstance(payload, dict):
        return {"version": 1, "surfaces": {}, "sessions": {}}
    payload.setdefault("version", 1)
    payload.setdefault("surfaces", {})
    payload.setdefault("sessions", {})
    return payload


def save_store(root: pathlib.Path, store: dict[str, Any]) -> None:
    path = store_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(store, indent=2, sort_keys=True) + "\n")


def _fingerprint(text: str) -> str:
    normalized = re.sub(r"\s+", " ", text.strip())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _fileop_surface(matcher: str, payload: str) -> tuple[pathlib.Path | None, str]:
    tokens = stallion_destructive_surface.shell_split(payload)
    if not tokens:
        return None, ""
    first = tokens[0]
    path = stallion_destructive_surface.normalize_path_token(first)
    if matcher in {"Write", "Edit", "MultiEdit"}:
        return path, payload[len(first) :].strip()
    return path, ""


def _looks_text_path(path: pathlib.Path, content: str) -> bool:
    if TEXT_PATH_RE.search(path.name):
        return True
    if not path.suffix:
        return bool(content)
    return False


def _read_existing_text(path: pathlib.Path, max_bytes: int = 262144) -> tuple[str | None, int]:
    try:
        stat = path.stat()
    except OSError:
        return None, 0
    if stat.st_size > max_bytes:
        return None, stat.st_size
    try:
        return path.read_text(encoding="utf-8"), stat.st_size
    except (OSError, UnicodeDecodeError):
        return None, stat.st_size


def _is_base64_like(text: str) -> bool:
    compact = re.sub(r"\s+", "", text)
    if len(compact) < 96:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/=._-]+", compact):
        return False
    alpha_ratio = sum(ch.isalnum() or ch in "+/=_-" for ch in compact) / max(len(compact), 1)
    return alpha_ratio >= 0.96


def _looks_junk_or_ciphertext(text: str) -> bool:
    if ENCRYPTION_MARKER_RE.search(text):
        return True
    if FOREIGN_HEADER_RE.search(text):
        return True
    if _is_base64_like(text) and len(re.findall(r"[A-Za-z]{3,}", text)) <= 6:
        return True
    return False


def _record_signal(
    store: dict[str, Any],
    *,
    path: pathlib.Path,
    surface: str,
    fingerprint: str | None,
    signal: str | None,
    session_id: str | None,
) -> None:
    path_key = str(path)
    surfaces = store.setdefault("surfaces", {})
    sessions = store.setdefault("sessions", {})
    record = surfaces.get(path_key) if isinstance(surfaces.get(path_key), dict) else {}
    surfaces[path_key] = {
        "surface": surface,
        "fingerprint": fingerprint or record.get("fingerprint"),
        "last_signal": signal or record.get("last_signal"),
        "last_session_id": session_id or record.get("last_session_id"),
        "last_seen_at": utc_now(),
        "first_seen_at": record.get("first_seen_at", utc_now()),
    }
    if session_id:
        session = sessions.setdefault(session_id, {})
        if not isinstance(session, dict):
            session = {}
            sessions[session_id] = session
        session[path_key] = {
            "last_signal": signal or record.get("last_signal"),
            "last_seen_at": utc_now(),
        }


def _previous_signal(store: dict[str, Any], path: pathlib.Path, session_id: str | None) -> str | None:
    if not session_id:
        return None
    session = store.get("sessions", {}).get(session_id)
    if not isinstance(session, dict):
        return None
    item = session.get(str(path))
    if not isinstance(item, dict):
        return None
    return str(item.get("last_signal")) if item.get("last_signal") else None


def _decision_for_surface(surface: str) -> str:
    return "block" if stallion_destructive_surface.is_critical_surface(surface) else "prompt"


def _identity(path: pathlib.Path, surface: str, matcher: str, destructive_class: str, fingerprint: str | None, tier: int) -> dict[str, Any]:
    return {
        "module": destructive_class,
        "path": str(path),
        "target": str(path),
        "surface": surface,
        "matcher": matcher,
        "fingerprint": fingerprint,
        "destructive_class": destructive_class,
        "tier": tier,
    }


def _hit(module: str, decision: str, identity: dict[str, Any], reason: str, safer: str, confidence: float) -> dict[str, Any]:
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
            "confidence": confidence,
            "safer_alternative": safer,
            "destructive_identity": identity,
        },
    }


def assess_fileop(root: pathlib.Path, event: str, matcher: str, payload: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
    if event != "PreToolUse" or matcher not in {"Write", "Edit", "MultiEdit"}:
        return {"identity": None, "hit": None}
    path, content = _fileop_surface(matcher, payload)
    if path is None:
        return {"identity": None, "hit": None}
    surface = stallion_destructive_surface.classify_path(path)
    fingerprint = _fingerprint(content) if content else None
    identity_base = {
        "path": str(path),
        "target": str(path),
        "surface": surface,
        "matcher": matcher,
        "fingerprint": fingerprint,
    }
    if surface == "generated-output":
        store = load_store(root)
        _record_signal(store, path=path, surface=surface, fingerprint=fingerprint, signal=None, session_id=str((context or {}).get("session_id") or "") or None)
        save_store(root, store)
        return {"identity": identity_base, "hit": None}

    existing_text, existing_size = _read_existing_text(path)
    existing_meaningful = bool(existing_size > 0 and ((existing_text is not None and existing_text.strip()) or existing_text is None))
    profile = str((context or {}).get("profile") or "balanced").lower()
    session_id = str((context or {}).get("session_id") or "") or None
    store = load_store(root)
    previous_signal = _previous_signal(store, path, session_id)
    hit = None
    signal = None
    textlike = _looks_text_path(path, content)

    if textlike and existing_meaningful and not content.strip():
        signal = "file-nulling-guard"
        identity = _identity(path, surface, matcher, signal, fingerprint, 1)
        hit = _hit(
            signal,
            _decision_for_surface(surface),
            identity,
            f"Blocked destructive empty overwrite of {path}." if stallion_destructive_surface.is_critical_surface(surface) else f"Review required before empty overwrite of {path}.",
            "Preserve meaningful file contents or replace the file through a reviewed migration or recovery-safe workflow.",
            0.96 if stallion_destructive_surface.is_critical_surface(surface) else 0.84,
        )
    elif textlike and existing_meaningful and STUB_RE.search(content.strip()) and len(content.strip()) <= 240:
        signal = "file-stub-replacement-guard"
        identity = _identity(path, surface, matcher, signal, fingerprint, 1)
        hit = _hit(
            signal,
            _decision_for_surface(surface),
            identity,
            f"Blocked destructive stub replacement of {path}." if stallion_destructive_surface.is_critical_surface(surface) else f"Review required before replacing {path} with a stub-like body.",
            "Keep critical files functional and replace them only with reviewed content, not placeholders, stubs, or no-op bodies.",
            0.95 if stallion_destructive_surface.is_critical_surface(surface) else 0.82,
        )
    elif textlike and existing_meaningful and _looks_junk_or_ciphertext(content):
        signal = "file-junk-overwrite-guard"
        identity = _identity(path, surface, matcher, signal, fingerprint, 1)
        hit = _hit(
            signal,
            _decision_for_surface(surface),
            identity,
            f"Blocked suspicious junk or ciphertext overwrite of {path}." if stallion_destructive_surface.is_critical_surface(surface) else f"Review required before replacing {path} with opaque or ciphertext-like content.",
            "Keep reviewed files human-auditable unless they are generated artifacts or intentionally encrypted outputs outside critical trust surfaces.",
            0.95 if stallion_destructive_surface.is_critical_surface(surface) else 0.8,
        )
    elif textlike and existing_meaningful and FOREIGN_HEADER_RE.search(content):
        signal = "foreign-header-overwrite-guard"
        identity = _identity(path, surface, matcher, signal, fingerprint, 1)
        hit = _hit(
            signal,
            _decision_for_surface(surface),
            identity,
            f"Blocked foreign-format overwrite of {path}." if stallion_destructive_surface.is_critical_surface(surface) else f"Review required before writing foreign-format header content into {path}.",
            "Keep config, policy, review, and release files in their expected text formats instead of replacing them with archive, certificate, HTML, or ciphertext headers.",
            0.94 if stallion_destructive_surface.is_critical_surface(surface) else 0.8,
        )
    elif profile == "strict" and DELAYED_DESTRUCTION_RE.search(content) and surface != "ordinary-surface":
        signal = "delayed-destruction-guard"
        identity = _identity(path, surface, matcher, signal, fingerprint, 3)
        hit = _hit(
            signal,
            "prompt",
            identity,
            f"Review required before writing delayed destructive automation into {path}.",
            "Keep cron, workflow, hook, and startup surfaces free of delayed destructive actions unless the exact maintenance workflow was separately reviewed.",
            0.78,
        )
    elif profile == "strict" and previous_signal and previous_signal != signal and RESOURCE_EXHAUSTION_RE.search(content):
        signal = "resource-exhaustion-destroy-guard"
        identity = _identity(path, surface, matcher, signal, fingerprint, 3)
        hit = _hit(
            signal,
            "prompt",
            identity,
            f"Review required before adding resource-exhaustion style destructive setup to {path}.",
            "Avoid writing disk-fill, zero-fill, or fork-bomb style content into tracked files without a tightly reviewed diagnostic reason.",
            0.7,
        )

    if profile == "strict" and previous_signal and signal and previous_signal != signal and (not hit or hit["decision"] != "block"):
        identity = _identity(path, surface, matcher, "split-step-destruction-guard", fingerprint, 3)
        hit = _hit(
            "split-step-destruction-guard",
            "prompt",
            identity,
            f"Review required because {path} is accumulating multiple destructive edit signals in the same session.",
            "Reset the edit flow and confirm the file should be rewritten this aggressively before continuing with additional destructive-like changes.",
            0.72,
        )

    _record_signal(store, path=path, surface=surface, fingerprint=fingerprint, signal=signal, session_id=session_id)
    save_store(root, store)
    if hit:
        return {"identity": hit["metadata"]["destructive_identity"], "hit": hit}
    return {"identity": identity_base, "hit": None}
