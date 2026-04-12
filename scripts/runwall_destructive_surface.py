#!/usr/bin/env python3
from __future__ import annotations

import os
import pathlib
import re
import shlex


RUNTIME_POLICY_PATH_RE = re.compile(
    r"(?i)(?:^|/)(?:"
    r"\.runwall/(?:config|state)(?:/|$)|"
    r"hooks/hooks\.json$|"
    r"\.mcp\.json$|"
    r"(?:\.claude-plugin|\.codex-plugin)/[^/]+\.json$|"
    r"(?:CLAUDE|AGENTS)\.md$|"
    r"settings\.json$"
    r")"
)
SAFETY_PATH_RE = re.compile(
    r"(?i)(?:^|/)(?:"
    r".*(?:audit(?:d|\.rules|\.jsonl)?|cloudtrail|rsyslog|syslog-ng|fluent-bit|promtail|vector|otel(?:col)?|falco|osquery)[^/]*|"
    r".*(?:backup|restore|rollback|recovery|snapshot)[^/]*|"
    r".*(?:monitor|alert|alertmanager|prometheus|grafana|datadog|newrelic|sentry|pagerduty|opsgenie)[^/]*|"
    r".*(?:incident|runbook|forensics|postmortem|evidence)[^/]*"
    r")\.(?:md|txt|json|yaml|yml|toml|conf|ini|sh|py)$|(?:^|/)(?:state|dist)/(?:audit\.jsonl|incident|forensics|evidence)"
)
RELEASE_PATH_RE = re.compile(
    r"(?i)(?:^|/)(?:"
    r"\.github/workflows/[^/]+\.(?:yml|yaml)|"
    r"package\.json|pyproject\.toml|Cargo\.toml|Dockerfile|docker-compose\.ya?ml|compose\.ya?ml|Chart\.yaml|values\.ya?ml|"
    r".*(?:sbom|bom|cyclonedx|spdx|provenance|attestation|in-toto|release-summary|release-notes|checksum|sha256|signature|sigstore|cosign|release\.asc|release\.gpg)[^/]*\.(?:json|md|txt|yaml|yml|toml)"
    r")$"
)
REVIEW_PATH_RE = re.compile(
    r"(?i)(?:^|/)(?:"
    r"\.github/(?:pull_request_template(?:\.[^/]+)?|issue_template(?:/|/[^/]+)?|PULL_REQUEST_TEMPLATE(?:\.[^/]+)?)|"
    r"(?:CHANGELOG|RELEASE_NOTES|SECURITY_REVIEW|REVIEW_NOTES|MERGE_NOTES|APPROVALS?)(?:\.[^/]+)?|"
    r"(?:docs|review|reviews|notes|tasks|tickets|incident|incidents|ops|release)/(?:[^/]+/)*[^/]*"
    r"(?:review|approval|merge|release|changelog|task|ticket|incident|postmortem|signoff)[^/]*\.(?:md|txt|yaml|yml|json)"
    r")$"
)
AUTH_PATH_RE = re.compile(
    r"(?i)(?:^|/)(?:"
    r"\.env(?:\.[^/]+)?|"
    r"\.envrc|"
    r"\.npmrc|"
    r"\.pypirc|"
    r"\.netrc|"
    r".*credentials?\.(?:json|ya?ml|toml|env)|"
    r".*secrets?\.(?:json|ya?ml|toml|env)|"
    r".*token[^/]*\.(?:json|txt|env)|"
    r".*auth[^/]*\.(?:json|ya?ml|toml|env)|"
    r"\.aws/.*|"
    r"\.ssh/.*|"
    r"\.kube/config|"
    r"known_hosts|authorized_keys"
    r")$"
)
GENERATED_PATH_RE = re.compile(
    r"(?i)(?:^|/)(?:dist|build|coverage|target|out|tmp|\.next|\.nuxt|\.cache|\.turbo|__pycache__|artifacts?)(?:/|$)|"
    r"\.(?:min\.js|min\.css|map|pyc|pyo|o|so|dylib|dll|class|jar|zip|tar|gz|tgz|whl)$"
)

CRITICAL_SURFACES = {
    "runtime-policy",
    "safety-control",
    "release-control",
    "review-surface",
    "auth-control",
}


def shell_split(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=os.name != "nt")
    except ValueError:
        return [token for token in command.strip().split() if token]


def normalize_path_token(token: str) -> pathlib.Path:
    stripped = token.strip("'\"= ")
    expanded = os.path.expanduser(stripped)
    path = pathlib.Path(expanded)
    if not path.is_absolute():
        path = pathlib.Path(os.path.abspath(str(pathlib.Path.cwd() / path)))
    return path


def _is_system_temp_path(path: pathlib.Path) -> bool:
    candidates = {
        pathlib.Path("/tmp"),
        pathlib.Path("/var/tmp"),
        pathlib.Path("/private/tmp"),
    }
    for env_name in ("TMPDIR", "TEMP", "TMP"):
        value = os.environ.get(env_name)
        if value:
            candidates.add(pathlib.Path(value).resolve(strict=False))
    resolved = path.resolve(strict=False)
    for base in candidates:
        try:
            resolved.relative_to(base.resolve(strict=False))
            return True
        except ValueError:
            continue
    return False


def classify_path(path: pathlib.Path) -> str:
    location = str(path).replace("\\", "/")
    if RUNTIME_POLICY_PATH_RE.search(location):
        return "runtime-policy"
    if SAFETY_PATH_RE.search(location):
        return "safety-control"
    if RELEASE_PATH_RE.search(location):
        return "release-control"
    if REVIEW_PATH_RE.search(location):
        return "review-surface"
    if AUTH_PATH_RE.search(location):
        return "auth-control"
    if path.is_absolute() and _is_system_temp_path(path):
        return "ordinary-surface"
    if GENERATED_PATH_RE.search(location):
        return "generated-output"
    return "ordinary-surface"


def is_critical_surface(surface: str) -> bool:
    return surface in CRITICAL_SURFACES
