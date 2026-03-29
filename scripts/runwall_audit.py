#!/usr/bin/env python3
from __future__ import annotations

import argparse
import html
import json
import pathlib
import re
import sys
import warnings
from dataclasses import dataclass
from typing import Any


SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".dmux",
    "node_modules",
    "dist",
    "build",
    "out",
    "coverage",
    "__pycache__",
}

CATEGORY_LABELS = {
    "secrets": "Secrets",
    "permissions": "Permissions",
    "hooks": "Hooks",
    "mcp": "MCP",
    "agents": "Agents",
}

SEVERITY_WEIGHTS = {
    "critical": 30,
    "high": 18,
    "medium": 10,
    "low": 4,
    "info": 1,
}

GRADE_BANDS = [
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (60, "D"),
    (50, "E"),
    (0, "F"),
]

FAIL_ON_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

RUNWALL_AUDIT_WORKFLOW = """name: Runwall Audit

on:
  pull_request:
  push:
    branches: [main]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.x'
      - name: Run Runwall audit
        run: |
          ./bin/runwall audit . --format json --fail-on high --output runwall-audit.json
      - name: Upload report
        uses: actions/upload-artifact@v4
        with:
          name: runwall-audit
          path: runwall-audit.json
"""


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    category: str
    file: str
    line: int
    evidence: str
    description: str
    fix: str
    guard_id: str
    runtime_effect: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "file": self.file,
            "line": self.line,
            "evidence": self.evidence,
            "description": self.description,
            "fix": self.fix,
            "guardId": self.guard_id,
            "runtimeEffect": self.runtime_effect,
            "enableWith": f"./bin/runwall install strict",
        }


class AuditEngine:
    def __init__(self, root: pathlib.Path, profile: str) -> None:
        self.root = root
        self.profile = profile
        self.config_dir = pathlib.Path(__file__).resolve().parents[1] / "config"
        self.findings: list[Finding] = []
        self.secret_patterns = self._compile_patterns("mcp-response-secrets.regex")
        self.prompt_patterns = self._compile_patterns(
            "prompt-injection-override.regex",
            "prompt-injection-roleplay.regex",
            "prompt-injection-context.regex",
            "prompt-injection-smuggling.regex",
        )
        self.mcp_source_patterns = self._compile_patterns("gateway-risky-sources.regex")

    def _compile_patterns(self, *names: str) -> list[re.Pattern[str]]:
        patterns: list[re.Pattern[str]] = []
        for name in names:
            path = self.config_dir / name
            if not path.exists():
                continue
            for raw in path.read_text(encoding="utf-8").splitlines():
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    normalized = (
                        line.replace("[[:space:]]", r"\s")
                        .replace("[^[:alnum:]_]", r"[^A-Za-z0-9_]")
                        .replace("[[:alnum:]_]", r"[A-Za-z0-9_]")
                    )
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore", FutureWarning)
                        patterns.append(re.compile(normalized, re.IGNORECASE | re.MULTILINE))
                except re.error:
                    continue
        return patterns

    def walk_files(self) -> list[pathlib.Path]:
        paths: list[pathlib.Path] = []
        for path in self.root.rglob("*"):
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            if path.is_file():
                paths.append(path)
        return paths

    def read_text(self, path: pathlib.Path) -> str | None:
        try:
            data = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            return None
        if len(data) > 512_000:
            return None
        return data

    def add_finding(
        self,
        *,
        rule_id: str,
        title: str,
        severity: str,
        category: str,
        file: pathlib.Path,
        line: int,
        evidence: str,
        description: str,
        fix: str,
        guard_id: str,
        runtime_effect: str,
    ) -> None:
        rel = str(file.relative_to(self.root))
        if any(
            existing.rule_id == rule_id and existing.file == rel and existing.line == line
            for existing in self.findings
        ):
            return
        self.findings.append(
            Finding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                category=category,
                file=rel,
                line=line,
                evidence=evidence[:160],
                description=description,
                fix=fix,
                guard_id=guard_id,
                runtime_effect=runtime_effect,
            )
        )

    def line_number(self, text: str, index: int) -> int:
        return text.count("\n", 0, index) + 1

    def audit_file(self, path: pathlib.Path, text: str) -> None:
        lower_name = path.name.lower()
        rel = str(path.relative_to(self.root))

        for pattern in self.secret_patterns:
            match = pattern.search(text)
            if match and any(token in rel.lower() for token in ("claude", "mcp", "agent", "plugin", "skill", "config", "json", "toml", "md", "yaml", "yml", "env")):
                self.add_finding(
                    rule_id="hardcoded-secret",
                    title="Hardcoded secret material in agent/runtime config",
                    severity="critical",
                    category="secrets",
                    file=path,
                    line=self.line_number(text, match.start()),
                    evidence=match.group(0),
                    description="Secrets in runtime config, prompts, or manifests are immediately reusable by compromised tools or malicious plugins.",
                    fix="Move the value to an environment variable or secret manager reference.",
                    guard_id="mcp-response-secret-leak-guard",
                    runtime_effect="Runwall will redact secret-like tool output and block some exfil paths, but config secrets should be removed entirely.",
                )
                break

        if lower_name in {"settings.json", "settings.local.json", ".mcp.json", "config.toml"} or path.suffix in {".json", ".toml"}:
            wildcard_match = re.search(r"(Bash|Write|Edit|MultiEdit|Read)\(\*\)", text)
            if wildcard_match:
                self.add_finding(
                    rule_id="wildcard-permission",
                    title="Overly permissive wildcard tool rule",
                    severity="high",
                    category="permissions",
                    file=path,
                    line=self.line_number(text, wildcard_match.start()),
                    evidence=wildcard_match.group(0),
                    description="Wildcard tool permissions make prompt injection or tool misuse much easier to turn into host impact.",
                    fix="Replace wildcard rules with scoped commands or narrower file patterns.",
                    guard_id="tool-capability-escalation-guard",
                    runtime_effect="Runwall can block some dangerous combinations at runtime, but static wildcard permissions should still be reduced.",
                )

            auto_approve = re.search(r'"autoApprove"\s*:\s*true|autoApprove\s*=\s*true', text)
            if auto_approve:
                self.add_finding(
                    rule_id="auto-approve-enabled",
                    title="Auto-approve tool execution enabled",
                    severity="high",
                    category="mcp",
                    file=path,
                    line=self.line_number(text, auto_approve.start()),
                    evidence=auto_approve.group(0),
                    description="Auto-approval removes the human checkpoint for risky tool calls and MCP operations.",
                    fix="Disable auto-approve for mutable, shell, network, or secret-touching tools.",
                    guard_id="mcp-permission-guard",
                    runtime_effect="Runwall can prompt or block suspicious requests, but disabling blanket auto-approval improves the baseline immediately.",
                )

            for pattern in self.mcp_source_patterns:
                match = pattern.search(text)
                if match and ("server" in lower_name or "mcp" in rel.lower()):
                    self.add_finding(
                        rule_id="risky-mcp-source",
                        title="Risky MCP source or sideload path",
                        severity="high",
                        category="mcp",
                        file=path,
                        line=self.line_number(text, match.start()),
                        evidence=match.group(0),
                        description="Temporary paths, raw URLs, sideloaded archives, and download directories are common supply-chain footholds for malicious MCP servers and plugins.",
                        fix="Pin reviewed local binaries or trusted package sources instead of temporary or raw download paths.",
                        guard_id="mcp-upstream-swap-guard",
                        runtime_effect="Runwall can suppress risky upstreams at runtime, but removing the source drift eliminates the exposure.",
                    )
                    break

        if "/hooks/" in rel or lower_name.endswith(".sh") or "hook" in lower_name:
            danger = re.search(r"(curl|wget|iwr|Invoke-WebRequest).*(\||&&|;).*(bash|sh|pwsh|powershell|zsh)|\|\|\s*true|2>/dev/null", text, re.IGNORECASE)
            if danger:
                self.add_finding(
                    rule_id="dangerous-hook-chain",
                    title="Hook contains dangerous execution or silent-failure chain",
                    severity="high",
                    category="hooks",
                    file=path,
                    line=self.line_number(text, danger.start()),
                    evidence=danger.group(0),
                    description="Downloaded execution chains and silent-failure patterns are both common ways to hide malicious hook behavior or bypass failures.",
                    fix="Remove fetch-and-exec chains and make hook failures visible instead of suppressing them.",
                    guard_id="plugin-exec-chain-guard",
                    runtime_effect="Runwall blocks many of these chains during execution, but hooks should not ship with them at all.",
                )

        if lower_name in {"claude.md", "agents.md", "skill.md"} or path.suffix == ".md":
            for pattern in self.prompt_patterns:
                match = pattern.search(text)
                if match and any(token in rel.lower() for token in ("claude", "agent", "skill", "prompt", "instruction")):
                    self.add_finding(
                        rule_id="instruction-prompt-smuggling",
                        title="Prompt-injection or instruction-override text in agent instructions",
                        severity="medium",
                        category="agents",
                        file=path,
                        line=self.line_number(text, match.start()),
                        evidence=match.group(0),
                        description="Instruction files are a high-trust surface. Hidden override text can survive code review and hijack later runtime behavior.",
                        fix="Strip override or jailbreak phrasing from trusted instruction files and keep agent instructions narrowly scoped.",
                        guard_id="instruction-override-bridge-guard",
                        runtime_effect="Runwall detects and suppresses many instruction-override bridges at runtime, but trusted docs should remain clean.",
                    )
                    break

        if "plugin" in rel.lower() and path.suffix in {".json", ".toml", ".md"}:
            source_swap = re.search(r"(updateUrl|downloadUrl|archiveUrl|latest)", text, re.IGNORECASE)
            if source_swap:
                self.add_finding(
                    rule_id="plugin-source-drift",
                    title="Plugin update or download source override present",
                    severity="medium",
                    category="hooks",
                    file=path,
                    line=self.line_number(text, source_swap.start()),
                    evidence=source_swap.group(0),
                    description="Plugin update indirection is a practical supply-chain pivot for malicious or swapped distributions.",
                    fix="Pin plugin provenance and avoid runtime update URLs unless they are strongly reviewed.",
                    guard_id="plugin-update-source-swap-guard",
                    runtime_effect="Runwall can flag plugin source drift at runtime and install time, but static review should still lock provenance.",
                )

    def scan(self) -> None:
        for path in self.walk_files():
            text = self.read_text(path)
            if text is None:
                continue
            self.audit_file(path, text)

    def category_scores(self) -> dict[str, int]:
        penalties = {category: 0 for category in CATEGORY_LABELS}
        for finding in self.findings:
            penalties[finding.category] += SEVERITY_WEIGHTS[finding.severity]
        scores = {}
        for category in CATEGORY_LABELS:
            scores[category] = max(0, 20 - penalties[category])
        return scores

    def overall_score(self) -> int:
        return sum(self.category_scores().values())

    def grade(self) -> str:
        score = self.overall_score()
        for threshold, grade in GRADE_BANDS:
            if score >= threshold:
                return grade
        return "F"

    def summary(self) -> dict[str, Any]:
        scores = self.category_scores()
        counts = {level: 0 for level in SEVERITY_WEIGHTS}
        for finding in self.findings:
            counts[finding.severity] += 1
        return {
            "path": str(self.root),
            "profile": self.profile,
            "score": self.overall_score(),
            "grade": self.grade(),
            "filesScanned": len(self.walk_files()),
            "findings": [finding.to_dict() for finding in self.findings],
            "counts": counts,
            "scoreBreakdown": {
                category: {"label": CATEGORY_LABELS[category], "score": value}
                for category, value in scores.items()
            },
        }


def render_text(report: dict[str, Any]) -> str:
    lines = [
        "Runwall Audit Report",
        "",
        f"Grade: {report['grade']} ({report['score']}/100)",
        "",
        "Score Breakdown",
    ]
    for item in report["scoreBreakdown"].values():
        bar = "█" * item["score"] + "░" * (20 - item["score"])
        lines.append(f"{item['label']:<12} {bar} {item['score']}")
    lines.extend(["", "Findings"])
    if not report["findings"]:
        lines.append("No findings.")
    else:
        for finding in report["findings"]:
            lines.append(
                f"- {finding['severity'].upper():8} {finding['title']} "
                f"({finding['file']}:{finding['line']})"
            )
            lines.append(f"  Evidence: {finding['evidence']}")
            lines.append(f"  Guard: {finding['guardId']}")
            lines.append(f"  Fix: {finding['fix']}")
    return "\n".join(lines) + "\n"


def render_html(report: dict[str, Any]) -> str:
    items = []
    for finding in report["findings"]:
        items.append(
            "<article class='finding'>"
            f"<div class='sev sev-{html.escape(finding['severity'])}'>{html.escape(finding['severity'].upper())}</div>"
            f"<h3>{html.escape(finding['title'])}</h3>"
            f"<p><strong>{html.escape(finding['file'])}:{finding['line']}</strong></p>"
            f"<p>{html.escape(finding['description'])}</p>"
            f"<pre>{html.escape(finding['evidence'])}</pre>"
            f"<p><strong>Runtime guard:</strong> {html.escape(finding['guardId'])}</p>"
            f"<p><strong>Fix:</strong> {html.escape(finding['fix'])}</p>"
            "</article>"
        )
    breakdown = "".join(
        f"<li><span>{html.escape(item['label'])}</span><strong>{item['score']}/20</strong></li>"
        for item in report["scoreBreakdown"].values()
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Runwall Audit Report</title>
  <style>
    :root {{ --bg:#0c1117; --panel:#121923; --text:#f5f7fb; --muted:#98a5b3; --line:#263243; --accent:#6ae3b9; --warn:#ffb85c; --crit:#ff6a6a; }}
    body {{ margin:0; font-family: ui-sans-serif, system-ui, sans-serif; background: radial-gradient(circle at top, #152130, var(--bg)); color:var(--text); }}
    main {{ max-width: 1100px; margin: 0 auto; padding: 40px 24px 72px; }}
    .hero {{ display:grid; grid-template-columns: 1.4fr 1fr; gap:24px; margin-bottom: 28px; }}
    .card {{ background: rgba(18,25,35,.88); border:1px solid var(--line); border-radius: 22px; padding: 24px; box-shadow: 0 24px 64px rgba(0,0,0,.25); }}
    h1,h2,h3 {{ margin:0 0 12px; }}
    .grade {{ font-size: 64px; font-weight: 800; color: var(--accent); }}
    .sub {{ color: var(--muted); }}
    ul {{ list-style:none; padding:0; margin:0; display:grid; gap:10px; }}
    li {{ display:flex; justify-content:space-between; border-bottom:1px solid rgba(255,255,255,.06); padding-bottom:10px; }}
    .finding {{ display:grid; gap:10px; background: rgba(255,255,255,.02); border:1px solid rgba(255,255,255,.06); border-radius:16px; padding:20px; margin-top:16px; }}
    .sev {{ width:max-content; padding:4px 10px; border-radius:999px; font-size:12px; font-weight:700; letter-spacing:.08em; }}
    .sev-critical,.sev-high {{ background: rgba(255,106,106,.16); color:#ffc1c1; }}
    .sev-medium {{ background: rgba(255,184,92,.16); color:#ffd4a3; }}
    .sev-low,.sev-info {{ background: rgba(106,227,185,.16); color:#b8ffe7; }}
    pre {{ white-space: pre-wrap; margin:0; background:#0b1118; border:1px solid rgba(255,255,255,.06); border-radius:12px; padding:12px; color:#dce6f2; }}
    @media (max-width: 800px) {{ .hero {{ grid-template-columns: 1fr; }} }}
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <div class="card">
        <p class="sub">Runwall audit bridges static findings back into runtime guardrails.</p>
        <h1>Runwall Audit Report</h1>
        <div class="grade">{report['grade']}</div>
        <p class="sub">Score {report['score']}/100 • Path {html.escape(report['path'])}</p>
      </div>
      <div class="card">
        <h2>Score Breakdown</h2>
        <ul>{breakdown}</ul>
      </div>
    </section>
    <section class="card">
      <h2>Findings</h2>
      {''.join(items) if items else '<p class="sub">No findings.</p>'}
    </section>
  </main>
</body>
</html>
"""


def render_sarif(report: dict[str, Any]) -> str:
    rules = []
    seen = set()
    results = []
    for finding in report["findings"]:
        if finding["id"] not in seen:
            rules.append(
                {
                    "id": finding["id"],
                    "name": finding["title"],
                    "shortDescription": {"text": finding["title"]},
                    "fullDescription": {"text": finding["description"]},
                    "properties": {"category": finding["category"], "guardId": finding["guardId"]},
                }
            )
            seen.add(finding["id"])
        results.append(
            {
                "ruleId": finding["id"],
                "level": "error" if finding["severity"] in {"critical", "high"} else "warning",
                "message": {"text": f"{finding['title']} — {finding['fix']}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding["file"]},
                            "region": {"startLine": finding["line"]},
                        }
                    }
                ],
            }
        )
    payload = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "Runwall Audit", "rules": rules}},
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2) + "\n"


def write_output(path: pathlib.Path | None, content: str) -> None:
    if path is None:
        sys.stdout.write(content)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def run_audit(args: argparse.Namespace) -> int:
    root = pathlib.Path(args.path).expanduser().resolve()
    engine = AuditEngine(root, args.profile)
    engine.scan()
    report = engine.summary()

    if args.format == "json":
        content = json.dumps(report, indent=2) + "\n"
    elif args.format == "html":
        content = render_html(report)
    elif args.format == "sarif":
        content = render_sarif(report)
    else:
        content = render_text(report)

    write_output(pathlib.Path(args.output).resolve() if args.output else None, content)

    if args.fail_on:
        minimum = FAIL_ON_RANK[args.fail_on]
        if any(FAIL_ON_RANK[finding["severity"]] >= minimum for finding in report["findings"]):
            return 2
    return 0


def run_init(args: argparse.Namespace) -> int:
    root = pathlib.Path(args.path).expanduser().resolve()
    runwall_dir = root / ".runwall"
    runwall_dir.mkdir(parents=True, exist_ok=True)
    (runwall_dir / "audit-baseline.json").write_text(
        json.dumps(
            {
                "profile": args.profile,
                "recommendedCommands": [
                    "./bin/runwall audit . --format html --output runwall-audit.html",
                    "./bin/runwall audit . --format sarif --output runwall-audit.sarif",
                    "./bin/runwall install strict",
                ],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    workflow = root / ".github" / "workflows" / "runwall-audit.yml"
    workflow.parent.mkdir(parents=True, exist_ok=True)
    if not workflow.exists() or args.force:
        workflow.write_text(RUNWALL_AUDIT_WORKFLOW, encoding="utf-8")
    sys.stdout.write(f"Runwall baseline created in {runwall_dir}\n")
    sys.stdout.write(f"Workflow ready at {workflow}\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Runwall audit and baseline utilities")
    sub = parser.add_subparsers(dest="command", required=True)

    audit = sub.add_parser("audit")
    audit.add_argument("path", nargs="?", default=".")
    audit.add_argument("--profile", default="strict")
    audit.add_argument("--format", choices=("text", "json", "html", "sarif"), default="text")
    audit.add_argument("--output")
    audit.add_argument("--fail-on", choices=("critical", "high", "medium", "low", "info"))
    audit.set_defaults(func=run_audit)

    init = sub.add_parser("init")
    init.add_argument("path", nargs="?", default=".")
    init.add_argument("--profile", default="strict")
    init.add_argument("--force", action="store_true")
    init.set_defaults(func=run_init)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
