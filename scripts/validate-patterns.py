#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import re
import subprocess
import sys
import warnings


PYTHON_ONLY = {
    "prompt-injection-context.regex",
    "prompt-injection-obfuscation.regex",
    "prompt-injection-override.regex",
    "prompt-injection-roleplay.regex",
    "prompt-injection-smuggling.regex",
}


def fail(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def validate_python_patterns(path: pathlib.Path) -> int:
    count = 0
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            try:
                re.compile(line, re.IGNORECASE | re.MULTILINE)
            except re.error as exc:
                fail(f"{path.name}:{lineno}: invalid Python regex: {exc}")
            for warning in caught:
                fail(f"{path.name}:{lineno}: regex warning: {warning.message}")
        count += 1
    return count


def validate_ere_patterns(path: pathlib.Path) -> int:
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "(?i)" in line:
            fail(f"{path.name}:{lineno}: non-portable ERE flag '(?i)' is not allowed; use grep -i and a portable pattern")
        if r"\b" in line:
            fail(f"{path.name}:{lineno}: non-portable ERE boundary '\\b' is not allowed; use explicit character boundaries")

    result = subprocess.run(
        ["grep", "-E", "-f", str(path), "/dev/null"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode == 2:
        fail(f"{path.name}: invalid ERE pattern file: {result.stderr.strip()}")

    count = 0
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        count += 1
    return count


def main() -> None:
    config_dir = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path("config")
    if not config_dir.is_dir():
        fail(f"config dir not found: {config_dir}")

    files = sorted(config_dir.glob("*.regex"))
    if not files:
        fail(f"no regex files found in {config_dir}")

    file_count = 0
    pattern_count = 0
    for path in files:
        if path.name in PYTHON_ONLY:
            pattern_count += validate_python_patterns(path)
        else:
            pattern_count += validate_ere_patterns(path)
        file_count += 1

    print(f"validated {pattern_count} patterns across {file_count} regex files")


if __name__ == "__main__":
    main()
