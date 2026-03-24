#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${2:-$(cat "$ROOT_DIR/VERSION")}"
REPO="${1:-}"
DIST_DIR="$ROOT_DIR/dist"
STAGE_DIR="$DIST_DIR/secure-claude-code-$VERSION"
PYTHON_BIN="${PYTHON_BIN:-}"

[ -n "$REPO" ] || {
  printf 'usage: scripts/package-release.sh <owner/repo> [version]\n' >&2
  exit 1
}

if [ -z "$PYTHON_BIN" ]; then
  if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python3)"
  elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python)"
  else
    printf 'error: python3 or python is required\n' >&2
    exit 1
  fi
fi

rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR" "$DIST_DIR"

rsync -a \
  --exclude '.git' \
  --exclude '.github' \
  --exclude '.codex' \
  --exclude '.claude' \
  --exclude '.cursor' \
  --exclude '.idea' \
  --exclude '.mcp' \
  --exclude '.mcp*' \
  --exclude '.vscode' \
  --exclude 'dist' \
  --exclude '.DS_Store' \
  --exclude 'state' \
  --exclude 'tmp' \
  "$ROOT_DIR"/ "$STAGE_DIR"/

(
  cd "$DIST_DIR"
  tar -czf "secure-claude-code-$VERSION.tar.gz" "secure-claude-code-$VERSION"
  rm -f "secure-claude-code-$VERSION.zip"
  zip -qr "secure-claude-code-$VERSION.zip" "secure-claude-code-$VERSION"
)

SHA256_TGZ="$(shasum -a 256 "$DIST_DIR/secure-claude-code-$VERSION.tar.gz" | awk '{print $1}')"
SHA256_ZIP="$(shasum -a 256 "$DIST_DIR/secure-claude-code-$VERSION.zip" | awk '{print $1}')"

"$PYTHON_BIN" - "$ROOT_DIR" "$REPO" "$VERSION" "$SHA256_TGZ" "$SHA256_ZIP" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
repo = sys.argv[2]
version = sys.argv[3]
sha_tgz = sys.argv[4]
sha_zip = sys.argv[5]

replacements = {
    "{{REPO}}": repo,
    "{{VERSION}}": version,
    "{{SHA256_TGZ}}": sha_tgz,
    "{{SHA256_ZIP}}": sha_zip,
}

targets = [
    (
        root / "packaging" / "homebrew" / "secure-claude-code.rb.tmpl",
        root / "dist" / "secure-claude-code.rb",
    ),
    (
        root / "packaging" / "scoop" / "secure-claude-code.json.tmpl",
        root / "dist" / "secure-claude-code.json",
    ),
]

for src, dest in targets:
    text = src.read_text()
    for old, new in replacements.items():
        text = text.replace(old, new)
    dest.write_text(text)
PY

cat >"$DIST_DIR/SHA256SUMS" <<EOF
$SHA256_TGZ  secure-claude-code-$VERSION.tar.gz
$SHA256_ZIP  secure-claude-code-$VERSION.zip
EOF

printf 'release assets created in %s\n' "$DIST_DIR"
