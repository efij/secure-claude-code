#!/usr/bin/env bash
set -euo pipefail

PROFILE="balanced"
REPO=""
REF="main"
VERSION=""
ARCHIVE_URL=""
ARCHIVE_FILE=""
KEEP_WORKDIR="false"
TMP_BASE=""

usage() {
  cat <<'EOF'
Usage:
  bootstrap.sh --repo owner/repo [--ref branch] [--profile profile]
  bootstrap.sh --repo owner/repo --version X.Y.Z [--profile profile]
  bootstrap.sh --archive-url https://.../secure-claude-code.tar.gz [--profile profile]
  bootstrap.sh --archive-file /path/to/secure-claude-code.tar.gz [--profile profile]
EOF
}

fail() {
  printf 'error: %s\n' "$1" >&2
  exit 1
}

cleanup() {
  if [ "${KEEP_WORKDIR:-false}" != "true" ] && [ -n "${TMP_BASE:-}" ] && [ -d "${TMP_BASE:-}" ]; then
    rm -rf "$TMP_BASE"
  fi
}

make_tempdir() {
  local base="${TMPDIR:-/tmp}"
  if tmpdir="$(mktemp -d 2>/dev/null)"; then
    printf '%s\n' "$tmpdir"
    return 0
  fi
  if tmpdir="$(mktemp -d -t secure-claude-code-bootstrap 2>/dev/null)"; then
    printf '%s\n' "$tmpdir"
    return 0
  fi
  if tmpdir="$(mktemp -d "$base/secure-claude-code-bootstrap.XXXXXX" 2>/dev/null)"; then
    printf '%s\n' "$tmpdir"
    return 0
  fi
  fail "could not create temporary directory"
}

download_file() {
  local url="${1:-}"
  local destination="${2:-}"

  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$destination"
    return 0
  fi

  if command -v wget >/dev/null 2>&1; then
    wget -qO "$destination" "$url"
    return 0
  fi

  fail "curl or wget is required"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --repo)
      shift
      [ "$#" -gt 0 ] || fail "missing value for --repo"
      REPO="$1"
      ;;
    --ref)
      shift
      [ "$#" -gt 0 ] || fail "missing value for --ref"
      REF="$1"
      ;;
    --version)
      shift
      [ "$#" -gt 0 ] || fail "missing value for --version"
      VERSION="$1"
      ;;
    --profile)
      shift
      [ "$#" -gt 0 ] || fail "missing value for --profile"
      PROFILE="$1"
      ;;
    --archive-url)
      shift
      [ "$#" -gt 0 ] || fail "missing value for --archive-url"
      ARCHIVE_URL="$1"
      ;;
    --archive-file)
      shift
      [ "$#" -gt 0 ] || fail "missing value for --archive-file"
      ARCHIVE_FILE="$1"
      ;;
    --keep-workdir)
      KEEP_WORKDIR="true"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown option: $1"
      ;;
  esac
  shift
done

if [ -n "$ARCHIVE_URL" ] && [ -n "$ARCHIVE_FILE" ]; then
  fail "use only one of --archive-url or --archive-file"
fi

if [ -z "$ARCHIVE_URL" ] && [ -z "$ARCHIVE_FILE" ]; then
  [ -n "$REPO" ] || fail "--repo is required unless --archive-url or --archive-file is used"
  if [ -n "$VERSION" ]; then
    ARCHIVE_URL="https://github.com/$REPO/releases/download/v$VERSION/secure-claude-code-$VERSION.tar.gz"
  else
    ARCHIVE_URL="https://github.com/$REPO/archive/refs/heads/$REF.tar.gz"
  fi
fi

command -v tar >/dev/null 2>&1 || fail "tar is required"

TMP_BASE="$(make_tempdir)"
trap cleanup EXIT

ARCHIVE_PATH="$TMP_BASE/archive.tar.gz"
EXTRACT_DIR="$TMP_BASE/extract"
mkdir -p "$EXTRACT_DIR"

if [ -n "$ARCHIVE_FILE" ]; then
  cp "$ARCHIVE_FILE" "$ARCHIVE_PATH"
else
  download_file "$ARCHIVE_URL" "$ARCHIVE_PATH"
fi

tar -xzf "$ARCHIVE_PATH" -C "$EXTRACT_DIR"

INSTALL_SCRIPT="$(find "$EXTRACT_DIR" -mindepth 1 -maxdepth 2 -type f -name install.sh -print -quit)"
[ -n "$INSTALL_SCRIPT" ] || fail "could not locate extracted install.sh"
SOURCE_DIR="$(dirname "$INSTALL_SCRIPT")"

printf 'Installing Secure Claude Code with profile %s\n' "$PROFILE"
bash "$SOURCE_DIR/install.sh" "$PROFILE"
