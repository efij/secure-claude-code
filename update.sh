#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "${1:-}" = "" ]; then
  exec "$ROOT_DIR/bin/stallion" update
else
  exec "$ROOT_DIR/bin/stallion" update "$1"
fi
