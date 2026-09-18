#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v swiftc >/dev/null 2>&1; then
  echo "swiftc not found; run on macOS"
  exit 2
fi

swiftc -o /tmp/wfs_unicorn_smoke WFSSwiftUnicorn.swift Tests/test_unicorn_smoke.swift

LIB=""
if [[ -n "${WFS_UNICORN_LIB:-}" ]]; then
  LIB="$WFS_UNICORN_LIB"
elif command -v brew >/dev/null 2>&1; then
  candidate="$(brew --prefix unicorn 2>/dev/null)/lib/libunicorn.2.dylib"
  [[ -e "$candidate" ]] && LIB="$candidate"
fi

if [[ -z "$LIB" ]]; then
  echo "libunicorn not found; smoke test compiled but skipped runtime"
  echo "install with: brew install unicorn"
  exit 0
fi

echo "Using libunicorn: $LIB"
WFS_UNICORN_LIB="$LIB" /tmp/wfs_unicorn_smoke