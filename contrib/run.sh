#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD="${1:-release}"
DEV="${2:-eth0}"

export RUST_LOG="${RUST_LOG:-pesigitgd=info}"

ARGS=(run -f -c "$ROOT/contrib/$DEV.conf")

if [ "$BUILD" = "release" ]; then
    ARGS=(run --release -f -c "$ROOT/contrib/$DEV.conf")
fi

exec sudo -E cargo xtask "${ARGS[@]}"
