#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD="${1:-release}"
CONF_PATH="${2:-contrib/etc/enp2s0f0.conf}"

export RUST_LOG="${RUST_LOG:-pesigitgd=info}"

ARGS=(run -f -c "$CONF_PATH")

if [ "$BUILD" = "release" ]; then
    ARGS=(run --release -f -c "$CONF_PATH")
fi

exec sudo -E cargo xtask "${ARGS[@]}"
