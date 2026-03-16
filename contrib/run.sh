#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEV=${1:-eth0}

export RUST_LOG="${RUST_LOG:-pesigitgd=info}"

exec sudo -E cargo xtask run --release \
    -f \
    -c "$ROOT/contrib/$DEV.conf"
