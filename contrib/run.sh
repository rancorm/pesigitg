#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

export RUST_LOG="${RUST_LOG:-pesigitgd=info}"

exec sudo -E cargo xtask run --release \
    -f \
    -c "$ROOT/contrib/pesigitgd.conf" \
    --route-config "$ROOT/contrib/lb.toml" \
    "$@"
