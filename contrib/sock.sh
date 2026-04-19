#!/usr/bin/env bash
#
# sock.sh [Query per-interface daemon status API socket]
#
set -euo pipefail

INTF="${1:-eth0}"
ENDPOINT="${2:-/config}"
STATUS_SOCK="/run/pesigitg/status-$INTF.sock"
JQ=$(command -v jq)

exec echo "GET $ENDPOINT" | sudo socat - UNIX-CONNECT:$STATUS_SOCK | $JQ
