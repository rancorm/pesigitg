#!/usr/bin/env bash
#
# hup.sh [Send HUP signal to per-interface daemon process]
#
set -euo pipefail

INTF=${1:-eth0}
TARGET_PID=$(cat /run/pesigitgd-$INTF.pid)

exec sudo kill -HUP "$TARGET_PID"
