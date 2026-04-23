#!/usr/bin/env bash
#
# ok.sh [Probe per-interface pesigitgd /health endpoint and exit with status]
#
# Usage: ok.sh [-i INTF] [-s SOCKET] [-v]
#   -i, --interface INTF Interface of socket
#   -s, --socket PATH    Status socket (default: /run/pesigitg/status-eth0.sock)
#   -v, --verbose        Print the full JSON response
#
# Exit codes:
#   0 — status ok
#   1 — status is not "ok" (e.g. "degraded")
#   2 — socket missing / inaccessible / bad arguments
#   3 — no response from daemon
#   4 — missing required tool
#
# Requires: nc, timeout (coreutils). Requires read access to the socket
# (mode 0660 by default — run as root or add your user to its group).
#
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Jonathan Cormier
# This file is part of Pesigitg.

set -euo pipefail

INTF="eth0"
SOCKET="/run/pesigitg/status-$INTF.sock"
VERBOSE=0

usage() {
    sed -n '2,16p' "$0" | sed 's/^# \?//'
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -i|--interface)
			INTF="$2";
			SOCKET="/run/pesigitg/status-$INTF.sock";
			shift 2 ;;
        -s|--socket)  SOCKET="$2"; shift 2 ;;
        -v|--verbose) VERBOSE=1; shift ;;
        -h|--help)    usage; exit 0 ;;
        *)            echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

for tool in nc timeout; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "Error: '$tool' not found in PATH" >&2
        exit 4
    }
done

if [[ ! -S "$SOCKET" ]]; then
    echo "Error: $SOCKET is not a socket (is pesigitgd running?)" >&2
    exit 2
fi

RESPONSE="$(printf 'GET /health\n' | timeout 2 nc -U "$SOCKET" 2>/dev/null || true)"

if [[ -z "$RESPONSE" ]]; then
    echo "Error: no response from $SOCKET" >&2
    exit 3
fi

if [[ "$VERBOSE" -eq 1 ]]; then
    if command -v jq >/dev/null 2>&1; then
        echo "$RESPONSE" | jq .
    else
        echo "$RESPONSE"
    fi
fi

if [[ "$RESPONSE" == *'"status":"ok"'* ]]; then
    [[ "$VERBOSE" -eq 1 ]] || echo "ok"
    exit 0
fi

[[ "$VERBOSE" -eq 1 ]] || echo "$RESPONSE"
exit 1
