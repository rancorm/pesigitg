#!/usr/bin/env bash
#
# restart-drop.sh [Measure connection drops across a handoff restart]
#
# Usage: restart-drop.sh [-i INTF] [-s SOCKET] [-t TARGET] [-n COUNT] [-v]
#   -i, --interface INTF Interface name (default: eth0)
#   -s, --socket PATH    Status socket (default: /run/pesigitg/status-INTF.sock)
#   -t, --target HOST:P  Target for quic-echo-client (default: 127.0.0.1:443)
#   -n, --count N        Total connections to attempt (default: 200)
#   -c, --client PATH    quic-echo-client binary (default: target/release/quic-echo-client)
#   -v, --verbose        Print per-connection outcome
#
# Drives N sequential QUIC connections via quic-echo-client. At the midpoint,
# sends SIGUSR2 to the running daemon to trigger a handoff restart, waits for
# the new daemon to become ready, then continues. Reports pass/fail counts
# and restart duration. The per-connection pass/fail ratio during the window
# approximates drop rate attributable to restart.
#
# Prerequisites:
#   - pesigitgd already running (systemd or contrib/run.sh).
#   - The unit / run loop must respawn the daemon after clean exit
#     (SIGUSR2 exits cleanly). For systemd: `Restart=always`.
#   - Status API enabled (status_socket= in daemon config).
#   - A backend reachable through the daemon.
#   - quic-echo-client built (`cargo build --release -p quic-echo`).
#
# Exit codes:
#   0 — completed, see reported results for pass/fail ratio
#   1 — daemon did not become ready after restart within timeout
#   2 — bad arguments / missing prerequisites
#
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Pesigitg

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

INTF="eth0"
SOCKET=""
TARGET="127.0.0.1:443"
COUNT=200
CLIENT="$ROOT/target/release/quic-echo-client"
VERBOSE=0
READY_TIMEOUT=10

usage() {
    sed -n '2,30p' "$0" | sed 's/^# \?//'
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -i|--interface) INTF="$2"; shift 2 ;;
        -s|--socket)    SOCKET="$2"; shift 2 ;;
        -t|--target)    TARGET="$2"; shift 2 ;;
        -n|--count)     COUNT="$2"; shift 2 ;;
        -c|--client)    CLIENT="$2"; shift 2 ;;
        -v|--verbose)   VERBOSE=1; shift ;;
        -h|--help)      usage; exit 0 ;;
        *)              echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

[[ -z "$SOCKET" ]] && SOCKET="/run/pesigitg/status-$INTF.sock"

for tool in nc timeout sudo awk; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "Error: '$tool' not found in PATH" >&2
        exit 2
    }
done

[[ -S "$SOCKET" ]] || {
    echo "Error: $SOCKET is not a socket (is pesigitgd running?)" >&2
    exit 2
}

[[ -x "$CLIENT" ]] || {
    echo "Error: $CLIENT not executable — build it with 'cargo build --release -p quic-echo'" >&2
    exit 2
}

PIDFILE="/var/run/pesigitgd-$INTF.pid"
[[ -r "$PIDFILE" ]] || {
    echo "Error: $PIDFILE not readable — run as root or check daemon config" >&2
    exit 2
}

wait_for_ready() {
    local deadline=$(( $(date +%s) + READY_TIMEOUT ))
    while (( $(date +%s) < deadline )); do
        if printf 'GET /health\n' | timeout 1 nc -U "$SOCKET" 2>/dev/null | grep -q '"status":"ok"'; then
            return 0
        fi
        sleep 0.2
    done
    return 1
}

run_one() {
    # Single connection attempt; returns 0 on success, 1 on failure.
    timeout 3 "$CLIENT" --connect "$TARGET" --count 1 --message "probe" \
        >/dev/null 2>&1
}

pass=0
fail=0
fail_in_restart_window=0
restart_elapsed=""

echo "Waiting for daemon readiness..."
wait_for_ready || { echo "Daemon not ready at start" >&2; exit 1; }

midpoint=$(( COUNT / 2 ))
restart_window_start=0
restart_window_end=0

echo "Driving $COUNT connections; handoff at #$midpoint..."

for i in $(seq 1 $COUNT); do
    if run_one; then
        pass=$((pass+1))
        [[ $VERBOSE -eq 1 ]] && echo "  $i: ok"
    else
        fail=$((fail+1))
        [[ $VERBOSE -eq 1 ]] && echo "  $i: FAIL"
        (( i >= restart_window_start && i <= restart_window_end )) && \
            fail_in_restart_window=$((fail_in_restart_window+1))
    fi

    if [[ $i -eq $midpoint ]]; then
        PID=$(cat "$PIDFILE")
        echo "Midpoint reached. Sending SIGUSR2 to pid $PID..."
        restart_start=$(date +%s%N)
        restart_window_start=$i
        sudo kill -USR2 "$PID"

        # Wait for daemon to exit.
        exit_deadline=$(( $(date +%s) + 10 ))
        while kill -0 "$PID" 2>/dev/null; do
            sleep 0.1
            (( $(date +%s) < exit_deadline )) || {
                echo "Daemon did not exit after SIGUSR2" >&2
                exit 1
            }
        done

        # Wait for respawned daemon to become ready (unit/wrapper must respawn).
        wait_for_ready || {
            echo "Daemon did not become ready after handoff" >&2
            exit 1
        }
        restart_end=$(date +%s%N)
        restart_elapsed=$(awk "BEGIN { printf \"%.3f\", ($restart_end - $restart_start) / 1e9 }")
        restart_window_end=$(( i + 5 ))  # Count failures within 5 attempts post-restart.
        echo "Daemon back in ${restart_elapsed}s"
    fi
done

echo
echo "Results:"
echo "  Total connections:                       $COUNT"
echo "  Succeeded:                               $pass"
echo "  Failed:                                  $fail"
echo "  Failures in restart window (±5 attempts): $fail_in_restart_window"
echo "  Restart duration:                        ${restart_elapsed}s"
echo "  Failure rate:                            $(awk "BEGIN { printf \"%.2f%%\", $fail * 100 / $COUNT }")"
