#!/usr/bin/env bash
#
# restart-drop.sh [Two-host measurement harness for handoff-restart drop rate]
#
# Runs in one of two roles:
#
#   restart-drop.sh client [-t TARGET] [-n COUNT] [-c PATH] [-v]
#     -t, --target HOST:P   LB endpoint (default: 127.0.0.1:443)
#     -n, --count N         Total connections to attempt (default: 200)
#     -c, --client PATH     quic-echo-client binary
#                           (default: target/release/quic-echo-client)
#     -v, --verbose         Print per-connection outcome
#
#   restart-drop.sh lb [-i INTF] [-s SOCKET]
#     -i, --interface INTF  Interface name (default: eth0)
#     -s, --socket PATH     Status socket
#                           (default: /run/pesigitg/status-INTF.sock)
#
# Typical flow:
#   1. On client host: ./restart-drop.sh client -t <lb>:443 -n 200
#      Press enter when ready; traffic begins.
#   2. At the midpoint the client pauses and prints instructions.
#   3. On LB host: ./restart-drop.sh lb -i enp2s0f0
#      Signals SIGUSR2, waits for the daemon to respawn ready, reports
#      restart duration, exits.
#   4. Back on client, press enter. Traffic resumes. Final report prints.
#
# The LB must respawn pesigitgd after SIGUSR2 clean exit (systemd with
# Restart=always, or a shell respawn loop). Otherwise the `lb` role will
# time out waiting for readiness.
#
# Exit codes:
#   0 — completed
#   1 — daemon not ready or did not respawn in time (lb role)
#   2 — bad arguments / missing prerequisites
#
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Jonathan Cormier
# This file is part of Pesigitg.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

READY_TIMEOUT=10
EXIT_TIMEOUT=10

usage() {
    sed -n '2,39p' "$0" | sed 's/^# \?//'
}

wait_for_ready() {
    local socket="$1"
    local deadline=$(( $(date +%s) + READY_TIMEOUT ))
    while (( $(date +%s) < deadline )); do
        if printf 'GET /health\n' | timeout 1 nc -U "$socket" 2>/dev/null | grep -q '"status":"ok"'; then
            return 0
        fi
        sleep 0.2
    done
    return 1
}

# ---------- client role ----------

client_mode() {
    local target="127.0.0.1:443"
    local count=200
    local client="$ROOT/target/release/quic-echo-client"
    local verbose=0

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -t|--target)  target="$2"; shift 2 ;;
            -n|--count)   count="$2"; shift 2 ;;
            -c|--client)  client="$2"; shift 2 ;;
            -v|--verbose) verbose=1; shift ;;
            -h|--help)    usage; exit 0 ;;
            *) echo "Unknown option: $1" >&2; exit 2 ;;
        esac
    done

    for tool in timeout awk; do
        command -v "$tool" >/dev/null 2>&1 || {
            echo "Error: '$tool' not found in PATH" >&2
            exit 2
        }
    done

    [[ -x "$client" ]] || {
        echo "Error: $client not executable — build with 'cargo build --release -p quic-echo'" >&2
        exit 2
    }

    local midpoint=$(( count / 2 ))

    cat <<EOF
client role
  target:    $target
  count:     $count
  client:    $client
  midpoint:  $midpoint (pause for manual LB handoff here)

Press enter to begin traffic...
EOF
    read -r

    local pre_pass=0 pre_fail=0 post_pass=0 post_fail=0
    local post_window_fail=0 post_window_size=5

    for i in $(seq 1 "$count"); do
        local phase="pre"
        (( i > midpoint )) && phase="post"

        if timeout 3 "$client" --connect "$target" --count 1 --message "probe-$i" >/dev/null 2>&1; then
            if [[ $phase == "pre" ]]; then
                pre_pass=$((pre_pass + 1))
            else
                post_pass=$((post_pass + 1))
            fi
            [[ $verbose -eq 1 ]] && echo "  $i [$phase]: ok"
        else
            if [[ $phase == "pre" ]]; then
                pre_fail=$((pre_fail + 1))
            else
                post_fail=$((post_fail + 1))
                local window_idx=$(( i - midpoint ))
                (( window_idx <= post_window_size )) && \
                    post_window_fail=$((post_window_fail + 1))
            fi
            [[ $verbose -eq 1 ]] && echo "  $i [$phase]: FAIL"
        fi

        if [[ $i -eq $midpoint ]]; then
            cat <<EOF

-------- midpoint reached ($midpoint/$count) --------

Run the LB side now, in a separate terminal on the load-balancer host:

    $(basename "$0") lb

When that completes (or the daemon is healthy again), press enter here
to resume traffic.

EOF
            read -r
            echo "Resuming traffic..."
        fi
    done

    local total=$count
    local fail=$(( pre_fail + post_fail ))
    local total_pass=$(( pre_pass + post_pass ))

    echo
    echo "Results:"
    printf '  total connections:                   %d\n' "$total"
    printf '  pre-handoff  pass/fail:              %d / %d\n' "$pre_pass" "$pre_fail"
    printf '  post-handoff pass/fail:              %d / %d\n' "$post_pass" "$post_fail"
    printf '  failures in first %d post-handoff:    %d\n' "$post_window_size" "$post_window_fail"
    printf '  overall pass/fail:                   %d / %d\n' "$total_pass" "$fail"
    printf '  overall failure rate:                %s\n' \
        "$(awk "BEGIN { printf \"%.2f%%\", $fail * 100 / $total }")"
    printf '  post-handoff failure rate:           %s\n' \
        "$(awk "BEGIN { printf \"%.2f%%\", $post_fail * 100 / ($total - $midpoint) }")"
}

# ---------- lb role ----------

lb_mode() {
    local intf="eth0"
    local socket=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -i|--interface) intf="$2"; shift 2 ;;
            -s|--socket)    socket="$2"; shift 2 ;;
            -h|--help)      usage; exit 0 ;;
            *) echo "Unknown option: $1" >&2; exit 2 ;;
        esac
    done

    [[ -z "$socket" ]] && socket="/run/pesigitg/status-$intf.sock"

    for tool in nc timeout sudo awk; do
        command -v "$tool" >/dev/null 2>&1 || {
            echo "Error: '$tool' not found in PATH" >&2
            exit 2
        }
    done

    [[ -S "$socket" ]] || {
        echo "Error: $socket is not a socket (is pesigitgd running?)" >&2
        exit 2
    }

    local pidfile="/var/run/pesigitgd-$intf.pid"
    [[ -r "$pidfile" ]] || {
        echo "Error: $pidfile not readable — run as root or check daemon config" >&2
        exit 2
    }

    local pid
    pid=$(cat "$pidfile")

    echo "LB role"
    echo "  interface:  $intf"
    echo "  socket:     $socket"
    echo "  pidfile:    $pidfile (pid $pid)"
    echo
    echo "Verifying daemon is ready before handoff..."
    wait_for_ready "$socket" || {
        echo "Daemon not ready before handoff" >&2
        exit 1
    }

    echo "Sending SIGUSR2 to pid $pid..."
    local restart_start restart_end
    restart_start=$(date +%s%N)
    sudo kill -USR2 "$pid"

    local exit_deadline=$(( $(date +%s) + EXIT_TIMEOUT ))
    while kill -0 "$pid" 2>/dev/null; do
        sleep 0.1
        (( $(date +%s) < exit_deadline )) || {
            echo "Daemon did not exit after SIGUSR2 within ${EXIT_TIMEOUT}s" >&2
            exit 1
        }
    done
    local exited_at
    exited_at=$(date +%s%N)

    echo "Daemon exited; waiting for respawn (Restart=always / run loop)..."
    wait_for_ready "$socket" || {
        echo "Daemon did not become ready after handoff within ${READY_TIMEOUT}s" >&2
        exit 1
    }
    restart_end=$(date +%s%N)

    local total_ms exit_ms respawn_ms
    total_ms=$(awk "BEGIN { printf \"%.1f\", ($restart_end - $restart_start) / 1e6 }")
    exit_ms=$(awk "BEGIN { printf \"%.1f\", ($exited_at - $restart_start) / 1e6 }")
    respawn_ms=$(awk "BEGIN { printf \"%.1f\", ($restart_end - $exited_at) / 1e6 }")

    echo
    echo "Handoff complete:"
    printf '  time-to-exit:    %s ms\n' "$exit_ms"
    printf '  time-to-ready:   %s ms (after exit)\n' "$respawn_ms"
    printf '  total:           %s ms (SIGUSR2 -> new daemon ready)\n' "$total_ms"
}

# ---------- dispatch ----------

ROLE="${1:-}"
shift || true

case "$ROLE" in
    client) client_mode "$@" ;;
    lb)     lb_mode "$@" ;;
    -h|--help|'') usage; exit 0 ;;
    *) echo "Unknown role: $ROLE (expected 'client' or 'lb')" >&2; exit 2 ;;
esac
