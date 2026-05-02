#!/usr/bin/env bash
#
# restart-drop.sh [Two-host measurement harness for handoff-restart drop rate]
#
# Runs in one of three roles:
#
#   restart-drop.sh client [-t TARGET] [-n COUNT] [-c PATH] [-l PATH] [-v]
#                          [--max-post-fail N] [--max-overall-fail N]
#     -t, --target HOST:P   LB endpoint (default: 127.0.0.1:443)
#     -n, --count N         Total connections to attempt (default: 200)
#     -c, --client PATH     quic-echo-client binary
#                           (default: target/release/quic-echo-client)
#     -l, --log PATH        Per-attempt log (TSV)
#                           (default: /tmp/restart-drop-client.log)
#     -v, --verbose         Print per-connection outcome
#     --max-post-fail N     Fail (exit 3) if more than N of the first 5
#                           post-handoff connections fail. Phase-2 acceptance
#                           gate: cold-boot expects ~5; phase 1 a few; phase 2
#                           "near-zero", typical threshold N=0 or 1.
#     --max-overall-fail N  Fail (exit 3) if more than N total connections
#                           fail across the whole run.
#
#   restart-drop.sh lb [-i INTF] [-s SOCKET] [-o PREFIX]
#     -i, --interface INTF  Interface name (default: eth0)
#     -s, --socket PATH     Status socket
#                           (default: /run/pesigitg/status-INTF.sock)
#     -o, --out PREFIX      Prefix for pre/post stats snapshots
#                           (default: /tmp/restart-drop-lb)
#
#   restart-drop.sh snapshot [-s SOCKET] [-o PATH]
#     One-shot capture of /stats from the daemon's status socket — useful
#     for baseline runs where lb is not invoked. Defaults match the lb role.
#
# Typical flow:
#   1. On client host: ./restart-drop.sh client -t <lb>:443 -n 200
#      Press enter when ready; traffic begins.
#   2. At the midpoint the client pauses and prints instructions.
#   3. On LB host: ./restart-drop.sh lb -i enp2s0f0
#      Signals SIGUSR2, waits for the daemon to respawn ready, reports
#      restart duration, then pauses.
#   4. Back on client, press enter. Traffic resumes. Final report prints.
#   5. Back on LB, press enter to capture the post-handoff snapshot. The
#      script prints each phase's counters side-by-side (pre-handoff from
#      the old daemon, post-handoff from the freshly-restarted one) —
#      counters reset across SIGUSR2, so no meaningful delta is computed.
#
# Baseline diagnostic (no handoff):
#   On LB host, capture pre-test stats, let client run through, capture
#   post-test stats:
#     ./restart-drop.sh snapshot -i enp2s0f0 -o /tmp/pre.json
#     # (wait for client to finish)
#     ./restart-drop.sh snapshot -i enp2s0f0 -o /tmp/post.json
#   Then eyeball counter deltas (forwarded, cid_unroutable, retry_*).
#   Client pauses at midpoint; press enter both times to skip the handoff.
#
# The LB must respawn pesigitgd after SIGUSR2 clean exit (systemd with
# Restart=always, or a shell respawn loop). Otherwise the `lb` role will
# time out waiting for readiness.
#
# Exit codes:
#   0 — completed (and any assertions passed, when set)
#   1 — daemon not ready or did not respawn in time (lb role)
#   2 — bad arguments / missing prerequisites
#   3 — assertion failed (--max-post-fail or --max-overall-fail exceeded)
#
# SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
# Copyright (c) 2026 Jonathan Cormier
# This file is part of Pesigitg.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

READY_TIMEOUT=10
EXIT_TIMEOUT=10

usage() {
    awk 'NR==1{next} /^[^#]/{exit} {sub(/^# ?/,""); print}' "$0"
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

# Capture a one-shot /stats snapshot from the daemon's status socket.
# Writes JSON to $2; prints nothing on success, warns on failure (does
# not exit — the caller decides whether a missing snapshot is fatal).
snapshot_stats() {
    local socket="$1" out="$2"
    if ! printf 'GET /stats\n' | timeout 2 nc -U "$socket" >"$out" 2>/dev/null; then
        echo "Warning: failed to capture stats from $socket -> $out" >&2
        return 1
    fi
    [[ -s "$out" ]] || {
        echo "Warning: empty stats response from $socket" >&2
        return 1
    }
    return 0
}

# Print non-zero scalar counters from a /stats JSON file. jq is required
# for pretty output; without it we fall back to pointing at the raw file.
# Counters reset across SIGUSR2, so cross-restart subtraction is never
# meaningful — we print each snapshot's own non-zero values instead.
print_nonzero_stats() {
    local snap="$1"
    if command -v jq >/dev/null 2>&1; then
        jq -r '
            [paths(scalars) as $p
               | {key: ($p | map(tostring) | join(".")), value: (getpath($p))}]
            | map(select((.value | type) == "number" and .value != 0))
            | sort_by(-.value)
            | .[] | "  \(.key): \(.value)"
        ' "$snap"
    else
        echo "  (install jq for a parsed view; raw snapshot at $snap)"
    fi
}

# ---------- client role ----------

client_mode() {
    local target="127.0.0.1:443"
    local count=200
    local client="$ROOT/target/release/quic-echo-client"
    local log="/tmp/restart-drop-client.log"
    local verbose=0
    # Empty string means "no assertion"; non-empty must parse as integer.
    local max_post_fail=""
    local max_overall_fail=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -t|--target)            target="$2"; shift 2 ;;
            -n|--count)             count="$2"; shift 2 ;;
            -c|--client)            client="$2"; shift 2 ;;
            -l|--log)               log="$2"; shift 2 ;;
            -v|--verbose)           verbose=1; shift ;;
            --max-post-fail)        max_post_fail="$2"; shift 2 ;;
            --max-overall-fail)     max_overall_fail="$2"; shift 2 ;;
            -h|--help)              usage; exit 0 ;;
            *) echo "Unknown option: $1" >&2; exit 2 ;;
        esac
    done

    for v in max_post_fail max_overall_fail; do
        if [[ -n "${!v}" && ! "${!v}" =~ ^[0-9]+$ ]]; then
            echo "Error: --${v//_/-} expects a non-negative integer, got '${!v}'" >&2
            exit 2
        fi
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
  log:       $log
  midpoint:  $midpoint (pause for manual LB handoff here)

Press enter to begin traffic...
EOF
    read -r

    printf '#i\tphase\tstatus\tdur_ms\tec\terr\n' > "$log"

    local pre_pass=0 pre_fail=0 post_pass=0 post_fail=0
    local post_window_fail=0 post_window_size=5

    for i in $(seq 1 "$count"); do
        local phase="pre"
        (( i > midpoint )) && phase="post"

        local t0 t1 dur_ms ec=0 err
        t0=$(date +%s%N)
        err=$(timeout 3 "$client" --connect "$target" --count 1 --message "probe-$i" 2>&1 >/dev/null) || ec=$?
        t1=$(date +%s%N)
        dur_ms=$(awk "BEGIN { printf \"%.0f\", ($t1 - $t0) / 1e6 }")
        # Last non-empty line of quinn's stderr is the useful bit.
        local err_summary
        err_summary=$(printf '%s' "$err" | awk '/./{x=$0} END{print x}')
        # Strip tabs/newlines to keep TSV clean.
        err_summary=${err_summary//$'\t'/ }

        local status
        if [[ $ec -eq 0 ]]; then
            status=ok
            if [[ $phase == "pre" ]]; then
                pre_pass=$((pre_pass + 1))
            else
                post_pass=$((post_pass + 1))
            fi
            [[ $verbose -eq 1 ]] && echo "  $i [$phase]: ok (${dur_ms}ms)"
        else
            status=FAIL
            if [[ $phase == "pre" ]]; then
                pre_fail=$((pre_fail + 1))
            else
                post_fail=$((post_fail + 1))
                local window_idx=$(( i - midpoint ))
                (( window_idx <= post_window_size )) && \
                    post_window_fail=$((post_window_fail + 1))
            fi
            [[ $verbose -eq 1 ]] && echo "  $i [$phase]: FAIL ec=$ec ${dur_ms}ms ${err_summary}"
        fi

        printf '%d\t%s\t%s\t%s\t%d\t%s\n' "$i" "$phase" "$status" "$dur_ms" "$ec" "$err_summary" >> "$log"

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

    if (( fail > 0 )); then
        echo
        echo "Failure breakdown:"
        # Bucket durations: <100ms fast, 100-1000 mid, 1000-2900 slow, 2900+ timeout.
        awk -F'\t' '
            NR==1 { next }
            $3 == "FAIL" {
                n++
                ec[$5]++
                if ($4 < 100)                 b_fast++
                else if ($4 < 1000)           b_mid++
                else if ($4 < 2900)           b_slow++
                else                          b_timeout++
                if (count_err[$6]++ == 0 && seen_ex < 5) {
                    ex[seen_ex++] = sprintf("    %s [%sms ec=%s]: %s", $2, $4, $5, $6)
                }
            }
            END {
                printf "  duration buckets:\n"
                printf "    <100ms (fast fail):               %d\n", b_fast+0
                printf "    100-1000ms:                       %d\n", b_mid+0
                printf "    1000-2900ms:                      %d\n", b_slow+0
                printf "    >=2900ms (likely 3s timeout):     %d\n", b_timeout+0
                printf "  exit codes:\n"
                for (c in ec) printf "    ec=%s:                            %d\n", c, ec[c]
                printf "  sample errors (up to 5 unique):\n"
                for (k = 0; k < seen_ex; k++) print ex[k]
            }
        ' "$log"
    fi

    echo
    echo "Per-attempt log: $log"

    # Assertions — when set, gate the exit code on observed failure counts.
    # Phase 2 expectation: post_window_fail near zero (handoff preserves the
    # AF_XDP rebind window so packets in flight aren't dropped).
    local assertion_failed=0
    if [[ -n "$max_post_fail" ]]; then
        echo
        if (( post_window_fail > max_post_fail )); then
            echo "ASSERT FAIL: post-handoff window failures $post_window_fail exceeds threshold $max_post_fail"
            assertion_failed=1
        else
            echo "ASSERT PASS: post-handoff window failures $post_window_fail <= threshold $max_post_fail"
        fi
    fi
    if [[ -n "$max_overall_fail" ]]; then
        if (( fail > max_overall_fail )); then
            echo "ASSERT FAIL: overall failures $fail exceeds threshold $max_overall_fail"
            assertion_failed=1
        else
            echo "ASSERT PASS: overall failures $fail <= threshold $max_overall_fail"
        fi
    fi
    (( assertion_failed )) && exit 3
}

# ---------- lb role ----------

lb_mode() {
    local intf="eth0"
    local socket=""
    local out_prefix="/tmp/restart-drop-lb"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -i|--interface) intf="$2"; shift 2 ;;
            -s|--socket)    socket="$2"; shift 2 ;;
            -o|--out)       out_prefix="$2"; shift 2 ;;
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

    local pre_snap="${out_prefix}.pre.json"
    local post_snap="${out_prefix}.post.json"

    echo "LB role"
    echo "  interface:  $intf"
    echo "  socket:     $socket"
    echo "  pidfile:    $pidfile (pid $pid)"
    echo "  snapshots:  $pre_snap / $post_snap"
    echo
    echo "Verifying daemon is ready before handoff..."
    wait_for_ready "$socket" || {
        echo "Daemon not ready before handoff" >&2
        exit 1
    }

    snapshot_stats "$socket" "$pre_snap" || true

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

    cat <<EOF

Resume the client now (press enter on its prompt). Once the client has
printed its final report, press enter here to capture the post-handoff
snapshot from the new daemon.
EOF
    read -r

    if snapshot_stats "$socket" "$post_snap"; then
        if [[ -s "$pre_snap" ]]; then
            echo
            echo "Pre-handoff phase (old daemon cumulative at SIGUSR2):"
            print_nonzero_stats "$pre_snap"
        fi
        echo
        echo "Post-handoff phase (new daemon cumulative since restart):"
        print_nonzero_stats "$post_snap"
    fi
}

# ---------- snapshot role ----------

snapshot_mode() {
    local intf="eth0"
    local socket=""
    local out=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -i|--interface) intf="$2"; shift 2 ;;
            -s|--socket)    socket="$2"; shift 2 ;;
            -o|--out)       out="$2"; shift 2 ;;
            -h|--help)      usage; exit 0 ;;
            *) echo "Unknown option: $1" >&2; exit 2 ;;
        esac
    done

    [[ -z "$socket" ]] && socket="/run/pesigitg/status-$intf.sock"
    [[ -z "$out" ]] && out="/tmp/restart-drop-stats-$(date +%Y%m%d-%H%M%S).json"

    [[ -S "$socket" ]] || {
        echo "Error: $socket is not a socket (is pesigitgd running?)" >&2
        exit 2
    }

    snapshot_stats "$socket" "$out" || exit 1
    echo "Wrote $out"
}

# ---------- dispatch ----------

ROLE="${1:-}"
shift || true

case "$ROLE" in
    client)   client_mode "$@" ;;
    lb)       lb_mode "$@" ;;
    snapshot) snapshot_mode "$@" ;;
    -h|--help|'') usage; exit 0 ;;
    *) echo "Unknown role: $ROLE (expected 'client', 'lb', or 'snapshot')" >&2; exit 2 ;;
esac
