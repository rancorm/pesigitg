#!/usr/bin/env bash
#
# snapshot.sh [Sample /stats twice and report cold-path candidate ratios]
#
# Pulls the daemon's /stats endpoint, waits, pulls again, and prints the
# delta along with each branch's share of received packets. Intended to
# answer "is this path actually rare?" before tagging it #[cold] — see
# the happy-friday plan, item #3.
#
# Usage: snapshot.sh [-i INTF] [-s SOCKET] [-d SECONDS]
#   -i, --interface INTF Interface of socket (default: eth0)
#   -s, --socket PATH    Status socket (default: /run/pesigitg/status-<intf>.sock)
#   -d, --duration SECS  Sample window in seconds (default: 30)
#   -h, --help           Show this help
#
# Exit codes:
#   0 — sampled successfully
#   2 — bad arguments / socket missing
#   3 — no response from daemon
#   4 — missing required tool
#
# Requires: nc, timeout, jq, awk.
#
# SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
# Copyright (c) 2026 Jonathan Cormier
# This file is part of Pesigitg.

set -euo pipefail

INTF="eth0"
SOCKET=""
DURATION=30

usage() {
    sed -n '2,21p' "$0" | sed 's/^# \?//'
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -i|--interface) INTF="$2"; shift 2 ;;
        -s|--socket)    SOCKET="$2"; shift 2 ;;
        -d|--duration)  DURATION="$2"; shift 2 ;;
        -h|--help)      usage; exit 0 ;;
        *)              echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

[[ -z "$SOCKET" ]] && SOCKET="/run/pesigitg/status-$INTF.sock"

for tool in nc timeout jq awk; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "Error: '$tool' not found in PATH" >&2
        exit 4
    }
done

if [[ ! -S "$SOCKET" ]]; then
    echo "Error: $SOCKET is not a socket (is pesigitgd running?)" >&2
    exit 2
fi

if ! [[ "$DURATION" =~ ^[0-9]+$ ]] || (( DURATION < 1 )); then
    echo "Error: --duration must be a positive integer (seconds)" >&2
    exit 2
fi

fetch_stats() {
    printf 'GET /stats\n' | timeout 2 nc -U "$SOCKET" 2>/dev/null || true
}

T0="$(fetch_stats)"
[[ -z "$T0" ]] && { echo "Error: no response from $SOCKET" >&2; exit 3; }

sleep "$DURATION"

T1="$(fetch_stats)"
[[ -z "$T1" ]] && { echo "Error: no response from $SOCKET" >&2; exit 3; }

# Extract every counter we care about into shell vars in one jq pass per
# snapshot. Field paths must mirror the SnapshotView schema in
# pesigitg-daemon/src/status_api.rs.
read_fields() {
    jq -r '
      [ .rx_packets,
        .cid_routed,
        .fallback_routed,
        .icmp_forwarded,
        .draining_forwarded,
        .cid_unroutable,
        .passed,
        .retry.initials_seen,
        .retry.issued,
        .retry.token_validated,
        .retry.token_invalid,
        .retry.token_expired,
        .retry.parse_error
      ] | @tsv
    '
}

read -r rx0 cid0 fb0 icmp0 drain0 unrout0 pass0 \
        ri0 riss0 rval0 rinv0 rexp0 rperr0 < <(printf '%s' "$T0" | read_fields)

read -r rx1 cid1 fb1 icmp1 drain1 unrout1 pass1 \
        ri1 riss1 rval1 rinv1 rexp1 rperr1 < <(printf '%s' "$T1" | read_fields)

awk -v intf="$INTF" -v dur="$DURATION" \
    -v rx0="$rx0" -v rx1="$rx1" \
    -v cid0="$cid0" -v cid1="$cid1" \
    -v fb0="$fb0" -v fb1="$fb1" \
    -v icmp0="$icmp0" -v icmp1="$icmp1" \
    -v drain0="$drain0" -v drain1="$drain1" \
    -v unrout0="$unrout0" -v unrout1="$unrout1" \
    -v pass0="$pass0" -v pass1="$pass1" \
    -v ri0="$ri0" -v ri1="$ri1" \
    -v riss0="$riss0" -v riss1="$riss1" \
    -v rval0="$rval0" -v rval1="$rval1" \
    -v rinv0="$rinv0" -v rinv1="$rinv1" \
    -v rexp0="$rexp0" -v rexp1="$rexp1" \
    -v rperr0="$rperr0" -v rperr1="$rperr1" '
BEGIN {
    drx     = rx1     - rx0
    dcid    = cid1    - cid0
    dfb     = fb1     - fb0
    dicmp   = icmp1   - icmp0
    ddrain  = drain1  - drain0
    dunrout = unrout1 - unrout0
    dpass   = pass1   - pass0
    dri     = ri1     - ri0
    driss   = riss1   - riss0
    drval   = rval1   - rval0
    drinv   = rinv1   - rinv0
    drexp   = rexp1   - rexp0
    drperr  = rperr1  - rperr0

    printf "pesigitgd snapshot — %s — %ds window — Δrx %s pkts (%s pps)\n\n",
           intf, dur, commafy(drx), (dur > 0 ? commafy(int(drx/dur)) : "0")

    if (drx == 0) {
        print "no traffic during sample window — nothing to compare against"
        exit 0
    }

    print "routed (hot path):"
    row("cid_routed",         dcid,   drx)
    row("fallback_routed",    dfb,    drx)
    row("icmp_forwarded",     dicmp,  drx)
    row("draining_forwarded", ddrain, drx)
    print ""

    print "cold-path candidates:"
    cold_row("passed",            dpass,   drx)
    cold_row("cid_unroutable",    dunrout, drx)
    cold_row("retry.parse_error", drperr,  drx)
    print ""

    print "retry counters (only meaningful if enabled):"
    row("initials_seen",   dri,    drx)
    row("issued",          driss,  drx)
    row("token_validated", drval,  drx)
    row("token_invalid",   drinv,  drx)
    row("token_expired",   drexp,  drx)
    print ""

    print "Rule of thumb: cold candidates with < ~1% share are safe to mark"
    print "#[cold]; anything higher would degrade the common case."
}

function commafy(n,    s, out, i, len) {
    s = (n < 0 ? "-" : "") int(n < 0 ? -n : n)
    len = length(s); out = ""
    for (i = 1; i <= len; i++) {
        out = out substr(s, i, 1)
        if (((len - i) % 3) == 0 && i < len) out = out ","
    }
    return (n < 0 ? "-" : "") out
}

function row(label, n, total) {
    printf "  %-20s %14s   %6.2f%%\n", label ":", commafy(n), (n * 100.0 / total)
}

function cold_row(label, n, total,    pct, mark) {
    pct = n * 100.0 / total
    mark = (pct < 1.0) ? "✓ cold-friendly" : "✗ too common"
    printf "  %-20s %14s   %6.2f%%   %s\n", label ":", commafy(n), pct, mark
}
'
