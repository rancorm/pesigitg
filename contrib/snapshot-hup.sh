#!/usr/bin/env bash
#
# snapshot-hup.sh [Bracket a SIGHUP-driven config rotation with snapshots]
#
# Runs `snapshot.sh` once for steady-state baseline, sends SIGHUP via
# `hup.sh`, then runs `snapshot.sh` again to capture the rotation
# transient. The "AFTER" sample is what tells you whether
# `cid_unroutable` or `passed` briefly spike during a rotation —
# the question that decides whether those branches deserve `#[cold]`.
#
# Usage: snapshot-hup.sh [-i INTF] [-d SECONDS] [-w SECONDS]
#   -i, --interface INTF Interface of socket (default: eth0)
#   -d, --duration SECS  Sample window for each snapshot (default: 30)
#   -w, --wait SECS      Pause between SIGHUP and AFTER sample (default: 2)
#   -h, --help           Show this help
#
# Exit codes:
#   0 — both samples captured
#   2 — bad arguments
#   non-zero — propagated from snapshot.sh / hup.sh on failure
#
# SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
# Copyright (c) 2026 Jonathan Cormier
# This file is part of Pesigitg.

set -euo pipefail

INTF="eth0"
DURATION=30
WAIT=2

usage() {
    sed -n '2,20p' "$0" | sed 's/^# \?//'
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -i|--interface) INTF="$2"; shift 2 ;;
        -d|--duration)  DURATION="$2"; shift 2 ;;
        -w|--wait)      WAIT="$2"; shift 2 ;;
        -h|--help)      usage; exit 0 ;;
        *)              echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNAPSHOT="$SCRIPT_DIR/snapshot.sh"
HUP="$SCRIPT_DIR/hup.sh"

[[ -x "$SNAPSHOT" ]] || { echo "Error: $SNAPSHOT not executable" >&2; exit 2; }
[[ -x "$HUP" ]]      || { echo "Error: $HUP not executable" >&2; exit 2; }

echo "=== BEFORE rotation (steady state) ==="
"$SNAPSHOT" -i "$INTF" -d "$DURATION"

echo
echo "--- Sending SIGHUP to pesigitgd-$INTF ---"
"$HUP" "$INTF"
sleep "$WAIT"

echo
echo "=== AFTER rotation (transient window) ==="
"$SNAPSHOT" -i "$INTF" -d "$DURATION"

echo
echo "Look for any cold-path candidate that flipped from ✓ to ✗"
echo "between the two samples — that's a branch you should NOT mark"
echo "#[cold]."
