#!/bin/bash
#
# xdp-detach.sh — Detach BPF-linked XDP programs from an interface.
#
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Jonathan Cormier
# This file is part of Pesigitg.

set -euo pipefail

PROGNAME=$(basename $0)

if [[ $# -ne 1 ]]; then
    echo "Usage: $PROGNAME <interface>" >&2
    exit 1
fi

IFACE="$1"
BPFTOOL=$(command -v bpftool) || {
	echo "Error: bpftool not found in PATH." >&2
	exit 1
}

if ! ip link show dev "$IFACE" &>/dev/null; then
    echo "Error: interface '$IFACE' not found." >&2
    exit 1
fi

# Parse bpftool link list for XDP links on this interface.
# Example line:  "201: xdp  prog 580"
# Followed by:   "      ifindex enp2s0f0(3)"
LINK_IDS=$(sudo "$BPFTOOL" link list 2>/dev/null \
    | awk -v iface="$IFACE" '
        /^[0-9]+:.*xdp/ { link_id = $1; sub(/:$/, "", link_id) }
        link_id && $0 ~ "ifindex " iface "\\(" { print link_id; link_id = "" }
    ')

if [[ -z "$LINK_IDS" ]]; then
    echo "No XDP BPF links found on $IFACE."
    exit 0
fi

for ID in $LINK_IDS; do
    echo "Detaching XDP link $ID from $IFACE..."
    sudo "$BPFTOOL" link detach id "$ID"
done

echo "Done."
