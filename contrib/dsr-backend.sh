#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: dsr-backend.sh [OPTIONS] VIP [VIP...]

Configure a backend server for Direct Server Return (DSR) by installing sysctl
settings and adding VIP addresses to the loopback interface via netplan.

Must be run as root.

Arguments:
  VIP                   Virtual IP address with optional prefix length
                        (e.g., 198.51.100.1, 198.51.100.1/32, 2001:db8::1/128)
                        Defaults to /32 for IPv4 and /128 for IPv6

Options:
  -r, --remove          Remove DSR configuration instead of installing it
  -n, --dry-run         Show what would be done without making changes
  -h, --help            Show this help

Files managed:
  /etc/sysctl.d/90-dsr.conf         ARP settings for DSR
  /etc/netplan/99-dsr-vip.yaml      VIP loopback addresses

Examples:
  # Single IPv4 VIP
  dsr-backend.sh 198.51.100.1

  # Multiple VIPs (mixed IPv4 and IPv6)
  dsr-backend.sh 198.51.100.1 2001:db8::1

  # Dry run
  dsr-backend.sh --dry-run 198.51.100.1

  # Remove DSR configuration
  dsr-backend.sh --remove
EOF
    exit "${1:-0}"
}

REMOVE=false
DRY_RUN=false
VIPS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        -r|--remove)
            REMOVE=true; shift ;;
        -n|--dry-run)
            DRY_RUN=true; shift ;;
        -h|--help)
            usage 0 ;;
        -*)
            echo "Error: unknown option: $1" >&2
            usage 1 ;;
        *)
            VIPS+=("$1"); shift ;;
    esac
done

SYSCTL=$(command -v sysctl)
NETPLAN=$(command -v netplan)
SYSCTL_FILE="/etc/sysctl.d/90-dsr.conf"
NETPLAN_FILE="/etc/netplan/99-dsr-vip.yaml"

if [[ $EUID -ne 0 ]]; then
    echo "Error: must be run as root" >&2
    exit 1
fi

# --- Remove mode ---

if $REMOVE; then
    if $DRY_RUN; then
        echo "[dry-run] would remove $SYSCTL_FILE"
        echo "[dry-run] would remove $NETPLAN_FILE"
        echo "[dry-run] would run: $SYSCTL --system"
        echo "[dry-run] would run: $NETPLAN apply"
        exit 0
    fi

    REMOVED=false
    if [[ -f "$SYSCTL_FILE" ]]; then
        rm "$SYSCTL_FILE"
        echo "Removed $SYSCTL_FILE"
        $SYSCTL --system >/dev/null 2>&1
        REMOVED=true
    fi
    if [[ -f "$NETPLAN_FILE" ]]; then
        rm "$NETPLAN_FILE"
        echo "Removed $NETPLAN_FILE"
        $NETPLAN apply
        REMOVED=true
    fi
    if ! $REMOVED; then
        echo "Nothing to remove"
    fi
    exit 0
fi

# --- Install mode ---

if [[ ${#VIPS[@]} -eq 0 ]]; then
    echo "Error: at least one VIP is required" >&2
    echo >&2
    usage 1
fi

# Normalise VIPs: add default prefix length if missing
NORMALISED=()
for VIP in "${VIPS[@]}"; do
    if [[ "$VIP" == */* ]]; then
        NORMALISED+=("$VIP")
    elif [[ "$VIP" == *:* ]]; then
        NORMALISED+=("${VIP}/128")
    else
        NORMALISED+=("${VIP}/32")
    fi
done

# Build sysctl config
SYSCTL_CONTENT="# pesigitg sysctl
net.ipv4.conf.all.arp_ignore = 1
net.ipv4.conf.all.arp_announce = 2
"

# Build netplan config
NETPLAN_CONTENT="# pesigitg netplan
network:
  version: 2
  ethernets:
    lo:
      addresses:"

for VIP in "${NORMALISED[@]}"; do
    NETPLAN_CONTENT="${NETPLAN_CONTENT}
        - ${VIP}"
done
NETPLAN_CONTENT="${NETPLAN_CONTENT}
"

if $DRY_RUN; then
    echo "${SYSCTL_FILE}:"
    echo "$SYSCTL_CONTENT"
    echo "${NETPLAN_FILE}:"
    echo "$NETPLAN_CONTENT"
    echo "[dry-run] would run: $SYSCTL --system"
    echo "[dry-run] would run: $NETPLAN apply"
    exit 0
fi

# Install sysctl config
printf '%s' "$SYSCTL_CONTENT" > "$SYSCTL_FILE"
chmod 644 "$SYSCTL_FILE"
echo "Installed $SYSCTL_FILE"
$SYSCTL --system >/dev/null 2>&1

# Install netplan config
printf '%s' "$NETPLAN_CONTENT" > "$NETPLAN_FILE"
chmod 600 "$NETPLAN_FILE"
echo "Installed $NETPLAN_FILE"
$NETPLAN apply

echo "DSR backend configuration applied"
