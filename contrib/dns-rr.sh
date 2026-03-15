#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: dns-rr.sh [OPTIONS] DOMAIN

Generate an HTTPS DNS Resource Record (RFC 9460) for advertising HTTP/3 (QUIC) support for a domain.

Arguments:
  DOMAIN                Domain name (e.g., example.com)

Options:
  -4, --ipv4 ADDR       IPv4 address hint (repeatable)
  -6, --ipv6 ADDR       IPv6 address hint (repeatable)
  -p, --port PORT       Service port (omitted when 443)
  -t, --ttl TTL         Record TTL in seconds (default: 300)
      --priority PRI    Record priority (default: 1)
      --target TGT      Target name (default: . meaning same domain)
      --no-default-alpn Advertise that default ALPNs are not supported
      --ech FILE        Path to ECHConfigList file (base64-encoded value)
      --value-only      Output only the record value (no domain, TTL, class, or type)
  -h, --help            Show this help

Examples:
  # Minimal — just advertise h3 support
  dns-rr.sh example.com

  # With IP address hints
  dns-rr.sh -4 192.0.2.1 -6 2001:db8::1 example.com

  # Multiple IPv4 hints, non-standard port
  dns-rr.sh -4 192.0.2.1 -4 192.0.2.2 -p 8443 example.com

  # With Encrypted Client Hello
  dns-rr.sh -4 192.0.2.1 --ech /path/to/echconfiglist.b64 example.com

  # Value only — for DNS providers that separate the name and value
  dns-rr.sh --value-only -4 192.0.2.1 example.com
EOF
    exit "${1:-0}"
}

TTL=300
PRIORITY=1
TARGET="."
NO_DEFAULT_ALPN=false
VALUE_ONLY=false
PORT=""
ECH_FILE=""
IPV4_HINTS=()
IPV6_HINTS=()
DOMAIN=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -4|--ipv4)
            [[ $# -ge 2 ]] || { echo "Error: $1 requires an argument" >&2; exit 1; }
            IPV4_HINTS+=("$2"); shift 2 ;;
        -6|--ipv6)
            [[ $# -ge 2 ]] || { echo "Error: $1 requires an argument" >&2; exit 1; }
            IPV6_HINTS+=("$2"); shift 2 ;;
        -p|--port)
            [[ $# -ge 2 ]] || { echo "Error: $1 requires an argument" >&2; exit 1; }
            PORT="$2"; shift 2 ;;
        -t|--ttl)
            [[ $# -ge 2 ]] || { echo "Error: $1 requires an argument" >&2; exit 1; }
            TTL="$2"; shift 2 ;;
        --priority)
            [[ $# -ge 2 ]] || { echo "Error: $1 requires an argument" >&2; exit 1; }
            PRIORITY="$2"; shift 2 ;;
        --target)
            [[ $# -ge 2 ]] || { echo "Error: $1 requires an argument" >&2; exit 1; }
            TARGET="$2"; shift 2 ;;
        --no-default-alpn)
            NO_DEFAULT_ALPN=true; shift ;;
        --value-only)
            VALUE_ONLY=true; shift ;;
        --ech)
            [[ $# -ge 2 ]] || { echo "Error: $1 requires an argument" >&2; exit 1; }
            ECH_FILE="$2"; shift 2 ;;
        -h|--help)
            usage 0 ;;
        -*)
            echo "Error: unknown option: $1" >&2
            usage 1 ;;
        *)
            if [[ -z "$DOMAIN" ]]; then
                DOMAIN="$1"
            else
                echo "Error: unexpected argument: $1" >&2
                usage 1
            fi
            shift ;;
    esac
done

if [[ -z "$DOMAIN" ]]; then
    echo "Error: DOMAIN is required" >&2
    echo >&2
    usage 1
fi

# Ensure FQDN (trailing dot) for zone file format
[[ "$DOMAIN" == *. ]] || DOMAIN="${DOMAIN}."

# Build SvcParams in RFC 9460 presentation format
PARAMS="alpn=h3,h2"

if $NO_DEFAULT_ALPN; then
    PARAMS="${PARAMS} no-default-alpn"
fi

if [[ -n "$PORT" && "$PORT" != "443" ]]; then
    PARAMS="${PARAMS} port=${PORT}"
fi

if [[ ${#IPV4_HINTS[@]} -gt 0 ]]; then
    IPV4_CSV=$(IFS=,; echo "${IPV4_HINTS[*]}")
    PARAMS="${PARAMS} ipv4hint=${IPV4_CSV}"
fi

if [[ ${#IPV6_HINTS[@]} -gt 0 ]]; then
    IPV6_CSV=$(IFS=,; echo "${IPV6_HINTS[*]}")
    PARAMS="${PARAMS} ipv6hint=${IPV6_CSV}"
fi

if [[ -n "$ECH_FILE" ]]; then
    if [[ ! -f "$ECH_FILE" ]]; then
        echo "Error: ECH file not found: $ECH_FILE" >&2
        exit 1
    fi
    ECH_VALUE=$(<"$ECH_FILE")
    # Strip any whitespace/newlines from the base64 value
    ECH_VALUE="${ECH_VALUE//[$'\n\r\t ']}"
    PARAMS="${PARAMS} ech=${ECH_VALUE}"
fi

if $VALUE_ONLY; then
    echo "${PRIORITY} ${TARGET} ${PARAMS}"
else
    echo "${DOMAIN}  ${TTL}  IN  HTTPS  ${PRIORITY} ${TARGET} ${PARAMS}"
fi
