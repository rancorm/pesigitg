% PESIGITGD(8) pesigitgd | Pesigitg Manual
% Jonathan Cormier
% April 2026

# NAME

pesigitgd - QUIC-aware load balancer using eBPF and AF_XDP

# SYNOPSIS

**pesigitgd** [**-f**] [**-i** *interface*] [**-p** *port*]... [**-q** *num*]
              [**-c** *path*] [**-s** *path*]

**pesigitgd** **-V** | **-h**

# DESCRIPTION

**pesigitgd** is a high-performance QUIC-aware load balancer that uses eBPF
and AF_XDP for kernel-bypass packet forwarding. It decodes QUIC Connection
IDs per draft-ietf-quic-load-balancers-21 to route packets to backend
servers without terminating the connection.

By default the daemon forks into the background. Use **-f** to keep it in
the foreground (for **systemd.service**(5) Type=simple units, container
runtimes, or interactive debugging).

Configuration values are resolved in this order, with earlier sources
taking precedence:

1. Command-line flags.
2. The daemon config file passed via **-c** (see **pesigitgd.conf**(5)).
3. Built-in defaults.

# OPTIONS

**-p**, **--port** *PORT*
:   UDP port to listen on. May be repeated to bind multiple ports.
    Defaults to 443 if neither the CLI nor the config file specify a port.

**-i**, **--interface** *NAME*
:   Network interface to attach the XDP program to. Default: *eth0*.

**-q**, **--queues** *NUM*
:   Number of NIC RX queues to bind AF_XDP sockets to. Must be between 1
    and 256. Default: 1. The interface must have at least *NUM* combined
    channels configured (see **ethtool**(8) **-l**/**-L**).

**-c**, **--config** *PATH*
:   Path to a daemon config file. See **pesigitgd.conf**(5). CLI flags
    override values from the config file. The config file may in turn
    reference a TOML route config; see **pesigitg-lb.toml**(5).

**-s**, **--status-socket** *PATH*
:   Unix-domain socket path for the JSON status API. When set, **pesigitgd**
    binds a read-only socket (mode *0660*) exposing */health*, */stats*, and
    */config* endpoints. Unset disables the API. See **STATUS API** below.

**-f**, **--foreground**
:   Do not daemonize; remain attached to the controlling terminal. Logs
    are written to *stderr*.

**-V**, **--version**
:   Print version, build date, rustc version, and target platform, then
    exit.

**-h**, **--help**
:   Print a usage summary and exit. Development builds list additional
    options, including **-l**/**--load-ebpf** for overriding the embedded
    eBPF object.

# SIGNALS

**SIGHUP**
:   Reload the daemon and route configurations, re-resolve server MAC
    addresses, and reset health-check backoff so all backends are re-probed
    on the next cycle. Under **systemd**(1), *RELOADING=1* is notified with
    *MONOTONIC_USEC* so reload duration is tracked.

**SIGUSR1**
:   Dump aggregated traffic statistics (packet counters, routing decisions,
    retry outcomes) to the log. See **STATISTICS** below for the field
    schema.

**SIGUSR2**
:   Dump the full runtime config to the log: daemon args, active route
    slots, per-server IP/MAC/health/drain status, fallback pool membership,
    and retry settings.

**SIGINT**, **SIGTERM**
:   Graceful shutdown — stop all AF_XDP workers, close the status socket
    (if any), and exit.

# HEALTH CHECKING

**pesigitgd** probes each backend with a short QUIC handshake and removes
servers that fail repeatedly from both the CID and fallback routing paths.
A backend returns to service automatically once a subsequent probe
succeeds.

Probes target the **first** configured listening port only. When the
daemon binds multiple ports (e.g. 443 and 8443), backends are still
checked on the first one. This assumes the backend runs a single QUIC
server instance whose reachability is the same on every advertised port;
deployments that expose different health on different ports are not
supported.

Send **SIGHUP** to reset the exponential backoff on unhealthy servers so
they are re-probed on the next cycle.

# STATUS API

When **--status-socket** (or **status_socket** in **pesigitgd.conf**(5)) is
set, **pesigitgd** exposes a line-oriented JSON API over a Unix-domain
socket. One request per connection. Access is gated solely by filesystem
permissions on the socket (mode *0660*, root-owned by default).

**GET /**
:   List of available endpoints.

**GET /health**
:   Lock-free liveness probe: *status* (**ok**/**degraded**), uptime,
    and worker alive/expected counts. Safe to poll at high frequency.

**GET /version**
:   Build identifiers — *name*, *version*, *build_date*,
    *rustc_version*, *target*. All values are baked in at compile
    time and never change for the lifetime of a daemon process, so
    polling can detect rolling restarts and binary drift across a
    fleet without parsing logs.

**GET /stats**
:   Aggregated counters — same data as the **SIGUSR1** log dump, in JSON.
    See **STATISTICS** below for the field schema.

**GET /config**
:   Live daemon args and the full route table. Encryption keys are never
    exposed; only the scheme name (**plaintext**, **single_pass**,
    **four_pass**).

See **contrib/ok.sh** in the source distribution for a sysadmin-oriented
wrapper that exits non-zero on degraded status.

# STATISTICS

The **GET /stats** endpoint and **SIGUSR1** log dump expose the same
counters, aggregated across all worker threads. JSON field names are
the stable contract; the **SIGUSR1** dump uses abbreviated names
(*rx*, *fwd*, *cid*, *fallback*, *icmp*, *pass*) but reports the same
totals. All counters are monotonic *u64*.

*uptime_secs*
:   Seconds since daemon start. (Not present in the **SIGUSR1** dump.)

*rx_packets*
:   Packets received from the NIC by all AF_XDP workers.

*forwarded*
:   Packets delivered to a backend or upstream — sum of *cid_routed* +
    *fallback_routed* + *icmp_forwarded*. *draining_forwarded* is
    *not* included.

*cid_routed*
:   Packets routed by decoding a QUIC-LB Connection ID.

*cid_by_config*
:   Per-*config_id* breakdown of *cid_routed* (a map of *config_id*
    0–6 to packet count). Zero-count entries are omitted.

*fallback_routed*
:   Packets routed via the fallback pool — short-header packets with
    no connection-table entry, or long-header packets whose decoded
    *config_id* is unconfigured.

*cid_unroutable*
:   Packets whose CID decoded successfully but pointed to a server
    that was unhealthy or absent. Indicates backend churn or stale
    CIDs, not a load-balancer error.

*draining_forwarded*
:   Packets forwarded to a backend marked **drain** in the route
    table. A non-zero delta after a drain transition is expected and
    decays to zero as flows finish.

*icmp_forwarded*
:   ICMP / ICMPv6 packets forwarded (e.g. PMTU discovery).

*passed*
:   Packets the daemon declined to handle and passed back to the
    kernel network stack — non-QUIC traffic on the bound port,
    malformed long headers, etc.

*pending_fill_peak*
:   Peak observed UMEM fill-ring backlog over the daemon's lifetime.
    Sustained non-zero values indicate the worker is falling behind
    on returning frames to the NIC.

The **retry** sub-object groups counters from the QUIC Retry service
(see **pesigitg-lb.toml**(5) **[retry]**). All fields are zero unless
*retry.enabled* is set in the route config.

*retry.initials_seen*
:   QUIC v1/v2 Initials the Retry classifier observed.

*retry.issued*
:   Retry responses emitted in place. Always zero in **observe** mode;
    in **load** mode, gated by the configured engagement threshold.

*retry.token_validated*
:   Initials carrying a token whose HMAC matched and was within
    *token_lifetime*.

*retry.token_invalid*
:   Initials carrying a token whose HMAC did not match. Indicates
    spoofed source addresses, replay against a different LB, or a
    *token_key* rotation since issuance.

*retry.token_expired*
:   Token HMAC matched but the timestamp was older than
    *token_lifetime*. Triggers a fresh Retry in emitting modes.

*retry.parse_error*
:   Packets that resembled a QUIC v1/v2 Initial but failed to parse
    past the version field (truncated CIDs, invalid varints, length
    overrun).

# ENVIRONMENT

**RUST_LOG**
:   Controls log verbosity. Example: *RUST_LOG=pesigitgd=debug*. Defaults
    to *pesigitgd=info* when launched via **cargo xtask run**.

# FILES

*/etc/pesigitg/pesigitgd.conf*
:   Default daemon config file location (if packaged).

*/etc/pesigitg/lb.toml*
:   Default route/CID config file location (if packaged).

*/var/run/pesigitgd-INTERFACE.pid*
:   PID file written when running daemonized outside **systemd**(1). The
    interface name is embedded so multiple manual instances can coexist.
    Under systemd the PID file is skipped (the main PID is tracked via
    *Type=notify*).

*/run/pesigitg/*
:   Runtime directory for status sockets. Created automatically by
    **systemd**(1) via *RuntimeDirectory=* or, on manual invocation, by
    the daemon at bind time.

# EXIT STATUS

**0**
:   Successful termination.

**non-zero**
:   Startup or runtime error. See *stderr* or the system journal for
    details.

# EXAMPLES

Run in the foreground on *enp2s0f0* with 6 RX queues, listening on UDP 443:

    pesigitgd -f -i enp2s0f0 -p 443 -q 6

Launch under **systemd**(1) with a config file:

    pesigitgd -f -c /etc/pesigitg/pesigitgd.conf

Bind multiple ports:

    pesigitgd -f -i enp2s0f0 -p 443 -p 8443

Enable the JSON status API on the systemd runtime directory:

    pesigitgd -f -i enp2s0f0 -p 443 -s /run/pesigitg/status.sock

Check liveness from the shell:

    printf 'GET /health\n' | nc -U /run/pesigitg/status.sock

# SEE ALSO

**pesigitgd.conf**(5), **pesigitg-lb.toml**(5), **systemd.service**(5),
**ethtool**(8), **ip-link**(8), **bpftool**(8)

# STANDARDS

draft-ietf-quic-load-balancers-21, *QUIC-LB: Generating Routable QUIC
Connection IDs*.

# AUTHOR

Jonathan Cormier.

# COPYRIGHT

Copyright (c) 2026 Jonathan Cormier. Licensed under GPL-3.0-or-later or a
commercial license; see *LICENSE* and *LICENSE-COMMERCIAL.md* in the
source distribution.
