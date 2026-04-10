% PESIGITGD(8) pesigitgd | Pesigitg Manual
% Jonathan Cormier
% April 2026

# NAME

pesigitgd - QUIC-aware load balancer using eBPF and AF_XDP

# SYNOPSIS

**pesigitgd** [**-f**] [**-i** *interface*] [**-p** *port*]... [**-q** *num*]
              [**-c** *path*]

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

# ENVIRONMENT

**RUST_LOG**
:   Controls log verbosity. Example: *RUST_LOG=pesigitgd=debug*. Defaults
    to *pesigitgd=info* when launched via **cargo xtask run**.

# FILES

*/etc/pesigitg/pesigitgd.conf*
:   Default daemon config file location (if packaged).

*/etc/pesigitg/lb.toml*
:   Default route/CID config file location (if packaged).

*/run/pesigitgd.pid*
:   PID file written when running in daemonized mode.

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
