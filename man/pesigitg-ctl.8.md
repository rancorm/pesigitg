% PESIGITG-CTL(8) pesigitg-ctl | Pesigitg Manual
% Jonathan Cormier
% April 2026

# NAME

pesigitg-ctl - control utility for **pesigitgd**(8) instances

# SYNOPSIS

**pesigitg-ctl** *command* [*args...*]

**pesigitg-ctl** **-h** | **--help** | **-V** | **--version**

# DESCRIPTION

**pesigitg-ctl** discovers running **pesigitgd**(8) instances on the local
host, reports liveness and traffic counters via each daemon's JSON status
socket, and signals individual daemons (reload, graceful shutdown, zero-drop
handoff). It works in both **systemd**(1) and ad-hoc invocation modes.

A *command* is required. Names may be abbreviated to any unique prefix
(e.g. **co** for **config**, **res** for **restart**); ambiguous prefixes
such as **s** (which matches **status**, **stats**, **stop**) are rejected.

Most commands accept an optional *target* — see **TARGET RESOLUTION**.

# COMMANDS

## Inventory

**list**
:   List every discovered instance: interface, pid, and which discovery
    sources observed it (*pidfile*, *socket*, *proc*). Stale pidfiles
    (pidfile present, no live process) are flagged inline.

**paths**
:   Print the conventional filesystem locations: PID directory, runtime
    directory for status sockets, and the bpffs pin root.

**version**
:   Print this control utility's own version. (Use **info** to query the
    daemon's build identifiers.)

## Status (read-only)

These commands open the per-instance Unix-domain status socket. They
require *status_socket* to be configured on the target daemon (see
**pesigitgd.conf**(5)). Filesystem permissions on the socket gate access.

**status** [*target*]
:   One-line health summary: status, uptime, worker counts.

**health** [*target*]
:   Pretty-printed **GET /health** JSON.

**stats** [*target*]
:   Pretty-printed **GET /stats** JSON. See **STATISTICS** in
    **pesigitgd**(8) for the field schema.

**config** [*target*]
:   Pretty-printed **GET /config** JSON: live daemon args and route
    table. Encryption keys are never exposed; only the scheme name.

**info** [*target*]
:   Pretty-printed **GET /version** JSON from the daemon: name, version,
    build date, rustc version, and target. Useful for detecting binary
    drift and rolling-restart progress across a fleet.

**endpoint** *path* [*target*]
:   Escape hatch — fetch any status endpoint by path (e.g. **/health**,
    **/stats**). Path must start with **/**. Future daemon endpoints can
    be probed without a ctl update.

**whoami** *cid-hex* [*target*] [**-r** *PATH* | **--route-config** *PATH*]
:   Decode a QUIC Connection ID and report which backend the flow would
    land on. Extracts the *config_id* from the CID's first three bits,
    looks up the matching route entry, and renders *config_id*, scheme,
    server-id length, nonce length, and the resolved server (address,
    MAC, declared state). CIDs whose first octet encodes the reserved
    *config_id* 7 (e.g. pre-handshake / Initials with random CIDs) are
    flagged as such.

    Two modes:

    - **Online (default).** Fetches **GET /config** from the target
      daemon's status socket. *plaintext* schemes are decoded fully;
      *single_pass* and *four_pass* CIDs only get a scheme/length
      report because **/config** redacts the encryption key. The
      verdict points at **--route-config** for full decode.
    - **Offline (--route-config).** Parses the supplied route TOML
      directly and decodes against it — including encrypted schemes,
      since the file holds the keys. Skips daemon discovery entirely;
      a *target* argument is rejected when this flag is supplied.
      Health state isn't available offline, so only the declared
      *draining* flag is surfaced.

**backend-config** *server-id-hex* [*target*] [**-r** *PATH* | **--route-config** *PATH*] [**--no-key**] [**--config-id** *N*]
:   Emit per-backend QUIC-LB provisioning JSON for one *server_id*.
    The output is a single document with **schema_version**, **source**
    (file path or daemon target), and a **matches** array — one entry
    per **config_id** that contains the server. During a key rollover
    a *server_id* appears in two configs; both are emitted so the
    backend QUIC stack can be configured to mint CIDs under each.

    Each match carries the fields the backend's QUIC-LB encoder needs:
    **config_id**, **server_id**, **server_id_length**, **nonce_length**,
    **first_octet_encodes_cid_length**, **encryption** (one of
    *plaintext*, *single_pass*, *four_pass*), **key** (hex; *null*
    when redacted), **key_redacted**, **draining**, **address**, and
    a precomputed **cid_total_length**. Consumers can iterate
    **matches** and provision each entry directly.

    Two modes:

    - **Offline (--route-config).** Parses the route TOML directly,
      so the **key** field carries the raw 16-byte AES key in hex.
      Skips daemon discovery entirely; a *target* argument is rejected
      when this flag is supplied. **SECURITY:** the output contains
      cleartext key material — pipe it into a vault/secret store
      rather than writing it to disk.
    - **Online (default).** Fetches **GET /config** from the target
      daemon's status socket. **/config** redacts encryption keys,
      so encrypted configs come back as **key: null, key_redacted:
      true**. Useful for "what's running right now" inspection;
      cannot provision a fresh backend on its own.

    **--no-key** strips the **key** field even on the offline path
    (sets it to *null* and **key_redacted** to *true* for encrypted
    configs). Use when the consumer only needs the configuration
    shape, not the secret material.

    **--config-id** *N* restricts the output to a single *config_id*
    (0-6). Without the flag, every config containing the server_id
    is emitted.

    With no matches the **matches** array is empty and the exit code
    is **0**; consumers should check **matches | length** rather than
    relying on the exit code.

**watch** [*target*] [**-n** *SECS* | **--interval** *SECS*]
:   Poll **/stats** at a fixed interval and print rate deltas: rx/s,
    fwd/s, cid/s, fallback/s, unrt/s, retry_iss/s. Default interval is
    1 second. The first row is a baseline (rates shown as **-**); a
    counter that goes backwards between samples (daemon restart)
    prints as **\***. Header repeats every 20 rows. Exit with Ctrl-C.

## Signals

These commands send a signal to the target daemon's main pid. They do
not require the status socket. See **SIGNALS** in **pesigitgd**(8) for
the full semantics.

**hup** [*target*] (alias: **reload**)
:   **SIGHUP** — reload daemon and route configs, re-resolve backend
    MACs, reset health-check backoff.

**dump-stats** [*target*] (alias: **usr1**)
:   **SIGUSR1** — log an aggregated stats snapshot.

**restart** [*target*] (aliases: **usr2**, **handoff**)
:   **SIGUSR2** — zero-drop handoff: the daemon stops AF_XDP workers and
    exits but leaves the XDP program and bpffs pins in place. The next
    invocation on the same interface adopts them. See **RESTART** in
    **pesigitgd**(8).

**stop** [*target*]
:   **SIGTERM** — graceful cold shutdown: stops workers, removes bpffs
    pins (detaching the XDP program), exits.

## Maintenance

**pin-info** [*target*]
:   List the contents of */sys/fs/bpf/pesigitg/INTERFACE/*. Accepts an
    interface name directly; the daemon does not need to be running
    (pins persist across handoff shutdown). Reading bpffs requires
    appropriate privileges.

**cleanup**
:   Remove pidfiles whose pid no longer points at a live **pesigitgd**
    process. Requires write access to */var/run* (typically root).
    Returns non-zero if any pidfile could not be removed.

**help**
:   Print the same usage message as **--help**.

# TARGET RESOLUTION

Most commands accept an optional *target* identifying which daemon to
act on. A target is one of:

*INTERFACE*
:   An interface name (e.g. **eth0**, **enp2s0f0**). Matched against
    the discovered instance whose **-i**/**--interface** value matches.

*PID*
:   A numeric process id. The pid must belong to a **pesigitgd**
    process; otherwise the command errors out.

When no target is supplied and exactly one identified daemon is
running, that daemon is selected automatically. With zero or multiple
identified daemons, the command errors with the list of candidates.

# DISCOVERY

Instances are gathered from three sources and keyed by interface:

1. **Pidfiles** under */var/run/pesigitgd-INTERFACE.pid* — only written
   by daemons running outside **systemd**(1), since systemd tracks the
   main pid via *Type=notify*.

2. **Status sockets** under */run/pesigitg/status-INTERFACE.sock* — present
   for any instance with *status_socket* configured, regardless of
   launch mode.

3. **Live processes** in */proc* whose *comm* is **pesigitgd**. The
   interface is parsed out of the kernel-recorded cmdline
   (**-i**/**--interface** in any of the short, long, space-separated,
   or **=**-joined forms).

A process whose interface cannot be determined from its cmdline
(e.g. a systemd instance launched with only **-c** *config*) is listed
under "Unmatched processes" by **list** and reachable only by pid.

# EXIT STATUS

**0**
:   Command succeeded.

**1**
:   Any error: missing/unknown/ambiguous command, target not found,
    socket I/O failure, daemon-side error, or remote endpoint missing.
    The diagnostic is printed to *stderr*.

# EXAMPLES

List every instance:

    pesigitg-ctl list

Quick liveness check (auto-selects the only running instance):

    pesigitg-ctl status

Pretty-print live counters for *eth0*:

    pesigitg-ctl stats eth0

Watch throughput at 5-second intervals:

    pesigitg-ctl watch eth0 -n 5

Reload route config without restarting:

    pesigitg-ctl reload eth0

Zero-drop in-place restart (e.g. after binary upgrade) under systemd —
combine with *Restart=always* on the unit:

    pesigitg-ctl restart eth0

Probe a status endpoint that does not yet have a dedicated subcommand:

    pesigitg-ctl endpoint /health eth0

Decode a Connection ID against the live route table to see which backend
it would route to:

    pesigitg-ctl whoami 0000010102030405060708090a0b0c0d eth0

Decode a Connection ID offline against a route TOML — full decode for
encrypted schemes since the file holds the keys:

    pesigitg-ctl whoami 00241c811384fbcf91de00ff31d3c928af \
        --route-config /etc/pesigitg/lb.toml

Extract per-backend QUIC-LB provisioning JSON for one *server_id* from
a route TOML (output contains the AES key — pipe into a secret store):

    pesigitg-ctl backend-config 000001 \
        --route-config /etc/pesigitg/lb.toml

Same query against a running daemon, with keys redacted server-side:

    pesigitg-ctl backend-config 000001 eth0

Sweep stale pidfiles after an unclean shutdown:

    sudo pesigitg-ctl cleanup

Inspect bpffs pins left behind after **SIGUSR2**:

    sudo pesigitg-ctl pin-info eth0

# FILES

*/var/run/pesigitgd-INTERFACE.pid*
:   Per-interface PID file written by daemons launched outside
    **systemd**(1). See **DISCOVERY**.

*/run/pesigitg/status-INTERFACE.sock*
:   Per-interface status socket. Created by **pesigitgd** at bind time
    when *status_socket* is configured. Mode *0660*, root-owned by
    default; group membership gates non-root read access.

*/sys/fs/bpf/pesigitg/INTERFACE/*
:   bpffs pin root for the XDP program link and the **XSKS** / **PORTS**
    maps. Listed by **pin-info**. See **RESTART** in **pesigitgd**(8).

# SEE ALSO

**pesigitgd**(8), **pesigitgd.conf**(5), **pesigitg-lb.toml**(5),
**systemd.service**(5), **bpftool**(8)

# AUTHOR

Jonathan Cormier.

# COPYRIGHT

Copyright (c) 2026 Jonathan Cormier. Licensed under GPL-3.0-or-later or a
commercial license; see *LICENSE* and *LICENSE-COMMERCIAL.md* in the
source distribution.
