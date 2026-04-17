% PESIGITGD.CONF(5) pesigitgd | Pesigitg Manual
% Jonathan Cormier
% April 2026

# NAME

pesigitgd.conf - daemon configuration file for pesigitgd

# SYNOPSIS

*/etc/pesigitg/pesigitgd.conf*

# DESCRIPTION

**pesigitgd.conf** is a plain-text **key = value** file read by
**pesigitgd**(8) when its path is passed via **-c**. The file sets the
listening ports, network interface, RX queue count, and path to the
route/CID config.

Command-line flags always override values from this file. Values not set
in either place fall back to the daemon's built-in defaults.

## File format

- One directive per line.
- Blank lines and lines starting with `#` are ignored.
- Keys and values are separated by `=`; surrounding whitespace is trimmed.
- Unknown keys are ignored (with a warning logged, citing the line
  number) so that older daemons tolerate configs written for newer
  versions. Malformed lines without a `=` separator trigger the same
  warning.

Only ASCII is supported. The file is read in full at startup; changes
require restarting the daemon.

# DIRECTIVES

**port** = *PORT*
:   UDP port to listen on. Must be a valid 16-bit port number
    (1-65535). May appear multiple times to bind several ports. If no
    **port** line is present and no **-p** flag is given, the daemon
    listens on 443.

**interface** = *NAME*
:   Network interface to attach the XDP program to. Default: *eth0*.

**queues** = *NUM*
:   Number of NIC RX queues to bind AF_XDP sockets to. Must be between 1
    and 256. Default: 1. The interface must have at least *NUM* combined
    channels configured (see **ethtool**(8) **-l**/**-L**).

**route_config** = *PATH*
:   Path to the TOML route/CID configuration file; see
    **pesigitg-lb.toml**(5). Relative paths are resolved against the
    directory containing **pesigitgd.conf**. If omitted, **pesigitgd**(8)
    runs without a loaded route table and can only use the fallback path.

**status_socket** = *PATH*
:   Unix-domain socket path for the JSON status API. When set,
    **pesigitgd**(8) binds a read-only socket (mode *0660*) exposing
    */health*, */stats*, and */config* endpoints. When unset (the
    default), the API is disabled. The parent directory is created on
    bind if missing. Equivalent to the **-s**/**--status-socket** flag.
    See **STATUS API** in **pesigitgd**(8).

# EXAMPLES

A typical per-interface config (*/etc/pesigitg/enp2s0f0.conf*):

    interface = enp2s0f0
    port = 443
    queues = 6
    route_config = lb.toml

Multiple listening ports:

    interface = eth0
    port = 443
    port = 8443
    queues = 4
    route_config = /etc/pesigitg/lb.toml

With the JSON status API enabled (see also **pesigitgd**(8)):

    interface = enp2s0f0
    port = 443
    queues = 6
    route_config = lb.toml
    status_socket = /run/pesigitg/status.sock

# DIAGNOSTICS

If the file exceeds the daemon's hard size limit, **pesigitgd**(8) refuses
to start and reports the observed size.

If **queues** is out of range, the daemon exits with an error naming the
valid range (1-256).

# SEE ALSO

**pesigitgd**(8), **pesigitg-lb.toml**(5), **ethtool**(8)

# AUTHOR

Jonathan Cormier.

# COPYRIGHT

Copyright (c) 2026 Jonathan Cormier. Licensed under GPL-3.0-or-later or a
commercial license.
