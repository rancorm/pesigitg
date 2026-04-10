% PESIGITG-LB.TOML(5) pesigitgd | Pesigitg Manual
% Jonathan Cormier
% April 2026

# NAME

pesigitg-lb.toml - QUIC-LB route/CID configuration for pesigitgd

# SYNOPSIS

*/etc/pesigitg/lb.toml*

# DESCRIPTION

The route config is a TOML document describing one or more QUIC-LB
configurations and their backend servers. **pesigitgd**(8) loads it via
the **route_config** directive in **pesigitgd.conf**(5).

The file follows draft-ietf-quic-load-balancers-21. Up to seven
configurations may be active simultaneously, each identified by a
**config_id** in the range 0-6. The config_id is encoded in the top three
bits of the first CID octet; codepoint 7 (0b111) is reserved for the
fallback / unroutable path and must not be used.

# STRUCTURE

Each configuration is an entry in a **[[configs]]** array. Each backend is
an entry in that configuration's **[[configs.servers]]** sub-array.

## [[configs]] keys

**config_id** = *0..6*
:   Configuration slot. Must be unique within the file. Required.

**first_octet_encodes_cid_length** = *true* | *false*
:   When *true*, the lower 6 bits of the first CID octet encode the
    remaining CID length. Default: *false*.

**server_id_length** = *1..15*
:   Length in octets of the server ID embedded in each CID. Required.

**nonce_length** = *4..18*
:   Length in octets of the nonce portion of each CID. Required. The sum
    **server_id_length + nonce_length** must not exceed 19.

**key** = *"<32 hex chars>"*
:   Optional 16-byte (128-bit) AES key, hex-encoded. When present, the
    encryption mode is chosen automatically from the length sum (see
    **ENCRYPTION MODES** below). When absent, the configuration runs in
    plaintext mode, which is not recommended for production.

## [[configs.servers]] keys

**id** = *"<hex>"*
:   Server ID as a hex string whose length equals
    **server_id_length × 2**. Required.

**address** = *"<ip>"*
:   IPv4 or IPv6 address used as the forwarding destination and for MAC
    resolution. Required.

**mac** = *"aa:bb:cc:dd:ee:ff"*
:   Optional L2 override. When omitted, the daemon resolves the MAC at
    runtime via neighbor discovery.

**draining** = *true* | *false*
:   When *true*, existing CID-routed flows continue to reach this server
    but new fallback connections are not assigned to it. Default: *false*.

# ENCRYPTION MODES

The sum *sum = server_id_length + nonce_length* selects the mode used
when a **key** is supplied:

- **sum == 16**: single-pass AES-128-ECB. Fastest; one block operation
  per CID.
- **sum != 16** and **sum <= 19**: four-pass block cipher (Feistel
  construction over AES-128).
- **no key**: plaintext. Not recommended for production.

Typical trade-offs for single-pass AES-ECB (*sum == 16*):

| server_id_length | nonce_length | notes                                   |
|------------------|--------------|-----------------------------------------|
| 1                | 15           | 256 servers, longest nonce life         |
| 2                | 14           | 65K servers, still huge nonce space     |
| 3                | 13           | 16M servers, practical sweet spot       |
| 4                | 12           | 4B servers, overkill for most           |
| 12               | 4            | massive server space, nonce exhausts    |

Typical trade-offs for four-pass mode (*sum != 16*, *sum <= 19*):

| server_id_length | nonce_length | sum | notes                         |
|------------------|--------------|-----|-------------------------------|
| 1                | 4            | 5   | 256 servers, minimal CID size |
| 2                | 4            | 6   | 65K servers, compact CID      |
| 3                | 8            | 11  | 16M servers, good nonce life  |
| 4                | 4            | 8   | 4B servers, compact CID       |
| 15               | 4            | 19  | max server space, short nonce |

# EXAMPLES

Minimal single-pass configuration with three IPv4 backends and one IPv6
backend:

    [[configs]]
    config_id = 0
    first_octet_encodes_cid_length = true
    server_id_length = 3
    nonce_length = 13
    key = "597a84b3093ebb17567bcb7e06721d68"

    [[configs.servers]]
    id = "000001"
    address = "10.0.1.10"

    [[configs.servers]]
    id = "000002"
    address = "10.0.1.11"

    [[configs.servers]]
    id = "000003"
    address = "10.0.1.12"
    mac = "aa:bb:cc:dd:ee:03"

    [[configs.servers]]
    id = "000004"
    address = "2001:db8::1"

Running two configurations in parallel for key rotation:

    [[configs]]
    config_id = 0
    server_id_length = 3
    nonce_length = 13
    key = "597a84b3093ebb17567bcb7e06721d68"

    [[configs.servers]]
    id = "000001"
    address = "10.0.1.10"

    [[configs]]
    config_id = 1
    server_id_length = 3
    nonce_length = 13
    key = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"

    [[configs.servers]]
    id = "000001"
    address = "10.0.1.10"

# DIAGNOSTICS

**pesigitgd**(8) refuses to start if any of the following hold:

- the file contains no **[[configs]]** entry;
- a **config_id** is outside 0-6 or is used more than once;
- **server_id_length** is not in 1-15, or **nonce_length** is not in
  4-18, or their sum exceeds 19;
- a **key** is not a valid 16-byte hex string;
- a server **id** has the wrong length for its configuration;
- a server **address** or **mac** cannot be parsed.

Servers start marked unhealthy and become eligible for fallback hashing
only after a QUIC probe succeeds and their MAC is resolved.

# SEE ALSO

**pesigitgd**(8), **pesigitgd.conf**(5)

# STANDARDS

draft-ietf-quic-load-balancers-21, *QUIC-LB: Generating Routable QUIC
Connection IDs*.

# AUTHOR

Jonathan Cormier.

# COPYRIGHT

Copyright (c) 2026 Jonathan Cormier. Licensed under GPL-3.0-or-later or a
commercial license.
