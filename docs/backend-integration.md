# Backend Integration

QUIC-LB is a server-cooperative scheme: the load balancer can only route
a CID-bearing packet if the **backend mints CIDs that follow the LB's
encoding**.

This doc covers what a QUIC backend must do to live behind `pesigitgd`, the
per-stack points, and how to verify correctness.

If your backend doesn't mint compliant CIDs, every post-handshake
packet falls through to the consistent-hash fallback path. That works,
but it loses the routing-by-CID property the LB exists to provide:
connection migration, NAT rebinding, and 4-tuple-shifting clients all
get re-pinned by hash, breaking session affinity.

## What must match between LB and backend

Five fields. The LB stores them in `[[configs]]`; the backend has to
generate CIDs using the **same** values:

| Field                            | Source on LB             | Backend role |
|----------------------------------|--------------------------|--------------|
| `config_id` (0-6)                | `[[configs]] config_id`  | Encoded in top 3 bits of CID octet 0 |
| `server_id` (per-backend)        | `[[configs.servers]] id` | Identifies *which* backend |
| `server_id_length` (1-15)        | `[[configs]]`            | Bytes of server_id |
| `nonce_length` (4-18)            | `[[configs]]`            | Random bytes per CID |
| `key` (16 bytes hex) or none     | `[[configs]]`            | AES-128 key for payload encryption |

The encryption mode is **derived** from the lengths, not configured
separately:

- No `key` set → **plaintext** (server_id and nonce visible on the wire)
- `server_id_length + nonce_length == 16` → **single-pass AES-128-ECB**
- `server_id_length + nonce_length != 16` (and ≤ 19) → **four-pass Feistel**

## CID layout

```
 byte 0                 1 .. 1+sid_len     1+sid_len .. cid_end
+--------+              +-----------+      +----------+
| octet0 |              | server_id |      |  nonce   |
+--------+              +-----------+      +----------+
  └─ bits 7..5: config_id (0-6)
     bits 4..0: cid_length-1, OR random (per `first_octet_encodes_cid_length`)

           [server_id || nonce]  is encrypted in place under `key`
           using the mode derived above (plaintext = no encryption).
```

Total CID length: `1 + server_id_length + nonce_length`. Values are
draft-ietf-quic-load-balancers-21 conformant. If you're reading the
draft alongside this doc, our terminology matches Section 3 + 5.

## Provisioning: ask the daemon, don't copy-paste

`pesigitg-ctl backend-config <server_id>` emits a JSON document with
exactly the fields a backend encoder needs, including the raw key when
read from a route TOML:

```sh
# Offline against the route file (key is in the output — handle as secret)
pesigitg-ctl backend-config 000001 \
    --route-config /etc/pesigitg/lb.toml

# Or against a running daemon (keys redacted server-side)
pesigitg-ctl backend-config 000001 eth0
```

During a key rollover a backend's `server_id` is in two configs at
once; the `matches` array carries one entry per config so the encoder
can mint CIDs under each. Iterate the array and configure both.

Schema is documented under `pesigitg-ctl backend-config` in `pesigitg-ctl(8)`.

## Per-stack notes

### Quinn

Rust drop-in for Quinn's EndpointConfig.

`contrib/quic-lb-cid` is a `quinn::ConnectionIdGenerator` impl. Wire it
into your `EndpointConfig`:

```rust
let gen = QuicLbCidGenerator::new(
    config_id,
    server_id_bytes,
    nonce_length,
    Encryption::SinglePass { key: aes_key },
    /* encode_cid_length = */ true,
);
endpoint_config.cid_generator(move || Box::new(gen.clone()));
```

This is the reference implementation.

Round-trip and per-mode tests live in `contrib/quic-lb-cid/src/lib.rs` and
`pesigitg-routing` shares the decoder, so a CID minted by the generator and
decoded by the LB are tested against the same byte layout.

### Nginx

Nginx's QUIC core (`src/event/quic/`) generates CIDs with `RAND_bytes`.

There is no **hook** for CID generation. Integration is a patch against the 
QUIC core, not a runtime extension.

Touchpoints:

- The function that mints the server-chosen CID for an accepted
  connection (currently around `ngx_quic_create_server_id` /
  equivalent — name has shifted across releases).
- The NEW_CONNECTION_ID emit path, so migration CIDs also follow the
  scheme.
- Config parsing for new `quic_lb_*` directives (`config_id`,
  `server_id`, `server_id_length`, `nonce_length`, `quic_lb_key`).

Practical setup:

1. Pin an Nginx version (mainline release tag, not `master`).
2. Carry the patch as a `quilt`-style series under `patches/`.
3. Build via a `make patch-nginx NGINX_VERSION=...` target so anyone
   can rebuild against a fresh tarball.
4. Encoding logic itself is ~150 lines — port from
   `contrib/quic-lb-cid/src/lib.rs` (single-pass and four-pass) or
   wrap the Rust crate as a `cdylib` and link it.

Rebase tax is the main cost: Nginx's QUIC code is still moving, so
every minor release you'll diff `src/event/quic/`.

Keeping the patch small (CID gen + config parsing, nothing else) makes
3-way merges almost always succeed cleanly.

### HAProxy

HAProxy's QUIC stack is more modular than Nginx's.

The haproxy-dev list has had QUIC-LB threads. Likely less rebase pain than
Nginx if you're picking a backend fresh. As of writing there is no upstream
support.

### lsquic / msquic / quiche

Each exposes some form of CID generation hook:

- **lsquic** — `lsquic_engine_settings.es_scid_iss_cb` lets you supply
  your own CID generator. Closest to a drop-in.
- **msquic** — connection ID generation is internal; you'd patch
  `core/connection.c`. Microsoft has discussed QUIC-LB but nothing has
  shipped publicly.
- **quiche** (Cloudflare) — `Connection::new_source_cid` is callable
  from the application, but generation policy is library-internal;
  a small fork is the realistic path.

## Validating a backend's CIDs

After wiring up the encoder, capture a real Initial from the backend
and decode it offline:

```sh
# Pull SCID from a pcap (tshark, scapy, etc.) — the long-header SCID
# field is the backend-chosen CID for the new connection.
pesigitg-ctl whoami <cid-hex> \
    --route-config /etc/pesigitg/lb.toml
```

`whoami` prints `config_id`, the resolved `server_id`, and the backend
the LB *would* route this CID to. If it resolves to your backend,
encoding is correct. If it resolves elsewhere or returns "no route",
you have one of:

- Wrong `config_id` in the encoder (top 3 bits don't match)
- Wrong `server_id` bytes (length mismatch is the most common)
- Wrong key / mode / nonce_length (decryption produces an unknown
  server_id; LB classifies as `cid_unroutable_bad_server_id` in
  `/stats` — the forgery/probing signal)

`/stats` is the live signal: a backend with broken encoding shows up
as a steady non-zero `cid_unroutable_bad_server_id` rate from the
moment it sees real traffic.

## Key rotation coordination

The LB supports running two configs at once (different `config_id`
slots) so a key rotation is a config overlap, not a flag day. Backend
side:

1. New config slot is added to the route TOML; old slot stays. Both
   contain the backend's `server_id`.
2. SIGHUP the daemon. Now both configs are live; the LB routes CIDs
   under either key.
3. Backend reconfigures its CID generator to use the **new** slot's
   `config_id` + key. Existing connections keep working — their CIDs
   were minted under the old key but the old slot is still active.
   New connections get CIDs minted under the new key.
4. After old connections have drained (watch
   `cid_by_config[old_id]` in `/stats` decay to zero), remove the old
   slot from the route TOML and SIGHUP again.

`pesigitg-ctl backend-config` returns both matches during overlap, so
backends that read provisioning at startup can detect the two-slot
window and mint under whichever they prefer.

If your backend can't reload CID-generator settings without dropping
connections, treat rotation as a rolling restart: drain one backend at
a time (`draining = true` on the LB side), rebuild it under the new
key, then un-drain.

## Common pitfalls

- **`server_id_length` mismatch.** The LB validates that each
  `[[configs.servers]] id` is exactly `server_id_length * 2` hex chars;
  a backend that mints a shorter or longer payload will look like
  garbage post-decryption. The decoder has no way to tell.
- **Plaintext mode in production.** Visible `server_id` lets clients
  pin a specific backend or correlate flows across IPs. Use it for
  bring-up only.
- **Re-using the same nonce.** The encoder must fill nonce bytes from
  a CSPRNG every time. A fixed nonce makes the encrypted payload
  deterministic, which leaks `server_id` to anyone watching.
- **Encoding `cid_length` when the LB expects random low bits** (or
  vice versa). Match `first_octet_encodes_cid_length` in
  `[[configs]]`. The LB extracts the CID length from the wire packet,
  not the first octet, so mismatches don't break routing — but they
  change the linkability properties advertised to clients.
- **Stale `config_id`.** If the LB removes a slot, every backend
  still minting under that `config_id` becomes unroutable. Use
  `pesigitg-ctl backend-config` at startup *and* on SIGHUP-equivalent
  reload, not just at install time.

## See also

- `pesigitg-lb.toml(5)` — full route-config schema
- `pesigitg-ctl(8)` — `whoami`, `backend-config` subcommands
- `SCENARIOS.md` — operator-side rollover walkthrough
- `contrib/quic-lb-cid/` — reference Quinn integration
- draft-ietf-quic-load-balancers-21 — the spec this all implements
