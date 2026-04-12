# Config / key rollover

The routing config (`/etc/pesigitg/lb.toml`) supports up to **7 simultaneous configurations** (`config_id` 0-6), and the `config_id` is encoded in the top 3 bits of every CID's first octet. That's the whole mechanism: rollover means *running two configs at once* until traffic migrates off the old one.

Reloads are signal-driven — the daemon doesn't restart, it re-parses the file on SIGHUP and atomically swaps the `RwLock<ConfigTable>`. In-flight connections are unaffected.

## Operator toolbox

```sh
# Reload route config (preferred — via systemd)
sudo systemctl reload pesigitgd

# Or directly
sudo kill -HUP $(cat /run/pesigitgd.pid)

# Dump live stats to journal
sudo kill -USR1 $(cat /run/pesigitgd.pid)

# Watch for reload confirmation + drain events
journalctl -u pesigitgd -f
```

Key journal lines to watch for:

- `route config reloaded: /etc/pesigitg/lb.toml` — SIGHUP accepted
- `config table (N active):` — followed by a Display dump of every slot
- `server X is draining (config_id=N)` — confirms drain flag applied
- `all draining servers fully drained — safe to remove from config` — fires once `draining_forwarded` drops to 0
- `X is back up` / `X is down` — health probe transitions

---

## Scenario 1: AES key rotation (most common)

You **cannot** rewrite `key = "..."` under the same `config_id`. Existing CIDs were encrypted with the old key; swapping keys in place breaks every in-flight connection. Instead:

**Step 1 — Start state.** `config_id = 0`, key `K_old`, backends X/Y/Z:

```toml
[[configs]]
config_id = 0
server_id_length = 3
nonce_length = 13
key = "597a84b3093ebb17567bcb7e06721d68"

[[configs.servers]]
id = "000001"
address = "10.0.1.10"
# … etc
```

**Step 2 — Add a second config** (`config_id = 1`, new key, same server IDs/addresses):

```toml
[[configs]]
config_id = 1
server_id_length = 3
nonce_length = 13
key = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"

[[configs.servers]]
id = "000001"
address = "10.0.1.10"
# … same set as config_id 0
```

```sh
sudo systemctl reload pesigitgd
journalctl -u pesigitgd -n 50 | grep -A1 "route config reloaded"
```

Expect `config table (2 active):` in the dump.

**Step 3 — Roll `K_new` out to the backends.** Each backend needs the new key *and* must start minting CIDs that encode `config_id = 1` in the first octet. That handoff is backend-side (your QUIC stack's QUIC-LB integration); the LB is now ready to route both.

**Step 4 — Drain `config_id = 0`.** Mark every server under `config_id = 0` as `draining = true` (leave the `config_id = 1` block untouched):

```toml
[[configs]]
config_id = 0
# ... same keys, same servers, but:
[[configs.servers]]
id = "000001"
address = "10.0.1.10"
draining = true
```

```sh
sudo systemctl reload pesigitgd
```

Existing CID-routed flows under `config_id = 0` keep working; no new fallback connections land there. Watch:

```sh
journalctl -u pesigitgd -f | grep -E "draining|drained"
```

When you see `all draining servers fully drained — safe to remove from config`, all old-key flows are gone.

**Step 5 — Remove the `config_id = 0` block entirely,** SIGHUP one more time. Rollover complete.

---

## Scenario 2: Adding / removing a backend

No key change needed — just edit `[[configs.servers]]` and reload.

- **Adding**: append a new server entry, SIGHUP. It starts `healthy = false`; the next health probe (up to 5 s) flips it, which triggers `rebuild_fallback_servers()` automatically. No operator action beyond the SIGHUP.
- **Removing gracefully**: first mark it `draining = true`, SIGHUP, wait for the drain-complete log line, then delete the entry and SIGHUP again.
- **Removing hard** (e.g., host is already dead): delete and SIGHUP. Health probes will have marked it down already; any stale CIDs pointing at it will miss and hit the fallback path.

---

## Scenario 3: Changing `server_id_length` / `nonce_length` / cipher mode

These are wire-format changes — same problem as keys. Add a second `config_id` with the new parameters, migrate backends onto it, drain the old, remove. Identical flow to Scenario 1.

---

## Gotchas

- **7-slot limit.** If all 7 `config_id`s are already in use, you can't start a new rollover until one is retired. In practice you'll only ever have 2 active mid-rollover.
- **Validation errors don't kill the daemon.** A bad `lb.toml` logs `failed to reload route config: …; keeping current settings` — the old config stays live. Always `journalctl -u pesigitgd -n 20` after a SIGHUP to confirm the new one landed.
- **Don't `systemctl restart`.** That tears down XDP, drops the socket, and breaks every flow. SIGHUP is the correct verb.
- **Key material lives in `lb.toml`.** Make sure the file is `chmod 600 root:root` (or equivalent) — a 128-bit AES key sitting world-readable in `/etc/` defeats the point of rotating it.
- **Backend cutover is the slow part.** The LB reload is instant; waiting for your backend fleet to start minting CIDs under the new `config_id` is where the rollover actually spends its time.

---

# QUIC Retry rollout

The `[retry]` section in `lb.toml` offloads QUIC address validation to the LB. Under a spoofed-source Initial flood the LB absorbs the blast; backends never see unvalidated connection attempts.

Retry is **no-shared-state**: the LB signs HMAC-SHA256 tokens over `(client_ip, timestamp, ODCID)`. Backends don't need to know the key — they trust any Initial that reaches them.

## Staged rollout procedure

### Step 1 — Ship disabled (default)

Deploy a `pesigitgd` build that includes the Retry code with no changes to `lb.toml`. The `[retry]` section is absent, so the datapath never enters the Retry path — zero hot-path cost.

### Step 2 — Observe mode, one port

Generate a 32-byte key:

```sh
openssl rand -hex 32
```

Add to `lb.toml`:

```toml
[retry]
enabled = true
token_key = "<64 hex chars from above>"
mode = "observe"
ports = [443]
```

```sh
sudo systemctl reload pesigitgd
```

Observe mode runs the full classify path — parse, token verify, mode decision — and advances `retry_*` counters, but **never emits a Retry**. This lets you validate the parser against real traffic.

Watch the counters:

```sh
sudo kill -USR1 $(cat /run/pesigitgd.pid)
journalctl -u pesigitgd -n 5 | grep retry
```

Expected output:

```
retry(seen=N issued=0 valid=0 invalid=0 expired=0 parse_err=0)
```

**Gate**: `retry_parse_error` must be near zero for at least a week before proceeding. Non-zero `parse_err` means the Initial parser is rejecting traffic that might be valid — investigate before enforcing.

### Step 3 — Always mode

Once `parse_err` is confirmed stable:

```toml
[retry]
enabled = true
token_key = "<same key>"
mode = "always"
ports = [443]
```

```sh
sudo systemctl reload pesigitgd
```

Every Initial on port 443 without a valid token now gets a Retry. Watch:

- `retry_issued` climbs (normal)
- `retry_token_validated` climbs as returning clients present valid tokens
- Handshake success rates via your backend monitoring — any regression means something is wrong

### Step 4 — Expand to remaining ports

Repeat Step 2-3 per port, or remove the `ports` filter to apply globally:

```toml
[retry]
enabled = true
token_key = "<same key>"
mode = "always"
```

### Step 5 — (Future) Switch to load-triggered mode

Once stable at 100%, switch to `mode = "load"` with a conservative `trigger_rate`:

```toml
[retry]
enabled = true
token_key = "<same key>"
mode = "load"

[retry.load]
trigger_rate = 50000
```

Normal traffic flows without Retry overhead; only floods above 50K initials/sec activate enforcement. *(Load mode is not yet implemented — currently degrades to observe.)*

### Kill switch

Instant rollback at any step:

```toml
[retry]
enabled = false
```

```sh
sudo systemctl reload pesigitgd
```

No XDP teardown, no flow disruption — pure forwarding resumes immediately.

## Token key rotation

Token keys live in `lb.toml` alongside the CID encryption keys and should be rotated on the same cadence. Unlike CID keys, Retry token keys **do not** require a two-config overlap: a mid-handshake key rotation simply invalidates in-flight tokens. The client retries the Initial, gets a fresh token signed with the new key, and completes normally. The worst case is one extra RTT for connections that happened to be mid-Retry when the SIGHUP landed.

```sh
# Generate new key
NEW_KEY=$(openssl rand -hex 32)

# Edit lb.toml: replace token_key value
sudo systemctl reload pesigitgd

# Verify
journalctl -u pesigitgd -n 10 | grep "route config reloaded"
```

The old key is gone immediately — `retry_token_invalid` may tick up briefly as stale tokens are rejected and re-issued. This is benign and self-resolving.

## Gotchas

- **`token_key` is 32 bytes (64 hex), not 16.** The CID `key` is 16-byte AES; the Retry `token_key` is 32-byte HMAC-SHA256. Don't mix them up.
- **Observe mode is the safety net.** Never skip it. The `parse_err` counter is the "don't flip this on yet" signal.
- **`token_lifetime_secs` default is 10.** Raise it if your clients are behind lossy links with >10s retransmit delays. Lower it if you want tighter replay protection. Must be 1-3600.
- **IPv6 extension headers are rejected.** The Retry path only handles plain IPv4 and IPv6 (next header = UDP). Packets with extension headers fall through to the normal CID path without being classified.
- **Key material lives in `lb.toml`.** Same `chmod 600 root:root` advice as for CID keys.
