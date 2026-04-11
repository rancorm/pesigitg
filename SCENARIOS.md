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
