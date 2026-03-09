# Pesigitg

> *Pesigitg* /be·se·gitk/ (Mi'kmaq) — "a fork in a river"

## What

A high-performance QUIC-aware load balancer written in Rust, using eBPF and AF_XDP for kernel-bypass packet forwarding.

## Architecture

- **pesigitg-common** — `no_std`-compatible library shared across crates.
  Contains compile-time constants (`DEFAULT_PORT`, `DEFAULT_INTF`, `PID_FILE`, `MAX_CONFIG_SIZE`), the `current_pid` helper, and the `exit!` macro.
  Standard-library-dependent code is gated behind the `std` feature flag.

- **pesigitg-daemon** — The `pesigitgd` binary. Daemonizes via double-fork, manages a PID file, parses CLI arguments and an optional config file (key=value format), queries NIC hardware queue counts via ethtool ioctl, and integrates with systemd (sd_notify watchdog, `READY=1`, `RELOADING=1`).
  Handles `SIGHUP` for live config reload and `SIGTERM`/`SIGINT` for graceful shutdown. Logs to syslog when daemonized, or to stderr when running in the foreground or under systemd.

- **pesigitg-ebpf** — eBPF programs.

## Development Prerequisites

### Toolchain

| Tool | Install | Notes |
|------|---------|-------|
| Rust (stable) | `rustup toolchain install stable` | Builds `pesigitg-daemon` and `pesigitg-common` |
| Rust (nightly) | `rustup toolchain install nightly` | Required for `pesigitg-ebpf` (`-Z build-std=core`) |
| `rust-src` component | `rustup component add rust-src --toolchain nightly` | Needed to cross-compile `core` for the BPF target |
| `bpf-linker` | `cargo +nightly install bpf-linker` | Links eBPF object files; uses rustc's bundled LLVM |

### System Packages (Debian/Ubuntu)

```sh
sudo apt install \
  build-essential \
  linux-headers-generic \
  libsystemd-dev \
  pkg-config
```

| Package | Why |
|---------|-----|
| `build-essential` | C compiler and libc headers (`libc6-dev`) needed by the `libc` and `nix` crates |
| `linux-headers-generic` | Kernel headers for netlink, ethtool ioctl, and XDP structures |
| `libsystemd-dev` | Required by the `sd-notify` crate for systemd integration |
| `pkg-config` | Locates system libraries during `cargo build` |

### Runtime Requirements

- **Linux kernel 5.8+** — AF_XDP socket support
- **AES-NI** — the daemon checks for this CPU feature at startup and will refuse to run without it (Westmere / 2010+ x86_64 CPUs)
- **systemd** (recommended) — `pesigitgd` uses `Type=notify` with watchdog; see `contrib/pesigitgd.service`

### Building

```sh
# daemon (stable toolchain)
cargo build --release -p pesigitg-daemon

# ebpf program (nightly toolchain, from the ebpf crate directory)
cd pesigitg-ebpf
cargo build --release
```

## HTTPS DNS Records

HTTP DNS records (formally SVCB and HTTPS RR, defined in RFC 9460) are
recent DNS record type that lets a domain advertise connection parameters directly in DNS, before the browser even makes a TCP or QUIC connection.

### The Problem They Solve

Traditionally, connecting to a site involved a sequential chain:

DNS → TCP → TLS → HTTP response (with Alt-Svc header)

That means "this server supports HTTP/3" or "use this specific port" couldn't be discovered until deep into the connection process. HTTPS records  collapse several of those round trips by putting that metadata into DNS itself.

### How They Work

There are two types:

- SVCB (Service Binding) the generic form, usable for any scheme.
- HTTPS RR an SVCB variant for HTTPS, which is what browsers query.

An HTTPS record looks like this:

```
example.com.  300  IN  HTTPS  1 . alpn=h3,h2 ipv4hint=192.0.2.1 ipv6hint=2001:db8::1
```

- **Priority** — `1` here. Priority `0` is a special "AliasMode" that works like a CNAME for HTTPS. Any non-zero value is "ServiceMode" carrying parameters.
- **Target** — `.` means "same domain." Could point elsewhere.
- **SvcParams** — the key-value pairs carrying the useful metadata:
-- **`alpn`**— which application protocols are supported (`h3`, `h2`, `http/1.1`). This is the big one — if `h3` is listed, the browser can attempt QUIC on the first connection without waiting for Alt-Svc.
-- **`ipv4hint`** / **`ipv6hint`** — IP addresses to try, saving an additional A/AAAA lookup.
-- **`port`** — if the service runs on a non-standard port.
-- **`ech`** — Encrypted Client Hello configuration, enabling TLS encryption of the SNI field for privacy.
-- **`no-default-alpn`** — indicates the server does not support default protocols, the client must use one of the listed ALPNs.