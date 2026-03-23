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

The workspace uses [cargo-xtask](https://github.com/matklad/cargo-xtask) to
orchestrate multi-toolchain builds. No extra binaries to install — `cargo xtask`
is a regular workspace member.

```sh
# build everything (eBPF program + daemon)
cargo xtask build --release

# build only the eBPF program
cargo xtask build-ebpf --release
```

`cargo xtask build` first compiles the eBPF program with the nightly toolchain
(selected automatically via `pesigitg-ebpf/rust-toolchain.toml`), then builds
the daemon with the stable toolchain, passing the eBPF object path through the
`PESIGITG_EBPF_OBJ` environment variable.

## contrib/

Example configuration files, systemd units, and helper scripts.

| File | Description |
|------|-------------|
| `etc/lb.toml` | Example route configuration defining CID encryption parameters and server-ID-to-address mappings. Documents both single-pass AES-ECB (when `server_id_length + nonce_length = 16`) and four-pass Feistel modes. |
| `etc/enp2s0f0.conf` | Example daemon config file (`key=value` format) showing interface, port, queue count, and `route_config` pointer. |
| `etc/90-dsr.conf` | Example sysctl configuration for DSR backend ARP settings (`/etc/sysctl.d/`). |
| `etc/99-dsr-vip.yaml` | Example netplan configuration for VIP loopback addresses (`/etc/netplan/`). |
| `pesigitgd.service` | Systemd `Type=notify` unit for running a single instance of `pesigitgd`. |
| `pesigitgd@.service` | Systemd template unit for per-interface instances — `systemctl start pesigitgd@eth0` reads `/etc/pesigitg/eth0.conf` and binds the service lifetime to the network device. |
| `run.sh` | Developer convenience script. Builds and runs the daemon under `sudo` via `cargo xtask run`. Accepts a build mode (`release`/`debug`, default `release`) and interface name (default `eth0`) as positional arguments. |
| `dns-rr.sh` | Generates HTTPS DNS resource records (RFC 9460) for advertising HTTP/3 support. Supports IP hints, non-standard ports, ECH, `--value-only` output for DNS providers, and `--query` to look up existing records via `dig`. |

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
  - **`alpn`** — which application protocols are supported (`h3`, `h2`, `http/1.1`). This is the big one — if `h3` is listed, the browser can attempt QUIC on the first connection without waiting for Alt-Svc.
  - **`ipv4hint`** / **`ipv6hint`** — IP addresses to try, saving an additional A/AAAA lookup.
  - **`port`** — if the service runs on a non-standard port.
  - **`ech`** — Encrypted Client Hello configuration, enabling TLS encryption of the SNI field for privacy.
  - **`no-default-alpn`** — indicates the server does not support default protocols, the client must use one of the listed ALPNs.

## Glossary

| Acronym | Full Name | Context |
|---------|-----------|---------|
| **AES** | Advanced Encryption Standard | Block cipher used for CID encryption |
| **AES-NI** | AES New Instructions | x86 CPU instruction set for hardware-accelerated AES; required at runtime |
| **AF_XDP** | Address Family XDP | User-space socket interface to XDP for kernel-bypass packet I/O |
| **ARP** | Address Resolution Protocol | IPv4 link-layer address resolution |
| **BPF** | Berkeley Packet Filter | In-kernel packet filtering VM; see eBPF |
| **CID** | Connection ID | QUIC connection identifier used for routing decisions |
| **DCID** | Destination CID | CID carried in incoming QUIC packets; used for server lookup |
| **DNS** | Domain Name System | Name resolution; HTTPS RR / SVCB records |
| **DSR** | Direct Server Return | Load-balancing mode where replies bypass the LB |
| **eBPF** | extended BPF | In-kernel virtual machine running the XDP packet-processing programs |
| **ECB** | Electronic Code Book | AES block cipher mode used in the Feistel-based CID encryption |
| **ECH** | Encrypted Client Hello | TLS extension that encrypts the SNI field for privacy |
| **ECMP** | Equal-Cost Multi-Path | Routing strategy that distributes flows across multiple next hops |
| **ICMP** | Internet Control Message Protocol | Error and diagnostic messages for IPv4 |
| **ICMPv6** | ICMP for IPv6 | Error and diagnostic messages for IPv6 |
| **IP** | Internet Protocol | Network-layer protocol; both v4 and v6 |
| **L2** | Layer 2 | Data link layer (Ethernet frames, MAC addresses) |
| **L3** | Layer 3 | Network layer (IP packets) |
| **LLVM** | Low Level Virtual Machine | Compiler infrastructure; used by `bpf-linker` for eBPF object files |
| **MAC** | Media Access Control | 48-bit hardware address on Ethernet interfaces |
| **MTU** | Maximum Transmission Unit | Largest packet size a link can carry |
| **NAT** | Network Address Translation | Client address/port rewriting; QUIC CID routing survives NAT rebinding |
| **NDP** | Neighbor Discovery Protocol | IPv6 link-layer address resolution (equivalent of ARP) |
| **NIC** | Network Interface Card | Physical or virtual network interface |
| **NUMA** | Non-Uniform Memory Access | CPU/memory topology; used for socket-aware thread placement |
| **PID** | Process ID | Unix process identifier; managed via PID file |
| **QUIC** | Quick UDP Internet Connections | UDP-based transport protocol; the primary protocol being load-balanced |
| **QUIC-LB** | QUIC Load Balancing | Specification for CID-based QUIC-aware load balancing |
| **RSS** | Receive Side Scaling | NIC feature that distributes incoming packets across hardware queues |
| **RTT** | Round Trip Time | Network latency measurement |
| **RX** | Receive | Incoming packet direction / receive queues |
| **SCID** | Source Connection ID | CID chosen by the server; encodes routing information |
| **SIGHUP** | Signal Hang Up | Unix signal used to trigger live config reload |
| **SIGINT** | Signal Interrupt | Unix signal sent by Ctrl+C |
| **SIGTERM** | Signal Terminate | Unix signal for graceful shutdown |
| **SNI** | Server Name Indication | TLS extension carrying the target hostname |
| **TLS** | Transport Layer Security | Cryptographic protocol layered over TCP (or built into QUIC) |
| **TTL** | Time To Live | IPv4 header field limiting packet lifetime (hop count) |
| **TX** | Transmit | Outgoing packet direction / transmit queues |
| **UMEM** | User Memory | Shared memory region for AF_XDP packet buffers |
| **VIP** | Virtual IP | Frontend IP address exposed to clients by the load balancer |
| **XDP** | eXpress Data Path | Linux kernel hook for early, high-performance packet processing |
