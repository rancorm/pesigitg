# Pesigitg

> *Pesigitg* /be·se·gitk/ (Mi'kmaq) — "a fork in a river"

## What

A high-performance QUIC-aware load balancer written in Rust, using eBPF and AF_XDP for kernel-bypass packet forwarding.

I brainstorm this idea with Claude Projects (RFCs, project configs, snippets, etc.) to avoid 
the cold start problem when returning to an idea or concept and having to start over,
grounding the answers to internal project knowledge.

This is an implementation of those concepts with the help of Claude Code. 

### Essentials

- Small code size
- Least amount of dependencies
- Single programming language
- Few items as possible to release
- Behave like a traditional UNIX tool
- Documentation for project and code history

### Knowledge

QUIC & HTTP/3 related RFCs and drafts.

#### Core QUIC
- [RFC 9000: QUIC – A UDP-Based Multiplexed and Secure Transport](https://www.rfc-editor.org/rfc/rfc9000)
- [RFC 9001: Using TLS to Secure QUIC](https://www.rfc-editor.org/rfc/rfc9001)
- [RFC 9002: QUIC Loss Detection and Congestion Control](https://www.rfc-editor.org/rfc/rfc9002)
- [RFC 8999: Version-Independent Properties of QUIC](https://www.rfc-editor.org/rfc/rfc8999)

#### HTTP/3
- [RFC 9114: HTTP/3](https://www.rfc-editor.org/rfc/rfc9114)

#### QUIC Extensions
- [RFC 9221: QUIC DATAGRAM Extension](https://www.rfc-editor.org/rfc/rfc9221)

#### MASQUE & Proxying
- [RFC 9308: Generic UDP Proxying (MASQUE)](https://www.rfc-editor.org/rfc/rfc9308)
- [RFC 9312: CONNECT-UDP (QUIC-based proxying)](https://www.rfc-editor.org/rfc/rfc9312)

#### HTTP Datagrams
- [RFC 9368: HTTP Datagrams and Capsule Protocol](https://www.rfc-editor.org/rfc/rfc9368)

#### DNS over QUIC & HTTP/3
- [RFC 9250: DNS over Dedicated QUIC Connections (DoQ)](https://www.rfc-editor.org/rfc/rfc9250)
- [RFC 9369: DNS over HTTP/3 (DoH3)](https://www.rfc-editor.org/rfc/rfc9369)
- [RFC 9460: SVCB and HTTPS DNS Resource Records](https://www.rfc-editor.org/rfc/rfc9460)

#### Web Enhancements
- [RFC 9443: Bootstrapping WebSockets with HTTP/3](https://www.rfc-editor.org/rfc/rfc9443)

#### Drafts
- [QUIC-LB: Load Balancers for QUIC](https://datatracker.ietf.org/doc/draft-ietf-quic-load-balancers/)
- [QUIC Retry Offload](https://datatracker.ietf.org/doc/draft-ietf-quic-retry-offload/)

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
  libelf-dev \
  libsystemd-dev \
  linux-headers-generic \
  pkg-config \
  rustup \
  zlib1g-dev
```

| Package | Why |
|---------|-----|
| `build-essential` | C compiler, `make`, and libc headers (`libc6-dev`) needed by the `libc` and `nix` crates and the vendored libbpf build |
| `libelf-dev` | ELF library headers required by the vendored libbpf build (`libbpf-sys`) |
| `libsystemd-dev` | Required by the `sd-notify` crate for systemd integration |
| `linux-headers-generic` | Kernel headers for netlink, ethtool ioctl, and XDP structures |
| `pkg-config` | Locates system libraries (`libelf`, `zlib`, `libsystemd`) during `cargo build` |
| `rustup` | Rust toolchain manager; provides `rustup`, `cargo`, and `rustc` |
| `zlib1g-dev` | Compression library required by the vendored libbpf build (`libbpf-sys`) |

### Runtime Requirements

- **Linux kernel 5.8+** — AF_XDP socket support
- **AES-NI** — the daemon checks for this CPU feature at startup and will refuse to run without it (Westmere / 2010+ x86_64 CPUs)
- **systemd** (recommended) — `pesigitgd` uses `Type=notify` with watchdog; see `contrib/etc/systemd/system/pesigitgd.service`

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

## Network Configuration

Pesigitg uses Direct Server Return (DSR): the load balancer forwards packets to
backends by rewriting only the L2, the destination IP stays as the VIP. Backends
respond directly to clients, bypassing the LB on the return path.

Both the load balancer and the backend servers require ARP tuning to prevent
Linux's default ARP behaviour ("ARP flux") from misdirecting traffic.

### Load Balancer — management interface ARP

When the LB host has a management interface (e.g. `eth0`) in addition to the
data-plane interface where XDP is attached, the kernel will, by default, answer
ARP requests for the VIP on **every** interface — including the management NIC.
The upstream router then caches the management interface's MAC for the VIP and
sends traffic there. Because XDP only runs on the data-plane interface, these
packets hit the kernel stack instead and are never forwarded to backends.

Set `arp_ignore=1` on the management interface so ARP for the VIP is only
answered on the data-plane NIC:

```sh
# apply immediately (replace eth0 with your management interface)
sudo sysctl -w net.ipv4.conf.eth0.arp_ignore=1
sudo sysctl -w net.ipv4.conf.eth0.arp_announce=2

# persist across reboots (see contrib/etc/sysctl.d/90-dsr.conf)
sudo cp contrib/etc/sysctl.d/90-dsr.conf /etc/sysctl.d/
sudo sysctl --system
```

### Backends — suppress ARP for the VIP

Backend servers need the VIP on loopback to accept DSR packets. Without ARP
suppression the backend answers ARP for the VIP on its physical NIC, the
upstream router learns the backend's MAC for the VIP, and traffic bypasses the
load balancer entirely.

```sh
# bind the VIP to loopback (see contrib/etc/netplan/99-dsr-vip.yaml)
sudo ip addr add 198.51.100.1/32 dev lo

# suppress ARP
sudo sysctl -w net.ipv4.conf.all.arp_ignore=1
sudo sysctl -w net.ipv4.conf.all.arp_announce=2
```

### Sysctl reference

| Sysctl | Effect |
|--------|--------|
| `arp_ignore=1` | Only reply to ARP when the target IP is configured on the *incoming* interface. |
| `arp_announce=2` | Use the best local address for the *outgoing* interface as the ARP source, preventing the VIP from leaking into upstream ARP caches. |

Per-interface knobs (e.g. `net.ipv4.conf.eth0.arp_ignore`) work too — Linux
takes the maximum of `conf.all` and `conf.<iface>`.  Use per-interface settings
on the LB to leave the data-plane interface's ARP behaviour untouched; use
`conf.all` on backends where every interface should be suppressed.

## contrib/

Example configuration files, systemd units, and helper scripts.

| File | Description |
|------|-------------|
| `etc/pesigitg/lb.toml` | Example route configuration defining CID encryption parameters and server-ID-to-address mappings. Documents both single-pass AES-ECB (when `server_id_length + nonce_length = 16`) and four-pass Feistel modes. |
| `etc/pesigitg/enp2s0f0.conf` | Example daemon config file (`key=value` format) showing interface, port, queue count, and `route_config` pointer. |
| `etc/sysctl.d/90-dsr.conf` | Sysctl ARP settings for DSR (load balancer and backends). |
| `etc/sysctl.d/90-lb.conf` | Sysctl ARP settings for the load balancer management interface. |
| `etc/netplan/99-dsr-vip.yaml` | Netplan configuration for VIP loopback addresses. |
| `etc/systemd/system/pesigitgd.service` | Systemd `Type=notify` unit for running a single instance of `pesigitgd`. |
| `etc/systemd/system/pesigitgd@.service` | Systemd template unit for per-interface instances — `systemctl start pesigitgd@eth0` reads `/etc/pesigitg/eth0.conf` and binds the service lifetime to the network device. |
| `run.sh` | Developer convenience script. Builds and runs the daemon under `sudo` via `cargo xtask run`. Accepts a build mode (`release`/`debug`, default `release`) and interface name (default `eth0`) as positional arguments. |
| `dns-rr.sh` | Generates HTTPS DNS resource records (RFC 9460) for advertising HTTP/3 support. Supports IP hints, non-standard ports, ECH, `--value-only` output for DNS providers, and `--query` to look up existing records via `dig`. |
| `dsr-backend.sh` | Installs/removes DSR backend configuration (sysctl + netplan VIPs) on a backend server. |

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
