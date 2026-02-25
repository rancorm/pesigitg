# Pesigitg

> *Pesigitg* /be·se·gitk/ (Mi'kmaq) — "a fork in a river"

## What

A high-performance QUIC-aware load balancer written in Rust, using eBPF and
AF_XDP for kernel-bypass packet forwarding.

## Architecture

- **pesigitg-common** — `no_std`-compatible library shared across crates.
  Contains compile-time constants (`DEFAULT_PORT`, `DEFAULT_INTF`, `PID_FILE`,
  `MAX_CONFIG_SIZE`), the `current_pid` helper, and the `exit!` macro.
  Standard-library-dependent code is gated behind the `std` feature flag.

- **pesigitg-daemon** — The `pesigitgd` binary. Daemonizes via double-fork,
  manages a PID file, parses CLI arguments and an optional config file
  (key=value format), queries NIC hardware queue counts via ethtool ioctl,
  and integrates with systemd (sd_notify watchdog, `READY=1`, `RELOADING=1`).
  Handles `SIGHUP` for live config reload and `SIGTERM`/`SIGINT` for graceful
  shutdown. Logs to syslog when daemonized, or to stderr when running in the
  foreground or under systemd.

- **pesigitg-ebpf** — eBPF programs.
