# Contributing to Pesigitg

Thank you for your interest in contributing to Pesigitg, a high-performance QUIC-LB load balancer. This document explains how to contribute and what is required before your contributions can be accepted.

## Contributor License Agreement (CLA)

**All contributors must sign the Contributor License Agreement before any contribution can be merged.** This is a strict requirement with no exceptions.

When you open your first pull request, the CLA Assistant bot will automatically comment with a link to review and sign the CLA. You sign by commenting on the PR — the process takes about a minute.

The CLA grants the project maintainer the right to sublicense your contributions. This is necessary because Pesigitg is available under a dual licensing model (GPLv3 and a commercial license). Without a signed CLA, your contribution cannot be accepted regardless of its quality or scope.

If you are contributing on behalf of your employer, please ensure you have authorization to sign the CLA, or have your employer execute a Corporate CLA by contacting the project maintainer directly.

## Licensing

Pesigitg is dual-licensed:

- **Open source:** GNU General Public License v3.0 or later (see `LICENSE`)
- **Commercial:** A proprietary license for organizations that prefer not to comply with GPLv3 obligations (see `LICENSE-COMMERCIAL.md`)

All contributions are accepted under these same terms via the CLA.

## Development Environment

### Prerequisites

- **Rust nightly toolchain** — pinned to a specific date in `rust-toolchain.toml`. Do not update the pin without verifying the date on Rust Forge; unpinned nightly silently breaks eBPF builds.
- **rust-src component** and **bpf-linker** — required for eBPF crate compilation.
- **Linux kernel 5.15+** — for AF_XDP and eBPF/XDP support.
- **AES-NI capable CPU** — required; there is no software fallback.
- **Target OS:** Ubuntu 24.04 LTS.

### Building

The project uses the `xtask` workspace pattern for build automation:

```sh
# build userspace daemon and eBPF program
cargo xtask build  
cargo xtask build --release
```

The eBPF crate targets `bpfel-unknown-none` and requires `-Z build-std=core`. This is handled automatically by the xtask build command.

### Running Tests

```sh
cargo test
```

### Dependency Audit

Supply-chain and license drift are checked via [cargo-deny](https://embarkstudios.github.io/cargo-deny/):

```sh
cargo install cargo-deny --locked
cargo deny check
```

The policy lives in `deny.toml`: a permissive-license allowlist compatible
with GPL-3.0-or-later, the RUSTSEC advisory database, duplicate-version
warnings, and a crates.io-only source restriction. Adding a new transitive
license requires updating the allowlist with a review note.

## How to Contribute

### Reporting Bugs

Open an issue with:

- A clear description of the problem.
- Steps to reproduce, if possible.
- Your hardware (NIC model, CPU), OS version, and kernel version.
- Relevant log output or packet captures.

### Suggesting Features

Open an issue describing the feature, its use case, and how it relates to the QUIC-LB specification (draft-ietf-quic-load-balancers-21) or operational requirements.

### Submitting Code

1. Fork the repository and create a branch from `main`.
2. Ensure your code compiles with no warnings under the pinned nightly toolchain.
3. Add or update tests for your changes.
4. Ensure all existing tests pass.
5. Every source file must include the SPDX license header (see below).
6. Open a pull request with a clear description of what the change does and why.

### SPDX License Headers

All Rust source files must begin with the following header:

```rust
// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.
```

For the eBPF crate, the header goes immediately before `#![no_std]`:

```rust
// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

#![no_std]
#![no_main]
```

### Code Style and Conventions

- Follow standard `rustfmt` formatting.
- Use `anyhow` for error handling in application code.
- Prefer minimal dependencies — propose new crate dependencies in the issue or PR description with justification.
- Use `debug_assertions` for dev-only code, not Cargo features.
- Keep tests close to the code they exercise using `#[cfg(test)] mod tests`.

### What We're Looking For

Contributions in these areas are especially welcome:

- Bug fixes and correctness improvements.
- Documentation and examples.
- Test coverage — particularly integration tests and property-based tests.
- Performance benchmarks.

### What to Avoid

- Large architectural changes without prior discussion in an issue.
- New dependencies without clear justification.
- Changes to the hot-path data plane without benchmarks showing no regression.

## Code of Conduct

Be respectful, constructive, and collaborative. 

## Questions?

Open an issue or reach out to the project maintainer directly.
