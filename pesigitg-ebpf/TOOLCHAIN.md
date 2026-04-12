# eBPF nightly toolchain policy

`pesigitg-ebpf` is pinned to a specific nightly in `rust-toolchain.toml`. This
document describes when and how to bump it.

## Cadence

**Bump monthly, not weekly, and never on autopilot.**

The eBPF target (`bpfel-unknown-none`) is still an unstable tier and nightly
breakage here is frequent — `build-std` + `rust-src` + aya's inline-asm usage
all have regressions land without warning. Chasing every nightly buys you
nothing and burns a CI afternoon every time something breaks.

### Regular bump

- **First Monday of the month**, try the latest nightly in a branch.
- Update `pesigitg-ebpf/rust-toolchain.toml`:
  ```toml
  [toolchain]
  channel = "nightly-YYYY-MM-DD"
  components = ["rust-src"]
  ```
- Run the full eBPF build (`cargo xtask` / whatever builds the eBPF object) and
  smoke-test with a loaded program attached to the XDP hook.
- If green, commit the pin bump. If red, stay put and try again in two weeks.

### Out-of-cycle bumps

Only bump outside the monthly window when there's a concrete reason:

- An `aya` / `aya-ebpf` release notes a minimum nightly.
- A specific compiler fix you actually need has landed.
- The current pin is **>60 days old** — security fixes start mattering.

## Rules

- **Never float the pin.** `channel = "nightly"` with no date breaks
  reproducibility — every contributor and CI run gets a different compiler.
  Always pin to a dated nightly.
- **Keep `rust-src` in `components`.** `build-std` needs it to rebuild `core`
  for the bpf target.
- **The workspace toolchain and the eBPF toolchain are independent.** The rest
  of the workspace tracks stable; only `pesigitg-ebpf/` overrides to nightly.
  Don't conflate them.
- **Pin bumps are their own commit** — never mix a toolchain bump with
  unrelated code changes. If the bump breaks something two weeks later, you
  want `git bisect` / `jj bisect` to land directly on the pin change.

## Tradeoffs

Monthly means you occasionally hit a multi-month-old regression that was fixed
two weeks after your pin, but the stability is worth it.
