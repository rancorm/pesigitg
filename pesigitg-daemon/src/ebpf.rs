// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

//! XDP program and eBPF map lifecycle, with bpffs pinning support for
//! zero-drop restart (phase 1 of the thursday-toil plan).
//!
//! Pin layout under `/sys/fs/bpf/pesigitg/<interface>/`:
//!   - `XSKS`   — AF_XDP socket map
//!   - `PORTS`  — listening-port set
//!   - `link`   — FdLink keeping the XDP program attached
//!
//! On startup, `load_ebpf()` adopts an existing install if the link pin is
//! present; otherwise it cold-boots and pins everything. On Drop, a cold
//! shutdown unpins so the program detaches; a handoff shutdown (see
//! [`EbpfHandle::set_handoff`]) leaves the pins in place so the next
//! daemon invocation adopts them.

use std::collections::HashSet;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail};
use aya::maps::{HashMap, Map, MapData, XskMap};
use aya::programs::links::{FdLink, PinnedLink};
use aya::programs::{Xdp, XdpFlags};
use aya::EbpfLoader;
use log::{debug, info, warn};

/// Force 8-byte alignment for the embedded eBPF ELF object.
/// `include_bytes!` does not guarantee alignment, but the ELF parser requires it.
#[repr(C, align(8))]
struct Aligned<T: ?Sized>(T);

static ALIGNED_EBPF: &Aligned<[u8]> = &Aligned(*include_bytes!(env!("PESIGITG_EBPF_OBJ")));
static EMBEDDED_EBPF: &[u8] = &ALIGNED_EBPF.0;

const PIN_ROOT: &str = "/sys/fs/bpf/pesigitg";
const LINK_PIN_NAME: &str = "link";
const XSKS_MAP_NAME: &str = "XSKS";
const PORTS_MAP_NAME: &str = "PORTS";

fn pin_root_for(interface: &str) -> PathBuf {
    Path::new(PIN_ROOT).join(interface)
}

/// Handle to the live eBPF state — XSKS and PORTS maps (as owned
/// [`MapData`]) and the [`PinnedLink`] that keeps the XDP program
/// attached. Shape is identical across cold-boot and adopt, so the rest
/// of the daemon doesn't care which path constructed it.
pub struct EbpfHandle {
    xsks: Map,
    ports: Map,
    _link: PinnedLink,
    pin_root: PathBuf,
    handoff: bool,
}

impl EbpfHandle {
    /// Register an AF_XDP socket for the given RX queue index.
    ///
    /// The socket must be bound to the same queue — packets arriving on
    /// a different queue will be dropped by the kernel.
    pub fn register_xsk(&mut self, queue_id: u32, socket_fd: impl AsRawFd) -> Result<()> {
        let mut xsk_map: XskMap<_> = XskMap::try_from(&mut self.xsks)
            .context("failed to wrap XSKS map as XskMap")?;

        xsk_map
            .set(queue_id, socket_fd, 0)
            .with_context(|| format!("failed to register AF_XDP socket for queue {}", queue_id))?;

        info!("registered AF_XDP socket for queue {}", queue_id);
        Ok(())
    }

    /// Mark this shutdown as a handoff: pins stay in bpffs so the next
    /// daemon invocation adopts the running program and maps. Without
    /// this call, Drop unpins everything (cold shutdown).
    pub fn set_handoff(&mut self) {
        self.handoff = true;
    }
}

impl Drop for EbpfHandle {
    fn drop(&mut self) {
        if self.handoff {
            debug!("handoff shutdown: leaving pins at {}", self.pin_root.display());
            return;
        }

        // Cold shutdown: remove pins so the program detaches and maps are freed.
        // The PinnedLink's underlying FD will close when this struct drops;
        // removing the pin file is what actually detaches.
        for name in [LINK_PIN_NAME, XSKS_MAP_NAME, PORTS_MAP_NAME] {
            let path = self.pin_root.join(name);
            if let Err(e) = std::fs::remove_file(&path) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    warn!("failed to unpin {}: {}", path.display(), e);
                }
            }
        }
        // Best-effort rmdir — leaves the parent directory untouched.
        let _ = std::fs::remove_dir(&self.pin_root);
    }
}

/// Load the XDP program and register the listening ports, adopting any
/// existing pinned install if the link pin is present.
///
/// In debug builds `path` can override the embedded object for rapid
/// iteration (via `-l`). Ignored on the adopt path, since the in-kernel
/// program is not re-loaded.
pub fn load_ebpf(path: Option<&Path>, interface: &str, ports: &[u16]) -> Result<EbpfHandle> {
    let pin_root = pin_root_for(interface);
    let link_pin = pin_root.join(LINK_PIN_NAME);

    if link_pin.exists() {
        match adopt_ebpf(&pin_root, ports) {
            Ok(handle) => return Ok(handle),
            Err(e) => {
                warn!(
                    "failed to adopt pinned eBPF install at {} ({}); falling back to cold boot",
                    pin_root.display(),
                    e
                );
                clear_stale_pins(&pin_root);
            }
        }
    }

    cold_boot_ebpf(path, interface, ports, &pin_root)
}

/// Cold-boot path: load + attach + pin everything from scratch.
fn cold_boot_ebpf(
    path: Option<&Path>,
    interface: &str,
    ports: &[u16],
    pin_root: &Path,
) -> Result<EbpfHandle> {
    let load_start = Instant::now();

    std::fs::create_dir_all(pin_root)
        .with_context(|| format!("failed to create pin root {}", pin_root.display()))?;

    let mut loader = EbpfLoader::new();
    loader.map_pin_path(pin_root);

    let mut ebpf = match path {
        #[cfg(debug_assertions)]
        Some(p) => {
            info!("loading eBPF object from {}", p.display());

            loader
                .load_file(p)
                .with_context(|| format!("failed to load eBPF object from {}", p.display()))?
        }
        _ => {
            if EMBEDDED_EBPF.is_empty() {
                bail!("no embedded eBPF object; build with `cargo xtask build`");
            }

            loader
                .load(EMBEDDED_EBPF)
                .context("failed to load embedded eBPF object")?
        }
    };

    debug!("eBPF object parsed in {:.2?}", load_start.elapsed());

    let program: &mut Xdp = ebpf
        .program_mut("pesigitg")
        .ok_or_else(|| anyhow!("XDP program 'pesigitg' not found in eBPF object"))?
        .try_into()
        .context("'pesigitg' is not an XDP program")?;

    let attach_start = Instant::now();
    program.load().context("failed to load XDP program")?;
    let link_id = program
        .attach(interface, XdpFlags::DRV_MODE)
        .context("failed to attach XDP program to interface")?;

    info!("XDP program attached to '{}'", interface);
    debug!("XDP program load+attach took {:.2?}", attach_start.elapsed());

    // Pin the link so the program stays attached across daemon exit
    // (until a cold shutdown explicitly unpins).
    let owned_link = program
        .take_link(link_id)
        .context("failed to take ownership of XDP link")?;
    let fd_link: FdLink = FdLink::try_from(owned_link)
        .context("XDP link is not an FdLink (kernel too old for bpf_link_create?)")?;
    let link_pin_path = pin_root.join(LINK_PIN_NAME);
    let pinned = fd_link
        .pin(&link_pin_path)
        .with_context(|| format!("failed to pin XDP link at {}", link_pin_path.display()))?;

    // Take ownership of the maps so our handle has the same shape
    // across cold-boot and adopt. Dropping `ebpf` afterwards is safe
    // because the pinned link keeps the program (and by extension the
    // maps) alive in the kernel.
    let xsks = ebpf
        .take_map(XSKS_MAP_NAME)
        .ok_or_else(|| anyhow!("{} map not found in eBPF object", XSKS_MAP_NAME))?;
    let ports_map = ebpf
        .take_map(PORTS_MAP_NAME)
        .ok_or_else(|| anyhow!("{} map not found in eBPF object", PORTS_MAP_NAME))?;

    let mut handle = EbpfHandle {
        xsks,
        ports: ports_map,
        _link: pinned,
        pin_root: pin_root.to_path_buf(),
        handoff: false,
    };

    reconcile_ports(&mut handle.ports, ports)?;
    info!("configured ports in eBPF: {:?}", ports);

    Ok(handle)
}

/// Adopt path: open existing pins, skip program load/attach, reconcile PORTS.
fn adopt_ebpf(pin_root: &Path, ports: &[u16]) -> Result<EbpfHandle> {
    info!("adopting pinned eBPF install at {}", pin_root.display());

    let link_pin_path = pin_root.join(LINK_PIN_NAME);
    let pinned = PinnedLink::from_pin(&link_pin_path)
        .with_context(|| format!("failed to open link pin at {}", link_pin_path.display()))?;

    let xsks_data = MapData::from_pin(pin_root.join(XSKS_MAP_NAME))
        .context("failed to open XSKS map pin")?;
    let ports_data = MapData::from_pin(pin_root.join(PORTS_MAP_NAME))
        .context("failed to open PORTS map pin")?;

    let mut handle = EbpfHandle {
        xsks: Map::XskMap(xsks_data),
        ports: Map::HashMap(ports_data),
        _link: pinned,
        pin_root: pin_root.to_path_buf(),
        handoff: false,
    };

    reconcile_ports(&mut handle.ports, ports)?;
    info!("adopted eBPF install; reconciled ports: {:?}", ports);

    Ok(handle)
}

/// Ensure the PORTS map contains exactly `configured` — insert missing,
/// remove stale. Invariant for cold-boot (map is empty) and adopt (map
/// may carry entries from a previous generation).
fn reconcile_ports(ports_map: &mut Map, configured: &[u16]) -> Result<()> {
    let mut port_map: HashMap<_, u16, u8> = HashMap::try_from(ports_map)
        .context("failed to wrap PORTS map as HashMap")?;

    let configured_set: HashSet<u16> = configured.iter().copied().collect();

    let live: HashSet<u16> = port_map
        .keys()
        .filter_map(|k| k.ok())
        .collect();

    for port in live.difference(&configured_set) {
        port_map
            .remove(port)
            .with_context(|| format!("failed to remove stale port {} from PORTS map", port))?;
        debug!("reconciled PORTS: removed {}", port);
    }

    for port in configured_set.difference(&live) {
        port_map
            .insert(port, 1, 0)
            .with_context(|| format!("failed to insert port {} into PORTS map", port))?;
        debug!("reconciled PORTS: inserted {}", port);
    }

    Ok(())
}

/// Remove any leftover pins under `pin_root`. Called on adopt failure
/// so the cold-boot path has a clean slate.
fn clear_stale_pins(pin_root: &Path) {
    for name in [LINK_PIN_NAME, XSKS_MAP_NAME, PORTS_MAP_NAME] {
        let path = pin_root.join(name);
        if let Err(e) = std::fs::remove_file(&path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                warn!("failed to clear stale pin {}: {}", path.display(), e);
            }
        }
    }
}
