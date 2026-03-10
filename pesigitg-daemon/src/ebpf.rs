use std::os::fd::AsRawFd;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use aya::maps::{HashMap, XskMap};
use aya::programs::{Xdp, XdpFlags};
use aya::Ebpf;
use log::{warn, info};

static EMBEDDED_EBPF: &[u8] = include_bytes!(env!("PESIGITG_EBPF_OBJ"));

/// Handle to a loaded eBPF program and its AF_XDP socket map.
///
/// Dropping this detaches the XDP program from the interface.
pub struct EbpfHandle {
    ebpf: Ebpf,
}

impl EbpfHandle {
    /// Register an AF_XDP socket for the given RX queue index.
    ///
    /// The socket must be bound to the same queue — packets arriving on
    /// a different queue will be dropped by the kernel.
    pub fn register_xsk(&mut self, queue_id: u32, socket_fd: impl AsRawFd) -> Result<()> {
        let mut xsk_map: XskMap<_> = XskMap::try_from(
            self.ebpf
                .map_mut("XSKS")
                .ok_or_else(|| anyhow!("XSKS map not found in eBPF object"))?,
        )
        .context("failed to open XSKS map")?;

        xsk_map
            .set(queue_id, socket_fd, 0)
            .with_context(|| format!("failed to register AF_XDP socket for queue {}", queue_id))?;

        info!("registered AF_XDP socket for queue {}", queue_id);
        Ok(())
    }
}

/// Loads the XDP program, attaches it to `interface`, and populates the
/// PORTS map with the configured listen ports.
///
/// In debug builds, `path` can override the embedded object for rapid
/// iteration (via `-l`). In release builds, only the embedded binary
/// built by `cargo xtask build` is used.
///
/// The returned [`EbpfHandle`] must be kept alive — dropping it
/// detaches the XDP program.
pub fn load_ebpf(path: Option<&Path>, interface: &str, ports: &[u16]) -> Result<EbpfHandle> {
    let mut ebpf = match path {
        #[cfg(debug_assertions)]
        Some(p) => {
            info!("loading eBPF object from {}", p.display());

            Ebpf::load_file(p)
                .with_context(|| format!("failed to load eBPF object from {}", p.display()))?
        }
        _ => {
            if EMBEDDED_EBPF.is_empty() {
                bail!(
                    "no embedded eBPF object; build with `cargo xtask build`"
                );
            }

            Ebpf::load(EMBEDDED_EBPF).context("failed to load embedded eBPF object")?
        }
    };

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let program: &mut Xdp = ebpf
        .program_mut("pesigitg")
        .ok_or_else(|| anyhow!("XDP program 'pesigitg' not found in eBPF object"))?
        .try_into()
        .context("'pesigitg' is not an XDP program")?;

    program.load()
        .context("failed to load XDP program")?;
    program
        .attach(interface, XdpFlags::default())
        .context("failed to attach XDP program to interface")?;

    info!("XDP program attached to '{}'", interface);

    {
        let mut port_map: HashMap<_, u16, u8> = HashMap::try_from(
            ebpf.map_mut("PORTS")
                .ok_or_else(|| anyhow!("PORTS map not found in eBPF object"))?,
        )
        .context("failed to open PORTS map")?;

        for &port in ports {
            port_map
                .insert(port, 1, 0)
                .with_context(|| format!("failed to insert port {} into PORTS map", port))?;
        }
    }

    info!("configured ports in eBPF: {:?}", ports);

    Ok(EbpfHandle { ebpf })
}
