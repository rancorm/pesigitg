use std::path::Path;

use anyhow::{anyhow, Context, Result};
use aya::maps::HashMap;
use aya::programs::{Xdp, XdpFlags};
use aya::Ebpf;
use log::info;

/// Loads the XDP program from `path`, attaches it to `interface`, and
/// populates the PORTS map with the configured listen ports.
///
/// The returned [`Ebpf`] handle must be kept alive — dropping it
/// detaches the XDP program.
pub fn load_ebpf(path: &Path, interface: &str, ports: &[u16]) -> Result<Ebpf> {
    let mut ebpf = Ebpf::load_file(path)
        .with_context(|| format!("failed to load eBPF object from {}", path.display()))?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        log::warn!("failed to initialize eBPF logger: {}", e);
    }

    let program: &mut Xdp = ebpf
        .program_mut("pesigitg")
        .ok_or_else(|| anyhow!("XDP program 'pesigitg' not found in eBPF object"))?
        .try_into()
        .context("'pesigitg' is not an XDP program")?;

    program.load().context("failed to load XDP program")?;
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

    Ok(ebpf)
}
