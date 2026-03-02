use std::ffi::CString;
use libc::{ioctl, socket, AF_INET, SOCK_DGRAM, c_char};

use crate::utils::num_cores;

const ETHTOOL_GCHANNELS: u32 = 0x0000003c;
const SIOCETHTOOL: libc::c_ulong = 0x8946;

#[repr(C)]
struct EthtoolChannels {
    cmd: u32,
    max_rx: u32,
    max_tx: u32,
    max_other: u32,
    max_combined: u32,
    rx_count: u32,
    tx_count: u32,
    other_count: u32,
    combined_count: u32,
}

#[repr(C)]
struct Ifreq {
    ifr_name: [c_char; 16],
    ifr_data: *mut EthtoolChannels,
}

pub struct ThreadConfig {
    pub queue_id: u32,
    pub core_id: usize,
}

pub fn get_hw_queues(interface: &str) -> std::io::Result<(u32, u32)> {
    let fd = unsafe { socket(AF_INET, SOCK_DGRAM, 0) };

    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut channels = EthtoolChannels {
        cmd: ETHTOOL_GCHANNELS,
        ..unsafe { std::mem::zeroed() }
    };

    let mut ifr: Ifreq = unsafe { std::mem::zeroed() };
    let name = CString::new(interface).unwrap();
    let name_bytes = name.as_bytes_with_nul();

    ifr.ifr_name[..name_bytes.len()]
        .copy_from_slice(unsafe { &*(name_bytes as *const [u8] as *const [c_char]) });
    ifr.ifr_data = &mut channels;

    let ret = unsafe { ioctl(fd, SIOCETHTOOL as _, &mut ifr) };

    unsafe { libc::close(fd) };

    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // combined_count means each queue handles both RX and TX
    // If combined > 0, that's your queue count; otherwise use rx/tx separately
    Ok((channels.combined_count, channels.max_combined))
}

pub fn plan_threads(interface: &str, max_threads: Option<u32>) -> Vec<ThreadConfig> {
    let (queue_count, _) = get_hw_queues(interface).unwrap_or((1, 1));
    let numa_cores = select_cores(interface, queue_count);

    let count = match max_threads {
        Some(max) => queue_count.min(max),
        None => queue_count,
    };

    (0..count)
        .map(|i| ThreadConfig {
            queue_id: i,
            core_id: numa_cores[i as usize],
        })
        .collect()
}

fn select_cores(interface: &str, queue_count: u32) -> Vec<usize> {
    // Prefer cores on the same NUMA node as the NIC
    // Read from /sys/class/net/<interface>/device/numa_node
    // Then pick cores from that node

    let nic_numa = std::fs::read_to_string(format!("/sys/class/net/{}/device/numa_node", interface))
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok())
        .unwrap_or(0);

    let mut local_cores = Vec::new();
    let mut remote_cores = Vec::new();

    for cpu in 0..num_cores() {
        let path = format!("/sys/devices/system/cpu/cpu{}/topology/physical_package_id", cpu);
        let numa = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| s.trim().parse::<i32>().ok())
            .unwrap_or(0);

        if numa == nic_numa {
            local_cores.push(cpu);
        } else {
            remote_cores.push(cpu);
        }
    }

    // Prefer NUMA-local cores, fall back to remote
    local_cores.extend(remote_cores);
    local_cores.truncate(queue_count as usize);
    local_cores
}
