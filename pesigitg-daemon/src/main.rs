mod args;
mod config;
mod pidfile;

use std::ffi::CString;
use libc::{ioctl, socket, AF_INET, SOCK_DGRAM, c_char};
use std::thread;
use std::time::Duration;

use log::{error, warn, info};
use nix::unistd::{chdir, dup2_stdin, dup2_stdout, dup2_stderr, fork, setsid, ForkResult};
use sd_notify::NotifyState;
use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use anyhow::{anyhow, bail, Result};
use pesigitg_common::{PID_FILE, PROC_NAME, current_pid, exit};

use args::{Args, parse_args};
use config::daemon::parse_config;
use pidfile::PidFile;

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


fn daemonize() -> Result<()> {
    // First fork: parent exits, child continues
    match unsafe { fork() }? {
        ForkResult::Parent { .. } => exit!(),
        ForkResult::Child => {}
    }

    // Create a new session, detach from controlling terminal
    setsid()?;

    // Second fork: session leader exits, grandchild can never acquire a terminal
    match unsafe { fork() }? {
        ForkResult::Parent { .. } => exit!(),
        ForkResult::Child => {}
    }

    chdir("/")?;

    // Redirect stdin/stdout/stderr to /dev/null
    let devnull = nix::fcntl::open(
        "/dev/null",
        nix::fcntl::OFlag::O_RDWR,
        nix::sys::stat::Mode::empty(),
    )?;
 
    dup2_stdin(&devnull)?;
    dup2_stdout(&devnull)?;
    dup2_stderr(&devnull)?;

    Ok(())
}

fn init_logging() -> Result<()> {
    let formatter = syslog::Formatter3164 {
        facility: syslog::Facility::LOG_DAEMON,
        hostname: None,
        process: PROC_NAME.into(),
        pid: current_pid(),
    };

    let logger = syslog::unix(formatter)
        .map_err(|e| anyhow!("failed to connect to syslog: {}", e))?;

    log::set_boxed_logger(Box::new(syslog::BasicLogger::new(logger)))
        .map_err(|e| anyhow!(e))?;
    log::set_max_level(log::LevelFilter::Info);

    Ok(())
}

fn reload_config(args: &mut Args) {
    let Some(ref path) = args.config else {
        info!("SIGHUP received but no config file specified; ignoring");

        return;
    };

    let _ = sd_notify::notify(false, &[NotifyState::Reloading]);

    match parse_config(path) {
        Ok(fc) => {
            args.ports = fc.ports;
            args.interface = fc.interface;
            args.queues = fc.queues;

            info!(
                "config reloaded: interface='{}', ports={:?}, queues={}",
                args.interface, args.ports, args.queues
            );
        }
        Err(e) => {
            error!("failed to reload config: {}; keeping current settings", e);
        }
    }

    let _ = sd_notify::notify(false, &[
        NotifyState::Ready,
        NotifyState::Status(&format!(
            "listening on {} ports {:?}", args.interface, args.ports
        )),
    ]);
}

fn get_hw_queues(interface: &str) -> std::io::Result<(u32, u32)> {
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

fn num_cores() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

fn running_under_systemd() -> bool {
    std::env::var_os("INVOCATION_ID").is_some()
}

struct ThreadConfig {
    queue_id: u32,
    core_id: usize,
}

fn plan_threads(interface: &str, max_threads: Option<u32>) -> Vec<ThreadConfig> {
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

fn is_aes_available() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        std::is_x86_feature_detected!("aes")
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        false
    }
}

fn main() -> Result<()> {
    let mut args = parse_args()?;

    // To be, or not to be a daemon.
    if !args.foreground && !running_under_systemd() {
        daemonize()?;
    }

    // Setup logging: stderr in foreground mode (journald captures it), syslog otherwise
    if args.foreground {
        env_logger::init();
    } else {
        init_logging()?;
    }

    // PID file (unnecessary under systemd) and signal hooks
    let pidfile = if !running_under_systemd() {
        Some(PidFile::create(PID_FILE.as_ref())?)
    } else {
        None
    };

    let mut signals = Signals::new([SIGINT, SIGTERM, SIGHUP])?;

    // Output details
    info!("PID: {}", current_pid());

    if let Some(ref pidfile) = pidfile {
        info!("PID file: {}", pidfile);
    }

    // AES-NI instruction set availability. AES-NI was introduced with
    // Westmere in 2010, so anything from the last ~15 years has it.
    // 
    // Few notable exceptions:
    //  - Early Atom Celeron/Pentium processors
    //  - Some Xeon Phi models
    //  - BIOS/firmware disabling (rare)
    if is_aes_available() {
        info!("AES-NI available");
    } else {
        error!("AES-NI not available - try again please");
        bail!("AES-NI not available - try again please");
    }

    info!("number of cores: {}", num_cores());
    info!(
        "starting on interface '{}', ports: {:?}, queues: {}",
        args.interface, args.ports, args.queues
    );

    match get_hw_queues(&args.interface) {
        Ok((current, max)) => {
            info!("current combined queues: {}", current);
            info!("max. combined queues: {}", max);

            // Warn about thread queue coverage
            if args.queues < current {
                warn!("spawn {0} AF_XDP threads for full queue coverage (--queues {0})", current);
            }
        }
        Err(e) => {
            error!("failed to query {}: {}", args.interface, e);
            error!("(requires root or CAP_NET_ADMIN)");
            
            exit!(1);
        }
    }

    // Threads
    let threads = plan_threads(&args.interface, Some(args.queues));
    
    for t in &threads {
        info!("thread: queue={}, core={}", t.queue_id, t.core_id);
    }

    // Notify systemd that we're ready with a status string
    let _ = sd_notify::notify(false, &[
        NotifyState::Ready,
        NotifyState::Status(&format!(
            "listening on {} ports {:?}, queues: {}", 
            args.interface, args.ports, args.queues
        )),
    ]);

    // Poll for signals with a timeout to allow watchdog keepalives
    loop {
        for sig in signals.pending() {
            match sig {
                SIGHUP => reload_config(&mut args),
                SIGINT | SIGTERM => {
                    let _ = sd_notify::notify(false, &[NotifyState::Stopping]);
                    info!("received signal {}, shutting down", sig);

                    return Ok(());
                }
                _ => unreachable!(),
            }
        }

        let _ = sd_notify::notify(false, &[NotifyState::Watchdog]);
        thread::sleep(Duration::from_secs(5));
    }
}
