mod pidfile;

use std::ffi::CString;
use libc::{ioctl, socket, AF_INET, SOCK_DGRAM, c_char};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use log::{error, warn, info};
use nix::unistd::{chdir, dup2_stdin, dup2_stdout, dup2_stderr, fork, setsid, ForkResult};
use sd_notify::NotifyState;
use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use anyhow::{anyhow, bail, Result};
use bytesize::ByteSize;

use pesigitg_common::{
    DEFAULT_INTF,
    DEFAULT_PORT,
    PID_FILE,
    PROC_NAME,
    MAX_CONFIG_SIZE,
    current_pid,
    exit
};

use pidfile::PidFile;

struct Args {
    ports: Vec<u16>,
    interface: String,
    queues: u16,
    config: Option<PathBuf>,
    foreground: bool,
}

struct FileConfig {
    ports: Vec<u16>,
    interface: String,
    queues: u16,
}

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


fn parse_config(path: &PathBuf) -> Result<FileConfig> {
    let size = std::fs::metadata(path)?.len();

    if size > MAX_CONFIG_SIZE {
        let byte_size = ByteSize::b(size);

        bail!("config file exceeds {} limit ({} bytes)", size, byte_size);
    }
    
    let content = std::fs::read_to_string(path)?;
    let mut ports = Vec::new();
    let mut interface = DEFAULT_INTF.to_string();
    let mut queues: u16 = 1;

    for line in content.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') { continue; }

        if let Some((k, v)) = line.split_once('=') {
            match k.trim() {
                "port" => ports.push(v.trim().parse::<u16>()?),
                "interface" => interface = v.trim().to_string(),
                "queues" => queues = v.trim().parse::<u16>()?,
                _ => {}
            }
        }
    }

    Ok(FileConfig { ports, interface, queues })
}

fn parse_args() -> Result<Args> {
    let mut pargs = pico_args::Arguments::from_env();

    // --version / -V
    if pargs.contains(["-V", "--version"]) {
        println!("{} {} ({})", PROC_NAME, env!("CARGO_PKG_VERSION"), env!("BUILD_DATE"));
        println!("{}", env!("RUSTC_VERSION"));
        println!("platform: {}", env!("TARGET"));

        exit!();
    }

    // --help / -h
    if pargs.contains(["-h", "--help"]) {
        println!(
            "{0} {1}\n\n\
            A QUIC-aware load balancer\n\n\
            Usage: {0} [OPTIONS]\n\n\
            Options:\n  \
            -p, --port <PORT>         Port to listen on (repeatable)\n  \
            -i, --interface <NAME>    Network interface [default: {DEFAULT_INTF}]\n  \
            -c, --config <PATH>       Config file path\n  \
            -q, --queues <NUM>        Number of NIC queues [default: 1]\n  \
            -f, --foreground          Run in foreground (don't daemonize)\n  \
            -V, --version             Print version\
        ", PROC_NAME, env!("CARGO_PKG_VERSION"));

        exit!();
    }

    let foreground = pargs.contains(["-f", "--foreground"]);
    let config: Option<PathBuf> = pargs.opt_value_from_str(["-c", "--config"])?;
    let interface: Option<String> = pargs.opt_value_from_str(["-i", "--interface"])?;
    let queues: Option<u16> = pargs.opt_value_from_str(["-q", "--queues"])?;

    // Collect all -p / --port values
    let mut ports = Vec::new();
    while let Some(port) = pargs.opt_value_from_str::<_, u16>(["-p", "--port"])? {
        ports.push(port);
    }

    // Check for unexpected arguments
    let remaining = pargs.finish();
    if !remaining.is_empty() {
        bail!("unknown arguments: {:?}", remaining);
    }

    // If config file provided, use it as base
    let file_config = config.as_ref().map(|path| {
        parse_config(path)
    }).transpose()?;

    // CLI -> config file -> defaults
    Ok(Args {
        ports: if !ports.is_empty() {
            ports
        } else if let Some(ref fc) = file_config {
            fc.ports.clone()
        } else {
            vec![DEFAULT_PORT]
        },
        interface: interface
            .or(file_config.as_ref().map(|fc| fc.interface.clone()))
            .unwrap_or_else(|| DEFAULT_INTF.into()),
        queues: queues
            .or(file_config.as_ref().map(|fc| fc.queues))
            .unwrap_or(1),
        config,
        foreground,
    })
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
        info!("PID file: {}", pidfile.path().display());
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
            if u32::from(args.queues) < current {
                warn!("spawn {0} AF_XDP threads for full queue coverage (--queues {0})", current);
            }
        }
        Err(e) => {
            error!("failed to query {}: {}", args.interface, e);
            error!("(requires root or CAP_NET_ADMIN)");
            
            exit!(1);
        }
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
