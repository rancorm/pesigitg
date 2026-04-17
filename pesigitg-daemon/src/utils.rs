// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.
use log::debug;

/// Fire-and-forget wrapper around `sd_notify::notify`.
///
/// Accepts one or more `sd_notify::NotifyState` values:
///   systemd_notify!(NotifyState::Ready);
///   systemd_notify!(NotifyState::Ready, NotifyState::Status("ok"));
macro_rules! systemd_notify {
    ($($state:expr),+ $(,)?) => {
        let _ = sd_notify::notify(false, &[$($state),+]);
    };
}

pub(crate) use systemd_notify;

/// Send `READY=1` with an optional status string to systemd.
pub fn notify_ready(status: &str) {
    systemd_notify!(
        sd_notify::NotifyState::Ready,
        sd_notify::NotifyState::Status(status),
    );
}

pub fn num_cores() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

pub fn running_under_systemd() -> bool {
    std::env::var_os("INVOCATION_ID").is_some()
}

/// Query the MAC address of a network interface via `SIOCGIFHWADDR`.
pub fn interface_mac(interface: &str) -> std::io::Result<[u8; 6]> {
    use std::ffi::CString;

    const SIOCGIFHWADDR: libc::c_ulong = 0x8927;

    #[repr(C)]
    struct Ifreq {
        ifr_name: [libc::c_char; 16],
        ifr_hwaddr: libc::sockaddr,
    }

    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut ifr: Ifreq = unsafe { std::mem::zeroed() };
    let name = CString::new(interface).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid interface name")
    })?;
    let name_bytes = name.as_bytes_with_nul();
    let copy_len = name_bytes.len().min(ifr.ifr_name.len());

    unsafe {
        std::ptr::copy_nonoverlapping(
            name_bytes.as_ptr() as *const libc::c_char,
            ifr.ifr_name.as_mut_ptr(),
            copy_len,
        );
    }

    let ret = unsafe { libc::ioctl(fd, SIOCGIFHWADDR as _, &mut ifr) };
    unsafe { libc::close(fd) };

    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut mac = [0u8; 6];
    for (i, b) in mac.iter_mut().enumerate() {
        *b = ifr.ifr_hwaddr.sa_data[i] as u8;
    }

    Ok(mac)
}

pub fn is_aes_available() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        std::is_x86_feature_detected!("aes")
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        false
    }
}

pub(crate) fn daemonize() -> anyhow::Result<()> {
    use nix::unistd::{ForkResult, chdir, dup2_stderr, dup2_stdin, dup2_stdout, fork, setsid};
    use pesigitg_common::exit;

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

    debug!("daemon mode");

    Ok(())
}

pub(crate) fn init_logging() -> anyhow::Result<()> {
    use pesigitg_common::{PROC_NAME, current_pid};

    let formatter = syslog::Formatter3164 {
        facility: syslog::Facility::LOG_DAEMON,
        hostname: None,
        process: PROC_NAME.into(),
        pid: current_pid(),
    };

    let logger = syslog::unix(formatter)
        .map_err(|e| anyhow::anyhow!("failed to connect to syslog: {}", e))?;

    log::set_boxed_logger(Box::new(syslog::BasicLogger::new(logger)))
        .map_err(|e| anyhow::anyhow!(e))?;
    log::set_max_level(log::LevelFilter::Info);

    Ok(())
}
