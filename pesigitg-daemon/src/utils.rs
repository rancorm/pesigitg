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

/// Initialize the global logger.
///
/// `PESIGITG_LOG_FORMAT` selects the format and takes precedence over
/// `foreground`:
///   * `"json"` — line-delimited JSON to stderr with fields
///     `{time, level, target, msg, pid}`. Suitable for Loki / Vector /
///     Elastic agents consuming container or service stderr. Requires
///     foreground or systemd (stderr is captured by journald); silently
///     dropped when the daemon forks and redirects stderr to /dev/null.
///   * unset or `"syslog"` (default) — preserves the original behavior:
///     `env_logger` text to stderr in foreground, RFC 3164 via
///     `/dev/log` when daemonized.
pub(crate) fn init_logging(foreground: bool) -> anyhow::Result<()> {
    let format = std::env::var("PESIGITG_LOG_FORMAT").unwrap_or_default();
    match format.as_str() {
        "json" => init_json(),
        "" | "syslog" => {
            if foreground {
                env_logger::init();
                Ok(())
            } else {
                init_syslog()
            }
        }
        other => Err(anyhow::anyhow!(
            "invalid PESIGITG_LOG_FORMAT={:?}; expected \"syslog\" or \"json\"",
            other
        )),
    }
}

fn init_syslog() -> anyhow::Result<()> {
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

fn init_json() -> anyhow::Result<()> {
    log::set_boxed_logger(Box::new(JsonLogger::new())).map_err(|e| anyhow::anyhow!(e))?;
    log::set_max_level(log::LevelFilter::Info);
    Ok(())
}

struct JsonLogger {
    pid: u32,
}

impl JsonLogger {
    fn new() -> Self {
        Self {
            pid: pesigitg_common::current_pid(),
        }
    }
}

impl log::Log for JsonLogger {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &log::Record<'_>) {
        use std::io::Write;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let line = serde_json::json!({
            "time": format_rfc3339_utc(now.as_secs(), now.subsec_millis()),
            "level": record.level().as_str(),
            "target": record.target(),
            "msg": record.args().to_string(),
            "pid": self.pid,
        });
        let mut out = std::io::stderr().lock();
        let _ = writeln!(out, "{}", line);
    }

    fn flush(&self) {
        use std::io::Write;
        let _ = std::io::stderr().lock().flush();
    }
}

/// Format a unix timestamp as `YYYY-MM-DDTHH:MM:SS.mmmZ`.
fn format_rfc3339_utc(secs: u64, millis: u32) -> String {
    let days = (secs / 86_400) as i64;
    let tod = (secs % 86_400) as u32;
    let (y, mo, d) = civil_from_days(days);
    let h = tod / 3600;
    let m = (tod % 3600) / 60;
    let s = tod % 60;
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}.{millis:03}Z")
}

/// Howard Hinnant's `civil_from_days`: convert days-since-1970-01-01 to
/// proleptic Gregorian (year, month, day). Inverse of the
/// `days_from_civil` used in `xtask`.
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m, d)
}

#[cfg(test)]
mod tests {
    use super::format_rfc3339_utc;

    #[test]
    fn rfc3339_epoch() {
        assert_eq!(format_rfc3339_utc(0, 0), "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn rfc3339_known_date() {
        // 2026-04-17 00:00:00 UTC
        assert_eq!(
            format_rfc3339_utc(1_776_384_000, 0),
            "2026-04-17T00:00:00.000Z"
        );
    }

    #[test]
    fn rfc3339_with_millis() {
        // 2026-04-17 12:34:56.789 UTC
        assert_eq!(
            format_rfc3339_utc(1_776_429_296, 789),
            "2026-04-17T12:34:56.789Z"
        );
    }

    #[test]
    fn rfc3339_leap_year_boundary() {
        // 2024-02-29 23:59:59 UTC = 1_709_251_199
        assert_eq!(
            format_rfc3339_utc(1_709_251_199, 0),
            "2024-02-29T23:59:59.000Z"
        );
    }
}
