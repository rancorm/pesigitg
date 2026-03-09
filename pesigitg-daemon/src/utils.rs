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
