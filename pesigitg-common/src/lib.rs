#![cfg_attr(not(feature = "std"), no_std)]

pub const DEFAULT_PORT: u16 = 443;
pub const DEFAULT_INTF: &str = "eth0";
pub const PID_FILE: &str = "/var/run/pesigitgd.pid";
pub const PROC_NAME: &str = "pesigitgd";

#[allow(non_upper_case_globals)]
pub const current_pid: fn() -> u32 = std::process::id;

#[macro_export]
macro_rules! exit {
    ($code:expr) => { std::process::exit($code) };
    () => { std::process::exit(0) };
}
