// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

#![cfg_attr(not(feature = "std"), no_std)]

pub const DEFAULT_PORT: u16 = 443;
pub const DEFAULT_INTF: &str = "eth0";
pub const DEFAULT_QUEUES: u32 = 1;
pub const DEFAULT_ROUTE_CONFIG: &str = "/etc/pesigitg/lb.toml";
pub const PID_DIR: &str = "/var/run";
pub const PROC_NAME: &str = "pesigitgd";
pub const MAX_CONFIG_SIZE: u64 = 1_000_000;
pub const MAX_QUEUES: u32 = 256;
pub const MAX_PORTS: u32 = 64;
pub const TAGLINE: &str = "A high-performance QUIC-aware load balancer, using eBPF and AF_XDP for kernel-bypass packet forwarding.";

// -- Network protocol constants (shared between eBPF and daemon) ----------

// Header sizes
pub const ETH_HDR_LEN: usize = 14;
pub const IPV4_MIN_HDR_LEN: usize = 20;
pub const IPV6_HDR_LEN: usize = 40;
pub const UDP_HDR_LEN: usize = 8;

// EtherType
pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_P_IPV6: u16 = 0x86dd;

// IP protocol numbers
pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_HOPOPTS: u8 = 0;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_ROUTING: u8 = 43;
pub const IPPROTO_FRAGMENT: u8 = 44;
pub const IPPROTO_ICMPV6: u8 = 58;
pub const IPPROTO_DSTOPTS: u8 = 60;

// ICMP header size (same for ICMPv4 and ICMPv6 error messages)
pub const ICMP_HDR_LEN: usize = 8;

// ICMPv4 error types
pub const ICMP_DEST_UNREACH: u8 = 3;
pub const ICMP_TIME_EXCEEDED: u8 = 11;

// ICMPv6 error types
pub const ICMPV6_DEST_UNREACH: u8 = 1;
pub const ICMPV6_PACKET_TOO_BIG: u8 = 2;
pub const ICMPV6_TIME_EXCEEDED: u8 = 3;

// Maximum IPv6 extension headers to walk before giving up
pub const MAX_IPV6_EXT_HDRS: usize = 6;


#[cfg(feature = "std")]
#[allow(non_upper_case_globals)]
pub const current_pid: fn() -> u32 = std::process::id;

/// Per-interface PID file path: `/var/run/pesigitgd-<iface>.pid`.
/// Lets multiple manual instances (different `-i`) coexist without
/// colliding on a single PID file.
#[cfg(feature = "std")]
pub fn pid_file(iface: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("{}/{}-{}.pid", PID_DIR, PROC_NAME, iface))
}

#[cfg(feature = "std")]
#[macro_export]
macro_rules! exit {
    ($code:expr) => { std::process::exit($code) };
    () => { std::process::exit(0) };
}
