#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, XskMap},
    programs::XdpContext,
};
use core::mem;

use pesigitg_common::{MAX_PORTS, MAX_QUEUES};

const ETH_HDR_LEN: usize = 14;
const IPV4_HDR_LEN: usize = 20; // minimum, without options
const IPV6_HDR_LEN: usize = 40;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const IPPROTO_UDP: u8 = 17;

#[map]
static PORTS: HashMap<u16, u8> = HashMap::with_max_entries(MAX_PORTS, 0);

/// AF_XDP socket map, indexed by RX queue id.  The daemon registers one
/// socket per hardware queue; the XDP program redirects matched packets
/// to the socket bound to the queue the packet arrived on.
#[map]
static XSKS: XskMap = XskMap::with_max_entries(MAX_QUEUES, 0);

#[xdp]
pub fn pesigitg(ctx: XdpContext) -> u32 {
    match try_pesigitg(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

/// Read a value of type T from `offset` within the XDP packet buffer,
/// returning a pointer.  Performs the bounds check that the eBPF
/// verifier requires.
#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

fn try_pesigitg(ctx: &XdpContext) -> Result<u32, ()> {
    // --- Ethernet header ---
    let eth_proto = u16::from_be(unsafe { *ptr_at::<u16>(ctx, 12)? });

    let dst_port = match eth_proto {
        ETH_P_IP => parse_ipv4_udp(ctx)?,
        ETH_P_IPV6 => parse_ipv6_udp(ctx)?,
        _ => return Ok(xdp_action::XDP_PASS),
    };

    let dst_port = match dst_port {
        Some(p) => p,
        None => return Ok(xdp_action::XDP_PASS),
    };

    // Look up the destination port in the PORTS map.
    if unsafe { PORTS.get(&dst_port) }.is_none() {
        return Ok(xdp_action::XDP_PASS);
    }

    // Redirect to the AF_XDP socket bound to this RX queue.
    let queue_id = unsafe { (*ctx.ctx).rx_queue_index };
    XSKS.redirect(queue_id, xdp_action::XDP_PASS as u64)
        .map_err(|_| ())
}

/// Parse an IPv4 packet and return the UDP destination port, or None if
/// it is not a UDP packet.
#[inline(always)]
fn parse_ipv4_udp(ctx: &XdpContext) -> Result<Option<u16>, ()> {
    // Read the first byte of the IPv4 header to get IHL (header length).
    let iph_byte0 = unsafe { *ptr_at::<u8>(ctx, ETH_HDR_LEN)? };
    let ihl = ((iph_byte0 & 0x0F) as usize) * 4;

    if ihl < IPV4_HDR_LEN {
        return Err(());
    }

    // Protocol field is at offset 9 in the IPv4 header.
    let protocol = unsafe { *ptr_at::<u8>(ctx, ETH_HDR_LEN + 9)? };
    if protocol != IPPROTO_UDP {
        return Ok(None);
    }

    // UDP destination port is at offset 2 within the UDP header.
    let udp_offset = ETH_HDR_LEN + ihl;
    let dst_port = u16::from_be(unsafe { *ptr_at::<u16>(ctx, udp_offset + 2)? });

    Ok(Some(dst_port))
}

/// Parse an IPv6 packet and return the UDP destination port, or None if
/// the next header is not UDP.
///
/// This handles the fixed 40-byte IPv6 header only.  Extension headers
/// are not followed — a packet whose Next Header is not UDP (17) is
/// simply passed through.
#[inline(always)]
fn parse_ipv6_udp(ctx: &XdpContext) -> Result<Option<u16>, ()> {
    // Next Header field is at offset 6 in the IPv6 header.
    let next_hdr = unsafe { *ptr_at::<u8>(ctx, ETH_HDR_LEN + 6)? };
    if next_hdr != IPPROTO_UDP {
        return Ok(None);
    }

    // UDP destination port is at offset 2 within the UDP header.
    let udp_offset = ETH_HDR_LEN + IPV6_HDR_LEN;
    let dst_port = u16::from_be(unsafe { *ptr_at::<u16>(ctx, udp_offset + 2)? });

    Ok(Some(dst_port))
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
