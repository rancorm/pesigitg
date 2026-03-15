#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, XskMap},
    programs::XdpContext,
};
use core::mem;

use pesigitg_common::{
    ETH_HDR_LEN, ETH_P_IP, ETH_P_IPV6, ICMP_DEST_UNREACH, ICMP_HDR_LEN, ICMP_TIME_EXCEEDED,
    ICMPV6_DEST_UNREACH, ICMPV6_PACKET_TOO_BIG, ICMPV6_TIME_EXCEEDED, IPPROTO_DSTOPTS,
    IPPROTO_FRAGMENT, IPPROTO_HOPOPTS, IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_ROUTING, IPPROTO_UDP,
    IPV4_MIN_HDR_LEN, IPV6_HDR_LEN, MAX_IPV6_EXT_HDRS, MAX_PORTS, MAX_QUEUES,
};

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
    // Ethernet header
    let eth_proto = u16::from_be(unsafe { *ptr_at::<u16>(ctx, 12)? });

    // Parse out a monitored port: UDP destination port, or for ICMP error
    // packets the inner (echoed) UDP source port.
    let port = match eth_proto {
        ETH_P_IP => parse_ipv4(ctx)?,
        ETH_P_IPV6 => parse_ipv6(ctx)?,
        _ => return Ok(xdp_action::XDP_PASS),
    };

    // Continue if a monitored port was found
    let dst_port = match port {
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

/// Parse an IPv4 packet and return the port to check against the PORTS map.
///
/// For UDP packets: returns the destination port.
/// For ICMP error packets: parses the echoed inner packet and returns
/// the inner UDP source port (the server's listening port).
#[inline(always)]
fn parse_ipv4(ctx: &XdpContext) -> Result<Option<u16>, ()> {
    let iph_byte0 = unsafe { *ptr_at::<u8>(ctx, ETH_HDR_LEN)? };
    let ihl = ((iph_byte0 & 0x0F) as usize) * 4;

    if ihl < IPV4_MIN_HDR_LEN {
        return Err(());
    }

    let protocol = unsafe { *ptr_at::<u8>(ctx, ETH_HDR_LEN + 9)? };

    match protocol {
        IPPROTO_UDP => {
            let udp_offset = ETH_HDR_LEN + ihl;
            let dst_port = u16::from_be(unsafe { *ptr_at::<u16>(ctx, udp_offset + 2)? });
            Ok(Some(dst_port))
        }
        IPPROTO_ICMP => {
            let icmp_offset = ETH_HDR_LEN + ihl;
            let icmp_type = unsafe { *ptr_at::<u8>(ctx, icmp_offset)? };
            if icmp_type != ICMP_DEST_UNREACH && icmp_type != ICMP_TIME_EXCEEDED {
                return Ok(None);
            }
            // Inner IPv4 header starts after ICMP header (8 bytes).
            let inner_ip_offset = icmp_offset + ICMP_HDR_LEN;
            let inner_byte0 = unsafe { *ptr_at::<u8>(ctx, inner_ip_offset)? };
            let inner_ihl = ((inner_byte0 & 0x0F) as usize) * 4;
            if inner_ihl < IPV4_MIN_HDR_LEN {
                return Ok(None);
            }
            let inner_proto = unsafe { *ptr_at::<u8>(ctx, inner_ip_offset + 9)? };
            if inner_proto != IPPROTO_UDP {
                return Ok(None);
            }
            // Inner UDP source port = server's listening port.
            let inner_udp_offset = inner_ip_offset + inner_ihl;
            let src_port = u16::from_be(unsafe { *ptr_at::<u16>(ctx, inner_udp_offset)? });
            Ok(Some(src_port))
        }
        _ => Ok(None),
    }
}

/// Parse an IPv6 packet and return the port to check against the PORTS map.
///
/// For UDP packets: returns the destination port.
/// For ICMPv6 error packets: parses the echoed inner packet and returns
/// the inner UDP source port.
///
/// Walks through known extension headers with a bounded loop to satisfy
/// the eBPF verifier.
#[inline(always)]
fn parse_ipv6(ctx: &XdpContext) -> Result<Option<u16>, ()> {
    let mut next_hdr = unsafe { *ptr_at::<u8>(ctx, ETH_HDR_LEN + 6)? };
    let mut offset = ETH_HDR_LEN + IPV6_HDR_LEN;
    let mut i = 0;

    while i < MAX_IPV6_EXT_HDRS {
        // Prevent LLVM from caching packet pointers across iterations.
        // Without this, the compiler reuses stale packet pointers from the
        // previous iteration, which the eBPF verifier cannot track through
        // variable-offset arithmetic.
        offset = core::hint::black_box(offset);

        match next_hdr {
            IPPROTO_UDP | IPPROTO_ICMPV6 => break,
            IPPROTO_FRAGMENT => {
                next_hdr = unsafe { *ptr_at::<u8>(ctx, offset)? };
                offset += 8;
            }
            IPPROTO_HOPOPTS | IPPROTO_ROUTING | IPPROTO_DSTOPTS => {
                next_hdr = unsafe { *ptr_at::<u8>(ctx, offset)? };
                let ext_len = (unsafe { *ptr_at::<u8>(ctx, offset + 1)? } as usize) & 0x1F;
                offset += (ext_len + 1) * 8;
            }
            _ => return Ok(None),
        }

        i += 1;
    }

    match next_hdr {
        IPPROTO_UDP => {
            let dst_port = u16::from_be(unsafe { *ptr_at::<u16>(ctx, offset + 2)? });
            Ok(Some(dst_port))
        }
        IPPROTO_ICMPV6 => {
            let icmp_type = unsafe { *ptr_at::<u8>(ctx, offset)? };
            if icmp_type != ICMPV6_DEST_UNREACH
                && icmp_type != ICMPV6_PACKET_TOO_BIG
                && icmp_type != ICMPV6_TIME_EXCEEDED
            {
                return Ok(None);
            }
            // Inner IPv6 header starts after ICMPv6 header (8 bytes).
            let inner_ip_offset = offset + ICMP_HDR_LEN;
            let mut inner_next_hdr = unsafe { *ptr_at::<u8>(ctx, inner_ip_offset + 6)? };
            let mut inner_offset = inner_ip_offset + IPV6_HDR_LEN;
            let mut j = 0;

            while j < MAX_IPV6_EXT_HDRS {
                inner_offset = core::hint::black_box(inner_offset);

                match inner_next_hdr {
                    IPPROTO_UDP => break,
                    IPPROTO_FRAGMENT => {
                        inner_next_hdr = unsafe { *ptr_at::<u8>(ctx, inner_offset)? };
                        inner_offset += 8;
                    }
                    IPPROTO_HOPOPTS | IPPROTO_ROUTING | IPPROTO_DSTOPTS => {
                        inner_next_hdr = unsafe { *ptr_at::<u8>(ctx, inner_offset)? };
                        let ext_len =
                            (unsafe { *ptr_at::<u8>(ctx, inner_offset + 1)? } as usize) & 0x1F;
                        inner_offset += (ext_len + 1) * 8;
                    }
                    _ => return Ok(None),
                }
                j += 1;
            }

            if inner_next_hdr != IPPROTO_UDP {
                return Ok(None);
            }
            // Inner UDP source port = server's listening port.
            let src_port = u16::from_be(unsafe { *ptr_at::<u16>(ctx, inner_offset)? });
            Ok(Some(src_port))
        }
        _ => Ok(None),
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
