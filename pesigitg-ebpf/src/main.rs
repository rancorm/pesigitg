#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::{map, xdp}, maps::HashMap, programs::XdpContext};
use aya_log_ebpf::info;

use pesigitg_common::MAX_PORTS;

#[map]
static PORTS: HashMap<u16, u8> = HashMap::with_max_entries(MAX_PORTS, 0);

#[xdp]
pub fn pesigitg(ctx: XdpContext) -> u32 {
    match try_pesigitg(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_pesigitg(ctx: &XdpContext) -> Result<u32, ()> {
    info!(ctx, "received packet");
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
