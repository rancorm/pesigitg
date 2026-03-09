#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;

use pesigitg_common::DEFAULT_PORT;

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
