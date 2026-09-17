//! Entry-only probes + keyed count maps (P2 promotes the spike
//! `count` program here). Skeleton: compiles for bpfel, attaches nothing.
#![no_std]
#![no_main]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
