//! Baseline: SHA-256 and the runtime scaffolding, without the LMS verifier.
//!
//! Subtracting this from the full probe gives the **marginal** cost of LMS
//! verification on a part that already has SHA-256 in its boot ROM — which every
//! part doing secure boot already does, because image integrity needs a hash
//! before it needs a signature. That marginal figure is the one a firmware
//! architect actually has to weigh, and it is much smaller than the total.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use sha2::{Digest, Sha256};

static MSG_ADDR: usize = 0x2000_2000;
static MSG_LEN: usize = 64;

// `loop {}` rather than a `wfi`/`wfe` idle: this binary exists to be measured,
// not to run, and a wait-for-interrupt would be arch-specific inline assembly
// that changes the very `.text` figure the file is here to produce.
#[allow(clippy::empty_loop)]
#[no_mangle]
pub extern "C" fn _start() -> ! {
    let out = unsafe {
        let msg = core::slice::from_raw_parts(
            core::ptr::read_volatile(&MSG_ADDR) as *const u8,
            core::ptr::read_volatile(&MSG_LEN),
        );
        let mut h = Sha256::new();
        h.update(msg);
        h.finalize()
    };

    unsafe {
        core::ptr::write_volatile(0x2000_0000 as *mut u8, out[0]);
    }
    loop {}
}

// `loop {}` rather than a `wfi`/`wfe` idle: this binary exists to be measured,
// not to run, and a wait-for-interrupt would be arch-specific inline assembly
// that changes the very `.text` figure the file is here to produce.
#[allow(clippy::empty_loop)]
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {}
}
