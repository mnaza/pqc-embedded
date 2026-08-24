//! Baseline: SHAKE-256 from `sha3`, which is what ML-DSA hashes with alone, for subtracting from the schemes that use it.
//!
//! Several probes here link **different versions of `sha2`**: `lms-verify` uses
//! 0.10, and `p256`, `slh-dsa` and friends require 0.11, whose SHA-256 compiles to
//! roughly four times the code. Comparing total binary sizes across them would
//! measure that difference and call it a difference between signature schemes.
//!
//! So every scheme is subtracted from a baseline built with the same hash, from the
//! same crate version.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

static MSG_ADDR: usize = 0x2000_2000;
static MSG_LEN: usize = 64;

#[allow(clippy::empty_loop)]
#[no_mangle]
pub extern "C" fn _start() -> ! {
    let out = unsafe {
        let msg = core::slice::from_raw_parts(
            core::ptr::read_volatile(&MSG_ADDR) as *const u8,
            core::ptr::read_volatile(&MSG_LEN),
        );
        let mut h = Shake256::default();
        h.update(msg);
        let mut r = h.finalize_xof();
        let mut out = [0u8; 1];
        r.read(&mut out);
        out[0]
    };
    unsafe { core::ptr::write_volatile(0x2000_0000 as *mut u8, out) };
    loop {}
}

#[allow(clippy::empty_loop)]
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {}
}
