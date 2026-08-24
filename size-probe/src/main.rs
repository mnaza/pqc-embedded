//! A minimal bare-metal binary whose only purpose is to be measured.
//!
//! Linked with `--gc-sections`, so `.text` plus `.rodata` is what the LMS
//! verifier and its SHA-256 actually cost in flash on the target — which is the
//! number `boot-budget` needs and the one nobody publishes.
//!
//! The inputs are read through volatile pointers rather than being constants.
//! That is load-bearing: given constant inputs LLVM will happily evaluate the
//! whole verification at compile time and leave a binary containing the answer
//! and no verifier, which measures as impressively small and means nothing.
//!
//! `unsafe` is allowed here, unlike the rest of the repository, because raw
//! volatile access is the point of the file.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

/// Where the harness would place the inputs. Never dereferenced on real
/// hardware by anything that matters — the binary exists to be sized, not run.
static PK_ADDR: usize = 0x2000_1000;
static MSG_ADDR: usize = 0x2000_2000;
static SIG_ADDR: usize = 0x2000_3000;
static MSG_LEN: usize = 64;
static SIG_LEN: usize = 1292;

// `loop {}` rather than a `wfi`/`wfe` idle: this binary exists to be measured,
// not to run, and a wait-for-interrupt would be arch-specific inline assembly
// that changes the very `.text` figure the file is here to produce.
#[allow(clippy::empty_loop)]
#[no_mangle]
pub extern "C" fn _start() -> ! {
    let ok = unsafe {
        let pk = core::slice::from_raw_parts(
            core::ptr::read_volatile(&PK_ADDR) as *const u8,
            lms_verify::PUBLIC_KEY_LEN,
        );
        let msg = core::slice::from_raw_parts(
            core::ptr::read_volatile(&MSG_ADDR) as *const u8,
            core::ptr::read_volatile(&MSG_LEN),
        );
        let sig = core::slice::from_raw_parts(
            core::ptr::read_volatile(&SIG_ADDR) as *const u8,
            core::ptr::read_volatile(&SIG_LEN),
        );
        // No scratch buffer any more: the `Kc` digest is parked across each chain
        // with `Sha256Backend::save` instead of the chain outputs being collected.
        lms_verify::verify_with(&mut lms_verify::SoftSha256::new(), pk, msg, sig).is_ok()
    };

    unsafe {
        core::ptr::write_volatile(0x2000_0000 as *mut u8, ok as u8);
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
