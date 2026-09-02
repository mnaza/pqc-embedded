//! FN-DSA-512 verification, sized like the others.
//!
//! # Why this one is here
//!
//! Asked for on r/rust, and the reason given was the right one: FIPS standardised
//! three signature schemes so that there is a plan B and a plan C. FN-DSA is
//! FALCON under its standard name.
//!
//! It fits this repository better than it first looks. FALCON's floating-point
//! problem belongs to signing. Verification does not touch it, and Pornin — who
//! designed the scheme — ships `fn-dsa-vrfy` as a separate `no_std` crate for
//! exactly the verify-only case a boot ROM has.
//!
//! # `VerifyingKey512`, not `VerifyingKeyStandard`
//!
//! `VerifyingKeyStandard` accepts degree 512 or 1024, so it carries the array for
//! the larger one whichever key it is given. A boot verifier knows its degree at
//! build time, so it should pay for one. That choice is worth roughly 2 KB of
//! RAM and is the kind of thing a table of published numbers should not hide.
//!
//! The message representative is computed with SHAKE256, so the baseline to
//! subtract is `shake256_only` — the same one ML-DSA uses.
//!
//! No cryptography is written here; the crate is used as-is and this binary
//! exists to be weighed.
#![no_std]
#![no_main]

use core::panic::PanicInfo;

use fn_dsa_vrfy::{VerifyingKey, VerifyingKey512, DOMAIN_NONE, HASH_ID_RAW};

fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    match VerifyingKey512::decode(pk) {
        Some(vk) => vk.verify(sig, &DOMAIN_NONE, &HASH_ID_RAW, msg),
        None => false,
    }
}

static PK_ADDR: usize = 0x2000_1000;
static MSG_ADDR: usize = 0x2000_2000;
static SIG_ADDR: usize = 0x2000_3000;
static MSG_LEN: usize = 64;

// See size-probe/src/main.rs on the `loop {}` and on why inputs are read through
// volatile pointers rather than being constants.
#[allow(clippy::empty_loop)]
#[no_mangle]
pub extern "C" fn _start() -> ! {
    let ok = unsafe {
        let pk = core::slice::from_raw_parts(core::ptr::read_volatile(&PK_ADDR) as *const u8, 897);
        let sg = core::slice::from_raw_parts(core::ptr::read_volatile(&SIG_ADDR) as *const u8, 666);
        let msg = core::slice::from_raw_parts(
            core::ptr::read_volatile(&MSG_ADDR) as *const u8,
            core::ptr::read_volatile(&MSG_LEN),
        );
        verify(pk, msg, sg)
    };
    unsafe { core::ptr::write_volatile(0x2000_0000 as *mut u8, ok as u8) };
    loop {}
}

#[allow(clippy::empty_loop)]
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {}
}
