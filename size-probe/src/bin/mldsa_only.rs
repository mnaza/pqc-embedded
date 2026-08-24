//! ML-DSA-44 verification, sized the same way as the LMS probe.
//!
//! # Why this is here
//!
//! `boot-budget` compares signature schemes, and until now it could only *measure*
//! one of them. Every other row carried an estimate, marked as such and enforced by
//! a test, which is honest but leaves the table doing half its job.
//!
//! No cryptography is written here. RustCrypto's `ml-dsa` is used as-is; this
//! binary exists to be weighed, not to be trusted. That distinction matters:
//! measuring flash and stack does not require believing the implementation is
//! correct, so using a pre-1.0 crate for it is legitimate in a way that shipping
//! it would not be.
//!
//! # The comparison this makes possible
//!
//! ML-DSA hashes with SHAKE — Keccak — and **the ESP32-S3's SHA accelerator does
//! the SHA-2 family only.** So the claim that a hash engine discounts LMS and does
//! nothing for ML-DSA is not a rhetorical flourish about "different maths": on this
//! specific silicon the peripheral cannot be pointed at ML-DSA's hash at all.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa44, Signature, VerifyingKey};

static PK_ADDR: usize = 0x2000_1000;
static MSG_ADDR: usize = 0x2000_2000;
static SIG_ADDR: usize = 0x2000_3000;
static MSG_LEN: usize = 64;

// See size-probe/src/main.rs: `loop {}` rather than a wait-for-interrupt, because
// this binary exists to be measured rather than run.
#[allow(clippy::empty_loop)]
#[no_mangle]
pub extern "C" fn _start() -> ! {
    let ok = unsafe {
        let pk = core::slice::from_raw_parts(
            core::ptr::read_volatile(&PK_ADDR) as *const u8,
            1312,
        );
        let sigbytes = core::slice::from_raw_parts(
            core::ptr::read_volatile(&SIG_ADDR) as *const u8,
            2420,
        );
        let msg = core::slice::from_raw_parts(
            core::ptr::read_volatile(&MSG_ADDR) as *const u8,
            core::ptr::read_volatile(&MSG_LEN),
        );

        let enc_pk = EncodedVerifyingKey::<MlDsa44>::try_from(pk).unwrap();
        let enc_sig = EncodedSignature::<MlDsa44>::try_from(sigbytes).unwrap();
        let vk = VerifyingKey::<MlDsa44>::decode(&enc_pk);
        match Signature::<MlDsa44>::decode(&enc_sig) {
            Some(sig) => vk.verify_with_context(msg, b"", &sig),
            None => false,
        }
    };

    unsafe {
        core::ptr::write_volatile(0x2000_0000 as *mut u8, ok as u8);
    }
    loop {}
}

#[allow(clippy::empty_loop)]
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {}
}
