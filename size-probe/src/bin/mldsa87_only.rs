//! ML-DSA-87 verification, sized the same way as the LMS probe.
//!
//! See `mldsa_only.rs` for why this exists and what it is and is not measuring.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa87, Signature, VerifyingKey};

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
            2592,
        );
        let sigbytes = core::slice::from_raw_parts(
            core::ptr::read_volatile(&SIG_ADDR) as *const u8,
            4627,
        );
        let msg = core::slice::from_raw_parts(
            core::ptr::read_volatile(&MSG_ADDR) as *const u8,
            core::ptr::read_volatile(&MSG_LEN),
        );

        let enc_pk = EncodedVerifyingKey::<MlDsa87>::try_from(pk).unwrap();
        let enc_sig = EncodedSignature::<MlDsa87>::try_from(sigbytes).unwrap();
        let vk = VerifyingKey::<MlDsa87>::decode(&enc_pk);
        match Signature::<MlDsa87>::decode(&enc_sig) {
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
