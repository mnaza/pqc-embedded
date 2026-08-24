//! SLH-DSA-SHA2-128s verification, sized like the others.
//!
//! # The parameter set matters more than the family
//!
//! SLH-DSA comes in SHA-2 and SHAKE flavours. This is the SHA-2 one, and it hashes
//! with **SHA-256** — so unlike ML-DSA it could drive the same accelerator that
//! gives LMS its discount. The split is not "hash-based versus lattice", it is
//! which hash function the scheme was parameterised with.
//!
//! No cryptography is written here; RustCrypto's `slh-dsa` is used as-is and this
//! binary exists to be weighed.
#![no_std]
#![no_main]

use core::panic::PanicInfo;

use slh_dsa::{Sha2_128s, Signature, VerifyingKey};
use slh_dsa::signature::Verifier;

fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(vk) = VerifyingKey::<Sha2_128s>::try_from(pk) else { return false };
    let Ok(s) = Signature::<Sha2_128s>::try_from(sig) else { return false };
    vk.verify(msg, &s).is_ok()
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
        let pk = core::slice::from_raw_parts(core::ptr::read_volatile(&PK_ADDR) as *const u8, 32);
        let sg = core::slice::from_raw_parts(core::ptr::read_volatile(&SIG_ADDR) as *const u8, 7856);
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
