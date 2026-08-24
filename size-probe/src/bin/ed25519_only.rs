//! Ed25519 verification — the other classical baseline.
#![no_std]
#![no_main]

use core::panic::PanicInfo;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(arr) = <[u8; 32]>::try_from(pk) else { return false };
    let Ok(vk) = VerifyingKey::from_bytes(&arr) else { return false };
    let Ok(sarr) = <[u8; 64]>::try_from(sig) else { return false };
    let s = Signature::from_bytes(&sarr);
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
        let sg = core::slice::from_raw_parts(core::ptr::read_volatile(&SIG_ADDR) as *const u8, 64);
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
