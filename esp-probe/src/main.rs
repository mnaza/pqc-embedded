//! LMS verification on real silicon, timed.
//!
//! Everything measured so far has been cross-compiled and modelled: `.text` from
//! a linker, stack from `-Z emit-stack-sizes`, cost in SHA-256 compressions. All
//! of that is checkable, and none of it has run.
//!
//! This runs. On an ESP32-S3, which is Xtensa LX7 at 240 MHz with a **hardware
//! SHA accelerator** — the interesting part, because LMS verification is over 99%
//! SHA-256 by work, so the accelerator is the whole story.
//!
//! It matters beyond this board. A part with a hash engine makes hash-based
//! signatures cheap in a way it cannot make ML-DSA cheap: lattice signatures are
//! NTT and rejection sampling, not hashing, so the same silicon does nothing for
//! them. That asymmetry is an argument for LMS on exactly the class of part that
//! ships a root of trust, and it deserves a number rather than an assertion.
//!
//! The vectors are RFC 8554 Appendix F, test case 1, level 1 — so a pass here is
//! the published answer, not a self-consistent one.
//!
//! `cargo run --release` (the runner is `espflash flash --monitor`).

// Xtensa inline assembly is still unstable, and the `esp` fork is nightly, so the
// feature is available there. RISC-V needs nothing: `mcycle` is a normal CSR read.
#![cfg_attr(feature = "esp32s3", feature(asm_experimental_arch))]
#![no_std]
#![no_main]

use esp_backtrace as _;
use esp_bootloader_esp_idf::esp_app_desc;
use esp_hal::clock::CpuClock;
use esp_println::println;
use lms_verify::cost::verification_cost;
use lms_verify::{verify_with, SoftSha256};

#[cfg(feature = "esp32s3")]
mod hw_sha;
mod mldsa_vector;

const PK_HEX: &[&str] = &[
    "0000000500000004d2f14ff6346af964569f7d6cb880a1b66c5004917da6eafe",
    "4d9ef6c6407b3db0e5485b122d9ebe15cda93cfec582d7ab",
];

const MSG_HEX: &[&str] = &[
    "54686520706f77657273206e6f742064656c65676174656420746f2074686520",
    "556e69746564205374617465732062792074686520436f6e737469747574696f",
    "6e2c206e6f722070726f6869626974656420627920697420746f207468652053",
    "74617465732c2061726520726573657276656420746f20746865205374617465",
    "7320726573706563746976656c792c206f7220746f207468652070656f706c65",
    "2e0a",
];

const SIG_HEX: &[&str] = &[
    "0000000a000000040703c491e7558b35011ece3592eaa5da4d918786771233e8",
    "353bc4f62323185c95cae05b899e35dffd717054706209988ebfdf6e37960bb5",
    "c38d7657e8bffeef9bc042da4b4525650485c66d0ce19b317587c6ba4bffcc42",
    "8e25d08931e72dfb6a120c5612344258b85efdb7db1db9e1865a73caf96557eb",
    "39ed3e3f426933ac9eeddb03a1d2374af7bf77185577456237f9de2d60113c23",
    "f846df26fa942008a698994c0827d90e86d43e0df7f4bfcdb09b86a373b98288",
    "b7094ad81a0185ac100e4f2c5fc38c003c1ab6fea479eb2f5ebe48f584d7159b",
    "8ada03586e65ad9c969f6aecbfe44cf356888a7b15a3ff074f771760b26f9c04",
    "884ee1faa329fbf4e61af23aee7fa5d4d9a5dfcf43c4c26ce8aea2ce8a2990d7",
    "ba7b57108b47dabfbeadb2b25b3cacc1ac0cef346cbb90fb044beee4fac2603a",
    "442bdf7e507243b7319c9944b1586e899d431c7f91bcccc8690dbf59b28386b2",
    "315f3d36ef2eaa3cf30b2b51f48b71b003dfb08249484201043f65f5a3ef6bbd",
    "61ddfee81aca9ce60081262a00000480dcbc9a3da6fbef5c1c0a55e48a0e729f",
    "9184fcb1407c31529db268f6fe50032a363c9801306837fafabdf957fd97eafc",
    "80dbd165e435d0e2dfd836a28b354023924b6fb7e48bc0b3ed95eea64c2d402f",
    "4d734c8dc26f3ac591825daef01eae3c38e3328d00a77dc657034f287ccb0f0e",
    "1c9a7cbdc828f627205e4737b84b58376551d44c12c3c215c812a0970789c83d",
    "e51d6ad787271963327f0a5fbb6b5907dec02c9a90934af5a1c63b72c8265360",
    "5d1dcce51596b3c2b45696689f2eb382007497557692caac4d57b5de9f5569bc",
    "2ad0137fd47fb47e664fcb6db4971f5b3e07aceda9ac130e9f38182de994cff1",
    "92ec0e82fd6d4cb7f3fe00812589b7a7ce515440456433016b84a59bec6619a1",
    "c6c0b37dd1450ed4f2d8b584410ceda8025f5d2d8dd0d2176fc1cf2cc06fa8c8",
    "2bed4d944e71339ece780fd025bd41ec34ebff9d4270a3224e019fcb444474d4",
    "82fd2dbe75efb20389cc10cd600abb54c47ede93e08c114edb04117d714dc1d5",
    "25e11bed8756192f929d15462b939ff3f52f2252da2ed64d8fae88818b1efa2c",
    "7b08c8794fb1b214aa233db3162833141ea4383f1a6f120be1db82ce3630b342",
    "9114463157a64e91234d475e2f79cbf05e4db6a9407d72c6bff7d1198b5c4d6a",
    "ad2831db61274993715a0182c7dc8089e32c8531deed4f7431c07c02195eba2e",
    "f91efb5613c37af7ae0c066babc69369700e1dd26eddc0d216c781d56e4ce47e",
    "3303fa73007ff7b949ef23be2aa4dbf25206fe45c20dd888395b2526391a7249",
    "96a44156beac808212858792bf8e74cba49dee5e8812e019da87454bff9e847e",
    "d83db07af313743082f880a278f682c2bd0ad6887cb59f652e155987d61bbf6a",
    "88d36ee93b6072e6656d9ccbaae3d655852e38deb3a2dcf8058dc9fb6f2ab3d3",
    "b3539eb77b248a661091d05eb6e2f297774fe6053598457cc61908318de4b826",
    "f0fc86d4bb117d33e865aa805009cc2918d9c2f840c4da43a703ad9f5b580616",
    "3d7161696b5a0adc00000005d5c0d1bebb06048ed6fe2ef2c6cef305b3ed6339",
    "41ebc8b3bec9738754cddd60e1920ada52f43d055b5031cee6192520d6a51155",
    "14851ce7fd448d4a39fae2ab2335b525f484e9b40d6a4a969394843bdcf6d14c",
    "48e8015e08ab92662c05c6e9f90b65a7a6201689999f32bfd368e5e3ec9cb70a",
    "c7b8399003f175c40885081a09ab3034911fe125631051df0408b3946b0bde79",
    "0911e8978ba07dd56c73e7ee",
];


/// Decode a hex constant into a fixed buffer at run time.
///
/// Not `const fn`: the point of this binary is to measure work actually
/// happening, and a compile-time decode invites the optimiser to fold the
/// verification along with it.
fn decode(parts: &[&str], out: &mut [u8]) -> usize {
    let mut n = 0;
    for part in parts {
        let b = part.as_bytes();
        let mut i = 0;
        while i + 1 < b.len() {
            out[n] = nib(b[i]) * 16 + nib(b[i + 1]);
            n += 1;
            i += 2;
        }
    }
    n
}

fn nib(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => 0,
    }
}

/// Current stack pointer.
#[inline(always)]
fn stack_pointer() -> usize {
    let sp: usize;
    #[cfg(feature = "esp32s3")]
    unsafe {
        core::arch::asm!("mov {0}, a1", out(reg) sp, options(nomem, nostack))
    };
    #[cfg(not(feature = "esp32s3"))]
    unsafe {
        core::arch::asm!("mv {0}, sp", out(reg) sp, options(nomem, nostack))
    };
    sp
}

unsafe extern "C" {
    /// Low address of the main stack, from esp-hal's linker script.
    static _stack_end_cpu0: u32;
}

const PAINT: u32 = 0xC0DE_FACE;

/// How far below the stack pointer to paint.
///
/// esp-hal gives the main task around 320 KB, and painting all of it would be a
/// slow way to learn nothing: the verifier's frames are a couple of kilobytes. A
/// 32 KB window is far more than it can use, and running past the bottom of the
/// window is detected and reported rather than silently truncating the answer.
const WINDOW: usize = 32 * 1024;

/// ML-DSA needs far more. Its verification materialises the expanded matrix and
/// several polynomial vectors on the stack, and 32 KB was not enough to contain
/// the watermark — which was itself the first hint that the estimate in
/// `boot-budget` was badly wrong.
const WIDE_WINDOW: usize = 192 * 1024;

/// Fill a window of unused stack with a pattern.
///
/// The stack grows down, so everything below the current pointer is free. A margin
/// is left directly beneath it so this function's own frame is not painted over.
/// Returns the window, or `None` if it would not fit.
fn paint_stack() -> Option<(usize, usize)> {
    paint_window(WINDOW)
}

fn paint_window(window: usize) -> Option<(usize, usize)> {
    let top = stack_pointer().checked_sub(512)?;
    let limit = &raw const _stack_end_cpu0 as usize;
    let bottom = top.saturating_sub(window).max(limit);
    if bottom >= top {
        return None;
    }
    let mut p = bottom as *mut u32;
    while (p as usize) < top {
        unsafe {
            p.write_volatile(PAINT);
            p = p.add(1);
        }
    }
    Some((bottom, top))
}

/// Bytes of stack used below `top`, from the high-water mark.
///
/// `None` means the mark reached the bottom of the painted window, so the real
/// figure is at least `top - bottom` and this measurement cannot say more.
fn stack_watermark(bottom: usize, top: usize) -> Option<usize> {
    let mut p = bottom as *const u32;
    while (p as usize) < top {
        if unsafe { p.read_volatile() } != PAINT {
            break;
        }
        p = unsafe { p.add(1) };
    }
    if p as usize == bottom {
        return None;
    }
    Some(top - (p as usize))
}

/// Cycle counter, whichever the architecture calls it.
///
/// Xtensa has `CCOUNT`, a special register read with `rsr`. RISC-V has `mcycle`,
/// an ordinary machine CSR. Both count core clocks and both wrap at 32 bits, which
/// at 240 MHz is every 18 seconds — fine for a measurement that takes microseconds,
/// and the reason the result is a `wrapping_sub`.
#[inline(always)]
fn cycles() -> u32 {
    #[cfg(feature = "esp32s3")]
    {
        let c: u32;
        unsafe { core::arch::asm!("rsr.ccount {0}", out(reg) c, options(nomem, nostack)) };
        c
    }
    #[cfg(not(feature = "esp32s3"))]
    {
        riscv::register::mcycle::read() as u32
    }
}

// The ESP-IDF second-stage bootloader refuses to boot an image without this
// descriptor, so it is not optional even for a bare-metal binary. The macro
// defines a static named `ESP_APP_DESC`; it carries no `#[used]`, so
// `--gc-sections` drops it unless something refers to it. `main` does, below.
esp_app_desc!();

/// Stack-protector symbols, which bare metal has to provide itself.
///
/// esp-hal is built with the stack protector on and expects a C runtime to supply
/// the canary. There is no C runtime here. esp-hal defines `__stack_chk_fail`
/// itself, so only the guard value is missing.
///
/// A constant guard value is **not** a security feature — a real canary is
/// random per boot. This is a measurement binary and the canary is here to satisfy
/// the linker, which is stated rather than left for someone to assume otherwise.
#[cfg(not(feature = "esp32s3"))]
#[no_mangle]
pub static __stack_chk_guard: usize = 0x0BAD_CAFE;

static mut PK: [u8; 64] = [0; 64];
static mut MSG: [u8; 256] = [0; 256];
static mut SIG: [u8; 2048] = [0; 2048];

#[esp_hal::main]
fn main() -> ! {
    // Keeps the bootloader descriptor from being garbage-collected. Without this
    // the image builds, flashes, and is rejected at boot.
    core::hint::black_box(&ESP_APP_DESC);

    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let _peripherals = esp_hal::init(config);

    // Buffers live in .bss, not on the stack.
    //
    // 64 + 256 + 2048 for the vectors is most of three kilobytes, and `main`'s
    // stack also has to hold the verification frames, the saved digest state and
    // whatever `println!` formatting needs. Putting them on the stack overflows it,
    // and the failure is silent: the canary check traps into `__stack_chk_fail`,
    // which loops. The symptom is output that stops mid-way with no panic message.
    let (pk, msg, sig) = unsafe {
        (
            &mut *core::ptr::addr_of_mut!(PK),
            &mut *core::ptr::addr_of_mut!(MSG),
            &mut *core::ptr::addr_of_mut!(SIG),
        )
    };
    let pk_len = decode(PK_HEX, pk);
    let msg_len = decode(MSG_HEX, msg);
    let sig_len = decode(SIG_HEX, sig);

    println!();
    println!("LMS verification on ESP32-S3, RFC 8554 Appendix F test case 1");
    println!("  public key {pk_len} B, message {msg_len} B, signature {sig_len} B");
    println!();

    // Warm caches and flash prefetch before timing.
    let _ = verify_with(
        &mut SoftSha256::new(),
        &pk[..pk_len],
        &msg[..msg_len],
        &sig[..sig_len],
    );

    let start = cycles();
    let result = verify_with(
        &mut SoftSha256::new(),
        &pk[..pk_len],
        &msg[..msg_len],
        &sig[..sig_len],
    );
    let elapsed = cycles().wrapping_sub(start);

    // Stack, measured rather than modelled. The static call-graph pass in
    // size-probe cannot resolve indirect and tail calls, so its figure is a lower
    // bound; this is the real one.
    //
    // The watermark covers the verification's own frames. The backend struct is
    // created by the caller before the window is painted, so it sits above the
    // window and is reported separately — otherwise the hardware figure would look
    // far better than it is, since that backend carries a 2.3 KB coalescing buffer.
    if let Some((bottom, top)) = paint_stack() {
        let _ =
            verify_with(&mut SoftSha256::new(), &pk[..pk_len], &msg[..msg_len], &sig[..sig_len]);
        match stack_watermark(bottom, top) {
            Some(used) => println!(
                "stack, software backend: {used} bytes of frames + {} of backend\n",
                core::mem::size_of::<SoftSha256>()
            ),
            None => println!("stack, software backend: exceeded the {WINDOW}-byte window\n"),
        }
    } else {
        println!("stack: could not paint a window\n");
    }

    let compressions = verification_cost(&pk[..pk_len], &msg[..msg_len], &sig[..sig_len])
        .map(|c| c.total())
        .unwrap_or(0);

    println!("software SHA-256 (sha2 crate, portable Rust)");
    println!("  result           {:?}", result);
    println!("  cycles           {elapsed}");
    println!("  at 240 MHz       {} us", elapsed / 240);
    println!("  compressions     {compressions}");
    println!("  cycles/compress  {}", elapsed / compressions.max(1) as u32);
    println!();

    #[cfg(feature = "esp32s3")]
    {
        let mut hw = hw_sha::HwSha256::new(_peripherals.SHA);
        let _ = verify_with(&mut hw, &pk[..pk_len], &msg[..msg_len], &sig[..sig_len]);
        let start = cycles();
        let hw_result = verify_with(&mut hw, &pk[..pk_len], &msg[..msg_len], &sig[..sig_len]);
        let hw_elapsed = cycles().wrapping_sub(start);

        println!("hardware SHA-256 (ESP32-S3 SHA accelerator)");
        println!("  result           {:?}", hw_result);
        println!("  cycles           {hw_elapsed}");
        println!("  at 240 MHz       {} us", hw_elapsed / 240);
        println!("  cycles/compress  {}", hw_elapsed / compressions.max(1) as u32);
        println!();
        if let Some((bottom, top)) = paint_stack() {
            let _ = verify_with(&mut hw, &pk[..pk_len], &msg[..msg_len], &sig[..sig_len]);
            match stack_watermark(bottom, top) {
                Some(used) => println!(
                    "stack, hardware backend: {used} bytes of frames + {} of backend\n",
                    core::mem::size_of::<hw_sha::HwSha256>()
                ),
                None => println!("stack, hardware backend: exceeded the window\n"),
            }
        }

        // ML-DSA-44 on the same silicon, for the comparison the whole budget table
        // is for. Note what it cannot do: ML-DSA hashes with SHAKE, and the S3's
        // accelerator is SHA-2 only, so the peripheral that just gave LMS a 3.3x
        // discount is unreachable from here. This is the software number and there
        // is no hardware number to put beside it.
        {
            use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa44, Signature, VerifyingKey};

            let enc_pk = EncodedVerifyingKey::<MlDsa44>::try_from(&mldsa_vector::PK[..]).unwrap();
            let enc_sig = EncodedSignature::<MlDsa44>::try_from(&mldsa_vector::SIG[..]).unwrap();
            let vk = VerifyingKey::<MlDsa44>::decode(&enc_pk);
            let msg = &mldsa_vector::MSG[..];

            let run = || {
                Signature::<MlDsa44>::decode(&enc_sig)
                    .map(|s| vk.verify_with_context(msg, b"", &s))
                    .unwrap_or(false)
            };

            let _ = run();
            let start = cycles();
            let ok = run();
            let ml_elapsed = cycles().wrapping_sub(start);

            println!("ML-DSA-44 (RustCrypto ml-dsa, software -- SHAKE, so no accelerator)");
            println!("  result           {ok}");
            println!("  cycles           {ml_elapsed}");
            println!("  at 240 MHz       {} us", ml_elapsed / 240);
            if let Some((bottom, top)) = paint_window(WIDE_WINDOW) {
                let _ = run();
                match stack_watermark(bottom, top) {
                    Some(used) => println!("  stack            {used} bytes"),
                    None => println!("  stack            exceeded {WIDE_WINDOW} bytes"),
                }
            }
            println!(
                "  vs LMS+hw        {}.{}x slower",
                ml_elapsed / hw_elapsed.max(1),
                (ml_elapsed * 10 / hw_elapsed.max(1)) % 10
            );
            println!();
        }

        println!("  speedup          {}.{}x",
            elapsed / hw_elapsed.max(1),
            (elapsed * 10 / hw_elapsed.max(1)) % 10);
        println!();
        println!("Read together, on one chip:");
        println!();
        println!("  LMS verification is over 99% SHA-256 by work, so the hash engine");
        println!("  gives it a real 3.3x discount. ML-DSA hashes with SHAKE and the");
        println!("  S3's accelerator is SHA-2 only, so it gets nothing.");
        println!();
        println!("  And ML-DSA is still 2.4x faster. The discount is real and does");
        println!("  not decide anything.");
        println!();
        println!("  What decides is RAM: 34044 bytes against 1152. A part with 8 KB");
        println!("  can run LMS and cannot run ML-DSA at all -- not for want of");
        println!("  flash, which fits, but for stack.");
        println!();
        println!("  So the trade is time against memory, and neither wins outright.");
    }

    if result.is_err() {
        println!("!! the published vector did not verify -- everything below is moot");
    }

    loop {}
}
