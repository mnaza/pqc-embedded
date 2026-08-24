//! Show the harness catching a real leak, and staying quiet on the fix.
//!
//! Run with `cargo run -p ct-probe --release --example naive_vs_ct`.
//!
//! **Use `--release`.** In a debug build the noise floor swamps the effect and the
//! naive comparison can come back clean — which is itself the lesson: the answer
//! depends on the binary you measured, not on the source you read.

use ct_probe::{run, Class, Config};

/// Early-exit comparison. Leaks how many leading bytes matched.
fn naive_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in 0..32 {
        if a[i] != b[i] {
            return false;
        }
    }
    true
}

/// Accumulate differences, branch once at the end.
///
/// `black_box` on the accumulator is load-bearing: without it nothing in the
/// language stops LLVM proving the loop can exit early and rewriting it into the
/// naive version. This is the gap between "I wrote it constant time" and "the
/// binary is constant time", and it is the reason this crate exists.
fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut acc = 0u8;
    for i in 0..32 {
        acc |= a[i] ^ b[i];
        acc = std::hint::black_box(acc);
    }
    acc == 0
}

fn main() {
    let secret = [0xABu8; 32];
    let cfg = Config {
        samples: 200_000,
        ..Config::default()
    };

    // Class A shares a long prefix with the secret; class B differs at byte 0.
    // An early-exit comparison spends more time on A.
    let prepare = |class: Class| -> [u8; 32] {
        let mut v = secret;
        match class {
            Class::A => v[31] ^= 0xFF,
            Class::B => v[0] ^= 0xFF,
        }
        v
    };

    println!("naive_eq — early exit on first mismatch");
    let r = run(&cfg, prepare, |v| {
        std::hint::black_box(naive_eq(v, &secret));
    });
    println!("{r}\n");

    println!("ct_eq — accumulate, branch once");
    let r = run(&cfg, prepare, |v| {
        std::hint::black_box(ct_eq(v, &secret));
    });
    println!("{r}\n");

    println!("Reminder: the second result is 'not detected', not 'proven safe',");
    println!("and both results describe this machine and this binary only.");
}
