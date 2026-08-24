//! Point the leakage detector at the verifier, and read the result correctly.
//!
//! `cargo run --release -p lms-verify --example timing_evidence`
//!
//! # Why run this at all
//!
//! The crate documentation claims verification has no meaningful timing surface,
//! on the argument that every value it touches is public. An argument is not
//! evidence, and the gap between the two is where security claims usually die. So:
//! measure.
//!
//! # What it will say, and why that is not a bug
//!
//! It will report a **large** t-statistic, far past the 4.5 threshold. Verification
//! time depends heavily on the message, because the Winternitz coefficients come
//! from `Q = H(I || q || D_MESG || C || message)` and each chain is walked from its
//! coefficient up to `2^w - 1`. Change the message, change the coefficients, change
//! the work by up to a factor of sixteen.
//!
//! **That is not a side channel.** A side channel leaks a secret, and this verifier
//! has none — no private key, no ephemeral randomness, nothing an attacker does not
//! already hold. The message and signature whose timing is being revealed are the
//! attacker's own inputs.
//!
//! This is the distinction worth being able to make out loud, because it is where
//! "constant time" gets applied as a reflex rather than a decision:
//!
//! - **Constant time is a property relative to a secret.** No secret, no property.
//! - A tool reporting variable timing has found a *fact*, not a *finding*. Deciding
//!   which it is takes a threat model, and no measurement supplies one.
//! - Padding this verifier to its worst case would roughly double average boot time
//!   to defend against nothing. See `examples/cost_distribution.rs` for the factor.
//!
//! The same harness pointed at a *signer* — which does hold a key — would be asking
//! a real question. That is the experiment worth running next, and it is not this
//! crate, because this crate deliberately does not sign.

use ct_probe::{run, Class, Config};
use lms_verify::*;

/// A syntactically valid public key. It authenticates nothing; verification will
/// fail at the root comparison, which is the point — the full chain walk happens
/// first either way, so the timing is representative of the real work.
fn public_key() -> Vec<u8> {
    let mut pk = Vec::with_capacity(PUBLIC_KEY_LEN);
    pk.extend_from_slice(&LMS_SHA256_M32_H5.typecode.to_be_bytes());
    pk.extend_from_slice(&LMOTS_SHA256_N32_W8.typecode.to_be_bytes());
    pk.extend_from_slice(&[0x5A; 16]);
    pk.extend_from_slice(&[0xA5; 32]);
    pk
}

fn signature(fill: u8) -> Vec<u8> {
    let len = signature_len(&LMOTS_SHA256_N32_W8, &LMS_SHA256_M32_H5);
    let mut sig = vec![fill; len];
    sig[0..4].copy_from_slice(&0u32.to_be_bytes()); // leaf 0, inside the tree
    sig[4..8].copy_from_slice(&LMOTS_SHA256_N32_W8.typecode.to_be_bytes());
    let at = 4 + LMOTS_SHA256_N32_W8.sig_len();
    sig[at..at + 4].copy_from_slice(&LMS_SHA256_M32_H5.typecode.to_be_bytes());
    sig
}

fn main() {
    let pk = public_key();
    let sig = signature(0x11);
    let cfg = Config {
        samples: 20_000,
        warmup: 200,
        ..Config::default()
    };

    println!("Experiment 1 — does verification time depend on the message?");
    println!("Class A: a fixed message. Class B: a fresh random one.\n");
    let report = run(
        &cfg,
        |class| match class {
            Class::A => [0u8; 32],
            Class::B => rand::random::<[u8; 32]>(),
        },
        |msg| {
            let _ = std::hint::black_box(verify(&pk, msg, &sig));
        },
    );
    println!("{report}\n");

    println!("Experiment 2 — does it depend on the signature?");
    println!("Class A: a fixed signature. Class B: one with different chain data.\n");
    let sig_a = signature(0x00);
    let sig_b = signature(0xFF);
    let msg = [7u8; 32];
    let report2 = run(
        &cfg,
        |class| match class {
            Class::A => sig_a.clone(),
            Class::B => sig_b.clone(),
        },
        |s| {
            let _ = std::hint::black_box(verify(&pk, &msg, s));
        },
    );
    println!("{report2}\n");

    println!("---");
    println!();
    if report.leaks() {
        println!("Timing does vary with the input, as expected and by a wide margin.");
    } else {
        println!("No variation detected — surprising; the chain walk should show up.");
        println!("Rerun with more samples before drawing any conclusion from that.");
    }
    println!();
    println!("This is a fact about scheduling, not a finding about security. The");
    println!("verifier holds no secret: the message, the signature and the public key");
    println!("are all the attacker's own inputs or public values. There is nothing for");
    println!("a timing attack to recover.");
    println!();
    println!("Constant time is a property relative to a secret. Where there is no");
    println!("secret the property is vacuous, and enforcing it anyway costs real boot");
    println!("time to defend against nothing. The number belongs in a boot-time budget");
    println!("-- see examples/cost_distribution.rs -- not in a threat model.");
    println!();
    println!("The same harness pointed at a signer, which does hold a key, would be");
    println!("asking a real question. That is deliberately not this crate.");
}
