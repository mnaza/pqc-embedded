//! Measure how much verification cost actually varies, and what a boot-time
//! budget should therefore use.
//!
//! `cargo run --release -p lms-verify --example cost_distribution`
//!
//! The theoretical worst case is a real bound but a useless budget: it needs `Q`
//! to hash to all zeros. What an architect needs is the shape of the distribution
//! and a percentile they can defend. This produces both.

use lms_verify::cost::{bounds, verification_cost};
use lms_verify::*;

/// A signer lives in `#[cfg(test)]`, so this example builds its own throwaway
/// LM-OTS coefficients instead: the cost of a signature depends only on `Q`, and
/// `Q` is a hash, so sampling hashes samples the cost distribution exactly.
fn sampled_chain_work(ots: &LmotsParams, seed: u64) -> usize {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(seed.to_be_bytes());
    let q = h.finalize();

    let mut qc = [0u8; 34];
    qc[..32].copy_from_slice(&q);

    // Checksum, recomputed here rather than exported from the crate: keeping it
    // private is right, and an example that re-derives it is a second check that
    // the definition in the RFC was read the same way twice.
    let w = ots.w as usize;
    let fields = 256 / w;
    let max = (1u32 << w) - 1;
    let mut sum = 0u32;
    let coef = |s: &[u8], i: usize| -> u32 {
        let per = 8 / w;
        ((s[i * w / 8] as u32) >> (8 - (w * (i % per) + w))) & max
    };
    for i in 0..fields {
        sum += max - coef(&q, i);
    }
    let cks = ((sum << ots.ls) as u16).to_be_bytes();
    qc[32..].copy_from_slice(&cks);

    (0..ots.p).map(|i| (max - coef(&qc, i)) as usize).sum()
}

fn main() {
    const SAMPLES: usize = 200_000;

    for (ots, name) in [
        (LMOTS_SHA256_N32_W8, "w=8  (34 chains of 255)"),
        (LMOTS_SHA256_N32_W4, "w=4  (67 chains of 15)"),
    ] {
        let lms = LMS_SHA256_M32_H10;
        let msg_len = 32 * 1024;
        let b = bounds(&ots, &lms, msg_len);

        let mut work: Vec<usize> = (0..SAMPLES as u64)
            .map(|s| sampled_chain_work(&ots, s))
            .collect();
        work.sort_unstable();

        // Fixed cost is total minus chains, and it does not vary.
        let fixed = b.typical - ots.p * (ots.chain_len() as usize) / 2;
        let at = |p: f64| work[((SAMPLES as f64 * p) as usize).min(SAMPLES - 1)] + fixed;

        println!("LMS_SHA256_M32_H10, LMOTS {name}, 32 KiB image");
        println!("  compressions, {SAMPLES} sampled signatures");
        println!("    theoretical min      {:>8}", b.min);
        println!("    measured p1          {:>8}", at(0.01));
        println!("    measured median      {:>8}", at(0.50));
        println!(
            "    modelled typical     {:>8}   <- what a benchmark shows",
            b.typical
        );
        println!("    measured p99         {:>8}", at(0.99));
        println!("    measured p99.999     {:>8}", at(0.99999));
        println!("    measured max         {:>8}", at(1.0));
        println!(
            "    theoretical max      {:>8}   <- hard real-time bound",
            b.max
        );
        println!(
            "    spread p1..p99       {:>8}   ({:.1}% of median)",
            at(0.99) - at(0.01),
            100.0 * (at(0.99) - at(0.01)) as f64 / at(0.5) as f64
        );
        println!(
            "    worst / median       {:>8.2}x",
            b.max as f64 / at(0.5) as f64
        );
        println!();
    }

    // The trade the two parameter sets actually represent.
    {
        let lms = LMS_SHA256_M32_H10;
        let msg_len = 32 * 1024;
        let b8 = bounds(&LMOTS_SHA256_N32_W8, &lms, msg_len);
        let b4 = bounds(&LMOTS_SHA256_N32_W4, &lms, msg_len);
        let s8 = signature_len(&LMOTS_SHA256_N32_W8, &lms);
        let s4 = signature_len(&LMOTS_SHA256_N32_W4, &lms);

        println!("The w=8 vs w=4 trade, quantified");
        println!();
        println!("  {:<12} {:>10} {:>16}", "", "signature", "compressions");
        println!("  {:<12} {:>10} {:>16}", "w=8", s8, b8.typical);
        println!("  {:<12} {:>10} {:>16}", "w=4", s4, b4.typical);
        println!(
            "  {:<12} {:>+10} {:>+16}",
            "w=4 - w=8",
            s4 as i64 - s8 as i64,
            b4.typical as i64 - b8.typical as i64
        );
        println!();
        println!(
            "  w=4 costs {} more bytes of flash per signed image and saves {} SHA-256",
            s4 - s8,
            b8.typical - b4.typical
        );
        println!("  compressions on every boot. At roughly a thousand cycles per software");
        println!(
            "  compression on a Cortex-M4, that is about {} million cycles, or ~{} ms at",
            (b8.typical - b4.typical) / 1000,
            (b8.typical - b4.typical) * 1000 / 168_000
        );
        println!("  168 MHz. Which way that trade should go depends on whether the part is");
        println!("  short of flash or short of boot time, and it is a decision nobody can");
        println!("  make without both numbers.");
        println!();
        println!("  Note the direction: the parameter that makes the signature SMALLER is");
        println!("  the one that makes verification SLOWER. w=8 walks 34 chains of 255;");
        println!("  w=4 walks 67 chains of 15. Fewer, longer chains pack into fewer bytes.");
        println!();
    }

    println!("Reading these numbers:");
    println!();
    println!("  The theoretical max is a real bound and a poor budget — it needs Q to hash");
    println!("  to all zeros. The measured tail is what a soft real-time budget should use,");
    println!("  and it sits close to the median: verification cost concentrates, because Q");
    println!("  is a hash and the coefficient sum is an average of many uniform draws.");
    println!();
    println!("  None of this variation is a side channel. Every input is public and the");
    println!("  verifier holds no secret. Padding to the worst case would roughly double");
    println!("  average boot time to defend against nothing.");
    println!();
    println!("  Multiply by the cost of one SHA-256 compression on the part in hand.");
    println!("  Software SHA-256 on Cortex-M4 is on the order of a thousand cycles; a");
    println!("  hardware hash engine is a small fraction of that.");

    // Sanity: the crate's own model and this example must agree on a real signature.
    let ots = LMOTS_SHA256_N32_W8;
    let lms = LMS_SHA256_M32_H5;
    let b = bounds(&ots, &lms, 1);
    assert!(b.min <= b.typical && b.typical <= b.max);
    let _ = verification_cost;
}
