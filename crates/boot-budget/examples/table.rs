//! Print the fit table and the measured LMS figures.
//!
//! `cargo run -p boot-budget --example table`

use boot_budget::{budget::ROOT_DIGEST_OTP, measurements, Fit, LMS_MEASUREMENTS, PARTS, SCHEMES};

fn main() {
    println!("Root of trust in OTP: {ROOT_DIGEST_OTP} bytes — a digest of the public key,");
    println!("not the key. The key lives in ordinary flash and is hashed on boot, which is");
    println!("why a 1312-byte ML-DSA key on a part with 32 bytes of fuses is not a problem.\n");

    print!(
        "{:<15} {:>7} {:>6} {:>6} {:>6} {:>6} {:>8}  {:<5} {:<5}",
        "scheme", "pubkey", "sig", "code", "-hash", "ram", "hashes", "code?", "ram?"
    );
    for p in PARTS {
        print!("  {:>16}", p.name);
    }
    println!();
    println!("{}", "-".repeat(77 + 18 * PARTS.len()));

    for s in SCHEMES {
        let marginal = match s.code_less_hash {
            Some(m) => m.to_string(),
            None => "?".to_string(),
        };
        let hashes = match s.verify_hashes {
            Some(h) => h.to_string(),
            None => "?".to_string(),
        };
        print!(
            "{:<15} {:>7} {:>6} {:>6} {:>6} {:>6} {:>8}  {:<5} {:<5}",
            s.name,
            s.public_key,
            s.signature,
            s.code,
            marginal,
            s.ram,
            hashes,
            s.code_provenance.mark(),
            s.ram_provenance.mark()
        );
        for p in PARTS {
            let verdict = match s.fits(p) {
                Fit::Fits => "fits",
                Fit::OtpExceeded => "OTP",
                Fit::FlashExceeded => "flash",
                Fit::RamExceeded => "RAM",
            };
            print!("  {verdict:>16}");
        }
        let mut tags = vec![];
        if s.quantum_broken {
            tags.push("classical");
        }
        if s.hash_based {
            tags.push("hash-based");
        }
        if s.stateful {
            tags.push("stateful");
        }
        println!("   {}", tags.join(", "));
    }

    println!(
        "\n  meas = measured on {} (see below)",
        measurements::REPRESENTATIVE
    );
    println!("  EST? = placeholder, not a measurement. Do not decide on it.");
    println!("  -hash = code minus a baseline built from the hash THAT scheme uses.");
    println!("          The comparable column. Totals are dominated by which hash crate");
    println!("          a scheme pulls: sha2 0.10's SHA-256 is 3880 bytes, 0.11's is 8840,");
    println!("          SHA-512 is 28856, SHAKE-256 is 2520 -- a wider spread than the");
    println!("          schemes themselves. These are specific implementations: a size-");
    println!("          optimised assembly ECDSA would be a fraction of the p256 crate.");
    println!("  pubkey and sig are from the standards and are reliable throughout.");
    println!("  hashes = typical SHA-256 compressions to verify a 32 KiB image. Exact and");
    println!("           architecture-independent; multiply by what one costs on your part.");
    println!("           Note w4/h10 verifies in a quarter the hashes of w8/h10 while");
    println!("           carrying a signature 1056 bytes larger — that is the real trade.");

    println!("\nLMS verifier, measured — size-probe/measure.sh\n");
    println!(
        "{:<32} {:<16} {:>7} {:>9} {:>9} {:>9}",
        "target", "core", "total", "sha-only", "marginal", "stack>="
    );
    println!("{}", "-".repeat(84));
    for m in LMS_MEASUREMENTS {
        println!(
            "{:<32} {:<16} {:>7} {:>9} {:>9} {:>9}",
            m.target,
            m.core,
            m.code_total,
            m.code_sha_only,
            m.code_marginal(),
            m.stack_lower_bound
        );
    }
    println!("\n  stack>= is a static LOWER bound -- indirect and tail calls leave edges");
    println!("  missing from the call graph. Never budget against it. Measured below.\n");

    println!("Measured on an ESP32-S3 at 240 MHz -- esp-probe\n");
    println!(
        "{:<28} {:>10} {:>9} {:>8} {:>9} {:>9}",
        "backend", "cycles", "us", "frames", "backend", "total RAM"
    );
    println!("{}", "-".repeat(78));
    for t in boot_budget::ON_TARGET {
        println!(
            "{:<28} {:>10} {:>9} {:>8} {:>9} {:>9}",
            t.backend,
            t.cycles,
            t.micros_at_240mhz(),
            t.stack_frames,
            t.backend_bytes,
            t.total_ram()
        );
    }
    println!("\nThe accelerator is 3.3x faster and costs more than twice the RAM: its");
    println!("2328 bytes are almost all coalescing buffer, and that buffer is why it is");
    println!("fast. Shrinking it to 256 bytes measured 5% slower.");

    println!("\nThe verifier is smaller than its hash function on every target measured.");
    println!("A part doing secure boot already has SHA-256 for image integrity, so the");
    println!("marginal column is the real price of making boot quantum-secure.");
    println!("\nParameter sets share these figures: w and h are runtime values here, so");
    println!("H5/W8 and H10/W4 are the same code. Only the loop counts differ.");
}
