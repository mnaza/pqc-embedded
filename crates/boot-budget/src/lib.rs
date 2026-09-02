//! What a bootloader needs from a signature scheme, and whether it fits.
//!
//! # The question this crate exists to answer
//!
//! *"You already have secure boot. How do we upgrade it to be quantum secure?"*
//!
//! Secure boot is staged signature verification. The boot ROM authenticates the
//! first-stage image against a root of trust, that stage authenticates the next,
//! and so on. Making it quantum-secure means replacing the signature scheme at
//! each link — and the whole difficulty is that the links have budgets.
//!
//! Three constraints decide it, and they are ordinary engineering arithmetic
//! rather than cryptography:
//!
//! - **OTP.** The root of trust is burned into fuses. There are tens of bytes,
//!   not kilobytes. See [`budget::ROOT_DIGEST_OTP`] for why this is usually not
//!   the binding constraint people assume it is.
//! - **Flash.** Verifier code plus the stored public key, in a boot ROM that may
//!   have 16 KB in total.
//! - **RAM.** Peak working set during verification, before the next stage has
//!   brought up the rest of the system.
//! - **Time.** Boot has a deadline. This is the constraint that gets waved at
//!   rather than counted, so [`budget::Scheme::verify_hashes`] counts it — in
//!   SHA-256 compressions, which are exact and architecture-independent, rather
//!   than in milliseconds, which are neither.
//!
//! And a fourth that is not a budget at all:
//!
//! - **Immutability.** A boot ROM is mask-programmed. It cannot be patched, ever.
//!   This is the reason signature agility is urgent in a way that is often
//!   confused with the encryption argument. Harvest-now-decrypt-later says today's
//!   ciphertext can be broken later. Signatures have no such problem — nobody
//!   forges yesterday's boot. The signature problem is worse in a different way:
//!   **a device that ships with an ECC-only root of trust can never be upgraded in
//!   the field.** For that device the window does not close when a quantum
//!   computer arrives. It closed at tape-out.
//!
//! # What is measured and what is not
//!
//! Key and signature sizes come from the standards and are facts.
//!
//! **The LMS rows are measured** on four bare-metal targets — Cortex-M0+,
//! Cortex-M4F, and RISC-V rv32imc and rv32imac — by `size-probe/measure.sh`. The
//! headline: on Cortex-M4F the whole verifying binary is 5416 bytes of `.text`, of
//! which SHA-256 and the runtime account for 3880. **LMS verification itself costs
//! about 1.5 KB**, with a peak stack of 1172 bytes. On a part that already has
//! SHA-256 for image integrity — which every part doing secure boot does — that
//! 1.5 KB is the real price of making boot quantum-secure.
//!
//! **ML-DSA-44 is measured too**, on the same silicon, and the comparison is the
//! reason the crate exists:
//!
//! | Cortex-M4F / ESP32-S3 | LMS w8/h5 | ML-DSA-44 |
//! |---|---|---|
//! | code | 5528 | 13561 |
//! | public key | 56 | 1312 |
//! | signature | 1292 | 2420 |
//! | RAM | 1152 | **34044** |
//! | verify, software | 138.9 ms | **17.3 ms** |
//! | verify, with SHA engine | 41.7 ms | not possible — SHAKE |
//!
//! **ML-DSA is 2.4× faster than LMS even after the accelerator, and uses thirty
//! times the RAM.** The hash-engine discount is real and does not decide anything;
//! what decides is which budget is tight. A part with 8 KB of RAM can run LMS and
//! cannot run ML-DSA at all — not for want of flash, but for 34 KB of stack.
//!
//! **The ML-DSA-44 estimate this replaced said 12000 bytes of RAM**, and on that
//! figure the scheme fitted a 32 KB part. It does not. An estimate that flips a fit
//! verdict is not approximately right, it is wrong — which is the argument for the
//! `Provenance` type existing at all.
//!
//! **ML-DSA-65 and -87 and both SLH-DSA rows remain estimates**, and after that
//! they should be read as probably optimistic rather than roughly right.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod budget;
pub mod measurements;
pub mod verifier;

pub use budget::{Fit, Part, Provenance, Scheme, PARTS, SCHEMES};
pub use measurements::{Measurement, OnTarget, LMS_MEASUREMENTS, ON_TARGET};
pub use verifier::{BootVerifier, LmsBootVerifier};

#[cfg(test)]
mod tests {
    use super::*;
    use lms_verify::{LMOTS_SHA256_N32_W8, LMS_SHA256_M32_H5};

    #[test]
    fn lms_verifier_reports_the_sizes_the_table_claims() {
        let v = LmsBootVerifier::new(LMOTS_SHA256_N32_W8, LMS_SHA256_M32_H5);
        assert_eq!(v.public_key_len(), 56);
        assert_eq!(v.signature_len(), 1292);
        assert_eq!(budget::scheme("LMS w8/h5").unwrap().public_key, 56);
        // Exact, not approximate: the table is generated from the same arithmetic
        // the verifier uses, so a drift between them is a bug and should fail here
        // rather than surface in a design meeting.
        let claimed = budget::scheme("LMS w8/h5").unwrap().signature;
        assert_eq!(claimed, v.signature_len(), "budget table has drifted");
    }

    #[test]
    fn ml_dsa_does_not_fit_a_tight_boot_rom_but_lms_does() {
        let tight = PARTS[0];
        // With the estimate this was FlashExceeded: 18000 bytes of guessed code
        // plus a 1312-byte key against 16 KB. The measurement says 13561, so the
        // flash actually fits — and 34044 bytes of RAM against 8 KB does not.
        //
        // Both verdicts are "does not fit", so the estimate happened to reach the
        // right conclusion for the wrong reason. On the 32 KB part it did not: see
        // `ml_dsa_does_not_fit_a_32k_part_either`.
        assert_eq!(
            budget::scheme("ML-DSA-44").unwrap().fits(&tight),
            Fit::RamExceeded
        );
        assert!(budget::scheme("ML-DSA-44").unwrap().code + 1312 < tight.flash);
        assert_eq!(budget::scheme("LMS w8/h5").unwrap().fits(&tight), Fit::Fits);
        assert_eq!(
            budget::scheme("SLH-DSA-128s").unwrap().fits(&tight),
            Fit::Fits
        );
    }

    #[test]
    fn everything_fits_an_application_core() {
        // 256 KB of RAM, so even ML-DSA's 34 KB of stack is comfortable. This is
        // the row where scheme choice stops being a fit question and becomes a
        // preference one.
        let big = PARTS[2];
        for s in SCHEMES {
            assert_eq!(s.fits(&big), Fit::Fits, "{} did not fit", s.name);
        }
    }

    #[test]
    fn the_classical_schemes_are_flagged_as_quantum_broken() {
        assert!(budget::scheme("ECDSA P-256").unwrap().quantum_broken);
        assert!(budget::scheme("Ed25519").unwrap().quantum_broken);
        for name in ["LMS w8/h5", "ML-DSA-44", "SLH-DSA-128s"] {
            assert!(!budget::scheme(name).unwrap().quantum_broken, "{name}");
        }
    }

    #[test]
    fn stateful_schemes_are_flagged() {
        // A reused LMS leaf index is fatal. The flag exists so a caller choosing a
        // scheme has to look at the consequence rather than only at the size.
        assert!(budget::scheme("LMS w8/h10").unwrap().stateful);
        assert!(!budget::scheme("SLH-DSA-128s").unwrap().stateful);
    }

    #[test]
    fn a_measured_row_names_the_target_it_was_measured_on() {
        // The rule the whole table rests on: `Measured` is a claim, and a claim
        // has to say where it came from. An estimate must not carry a target.
        for s in SCHEMES {
            match s.code_provenance {
                Provenance::Measured => assert!(
                    s.measured_on.is_some(),
                    "{} claims measured code but names no target",
                    s.name
                ),
                Provenance::Estimated => assert!(
                    s.code_less_hash.is_none(),
                    "{} is a code estimate but carries a hash-subtracted figure",
                    s.name
                ),
                Provenance::Specified => {}
            }
        }
    }

    #[test]
    fn measured_rows_are_the_ones_the_docs_claim() {
        // Fails the moment another scheme is measured, which is the reminder to
        // correct every doc comment listing which rows are real.
        const MEASURED: &[&str] = &[
            "ECDSA P-256",
            "Ed25519",
            "LMS w8/h5",
            "LMS w8/h10",
            "LMS w4/h10",
            "ML-DSA-44",
            "ML-DSA-65",
            "ML-DSA-87",
            "SLH-DSA-128s",
            "FN-DSA-512",
        ];
        for s in SCHEMES {
            assert_eq!(
                s.code_provenance == Provenance::Measured,
                MEASURED.contains(&s.name),
                "{} changed provenance — update the crate docs and the README",
                s.name
            );
        }
    }

    #[test]
    fn ml_dsa_does_not_fit_a_32k_part_either() {
        // The correction that matters most in this crate. The estimate said 12000
        // bytes of RAM and it fitted a Cortex-M4 class part; the measurement says
        // 34044 and it does not. An estimate that flips a fit verdict is not a
        // rough figure, it is a wrong answer.
        let m4 = PARTS[1];
        assert_eq!(m4.ram, 32 * 1024);
        assert_eq!(
            budget::scheme("ML-DSA-44").unwrap().fits(&m4),
            Fit::RamExceeded
        );
        assert_eq!(budget::scheme("LMS w8/h5").unwrap().fits(&m4), Fit::Fits);
    }

    #[test]
    fn ml_dsa_is_faster_than_lms_and_that_is_the_point() {
        // Measured on one ESP32-S3: ML-DSA-44 verifies in 17.3 ms of pure software
        // against 41.7 ms for LMS *with* the SHA accelerator. The hash engine gives
        // LMS a real 3.3x discount and does not close the gap, because SHAKE cannot
        // use it.
        //
        // So the trade is time against RAM, and neither scheme wins outright. This
        // test exists because an earlier version of the crate's docs claimed
        // otherwise for several days.
        let lms_hw_us = ON_TARGET[1].micros_at_240mhz();
        assert!(lms_hw_us > 40_000);
        let mldsa = budget::scheme("ML-DSA-44").unwrap();
        let lms = budget::scheme("LMS w8/h5").unwrap();
        assert!(mldsa.ram > lms.ram * 25);
        assert!(mldsa.code > lms.code * 2);
    }

    #[test]
    fn the_table_quotes_the_representative_target_faithfully() {
        let m = measurements::measurement(measurements::REPRESENTATIVE).unwrap();
        let lms = budget::scheme("LMS w8/h5").unwrap();
        assert_eq!(lms.code, m.code_total);
        assert_eq!(lms.ram, measurements::ON_TARGET[0].total_ram());
        assert_eq!(lms.code_less_hash, Some(m.code_marginal()));
    }

    #[test]
    fn the_stored_verification_costs_match_the_live_model() {
        use lms_verify::cost::bounds;
        use lms_verify::{
            LMOTS_SHA256_N32_W4, LMOTS_SHA256_N32_W8, LMS_SHA256_M32_H10, LMS_SHA256_M32_H5,
        };
        const IMAGE: usize = 32 * 1024;
        for (name, ots, lms) in [
            ("LMS w8/h5", LMOTS_SHA256_N32_W8, LMS_SHA256_M32_H5),
            ("LMS w8/h10", LMOTS_SHA256_N32_W8, LMS_SHA256_M32_H10),
            ("LMS w4/h10", LMOTS_SHA256_N32_W4, LMS_SHA256_M32_H10),
        ] {
            let s = budget::scheme(name).unwrap();
            assert_eq!(
                s.verify_hashes,
                Some(bounds(&ots, &lms, IMAGE).typical),
                "{name} has drifted from the cost model"
            );
        }
    }

    #[test]
    fn the_smaller_signature_is_the_slower_one_to_verify() {
        // The trade worth being able to state: w=8 packs into fewer bytes by
        // walking fewer, longer chains, and pays for it on every boot.
        let w8 = budget::scheme("LMS w8/h10").unwrap();
        let w4 = budget::scheme("LMS w4/h10").unwrap();
        assert!(w8.signature < w4.signature);
        assert!(w8.verify_hashes > w4.verify_hashes);
    }

    #[test]
    fn ram_is_only_claimed_measured_where_it_was_measured() {
        // Code and RAM are established by different means, so one flag cannot cover
        // both. An earlier version had one, and every row whose code got measured
        // started advertising measured RAM it never had.
        const RAM_MEASURED: &[&str] = &["LMS w8/h5", "LMS w8/h10", "LMS w4/h10", "ML-DSA-44"];
        for s in SCHEMES {
            assert_eq!(
                s.ram_provenance == Provenance::Measured,
                RAM_MEASURED.contains(&s.name),
                "{} RAM provenance disagrees with what was actually measured",
                s.name
            );
        }
    }

    #[test]
    fn the_larger_ml_dsa_ram_estimates_are_known_wrong() {
        // -65 and -87 have larger matrices than -44, whose measured usage is 34044
        // bytes, so their estimates of 16000 and 20000 cannot be right. Pinned so
        // that whoever measures them sees this test fail and knows to delete it.
        let m44 = budget::scheme("ML-DSA-44").unwrap();
        assert_eq!(m44.ram_provenance, Provenance::Measured);
        for n in ["ML-DSA-65", "ML-DSA-87"] {
            let s = budget::scheme(n).unwrap();
            assert_eq!(s.ram_provenance, Provenance::Estimated);
            assert!(
                s.ram < m44.ram,
                "{n} estimate is below the measured -44 figure"
            );
        }
    }

    #[test]
    fn the_classical_scheme_carries_the_most_code() {
        // The result that inverts the usual framing. Post-quantum is bigger in keys
        // and signatures and smaller in code: ECDSA P-256's field and curve
        // arithmetic outweighs ML-DSA's lattice arithmetic, and LMS — which is a
        // hash in a loop and nothing else — is an order of magnitude under both.
        let by_code = |n: &str| budget::scheme(n).unwrap().code_less_hash.unwrap();
        assert!(by_code("ECDSA P-256") > by_code("ML-DSA-44"));
        assert!(by_code("ML-DSA-44") > by_code("SLH-DSA-128s"));
        assert!(by_code("SLH-DSA-128s") > by_code("LMS w8/h5") * 3);
    }

    #[test]
    fn ml_dsa_parameter_sets_barely_differ_in_code() {
        // 11041 / 11257 / 11201. The parameter set is paid for in key size,
        // signature size and RAM — not in flash, which is where people expect it.
        let c = |n: &str| budget::scheme(n).unwrap().code_less_hash.unwrap();
        let (a, b) = (c("ML-DSA-44"), c("ML-DSA-87"));
        assert!(
            b.abs_diff(a) * 20 < a,
            "expected under 5% apart: {a} vs {b}"
        );
        assert!(
            budget::scheme("ML-DSA-87").unwrap().public_key
                > budget::scheme("ML-DSA-44").unwrap().public_key
        );
    }

    #[test]
    fn only_lms_has_a_verification_cost() {
        for s in SCHEMES {
            assert_eq!(
                s.verify_hashes.is_some(),
                s.name.starts_with("LMS"),
                "{} — deriving a cost for this scheme means updating the docs too",
                s.name
            );
        }
    }

    #[test]
    fn the_accelerator_costs_ram_rather_than_saving_it() {
        // Worth pinning, because it is the opposite of what people expect. The
        // hardware backend's stack frames are tiny — the hash state lives in the
        // peripheral — but its coalescing buffer more than pays that back.
        let soft = ON_TARGET[0];
        let hw = ON_TARGET[1];
        assert!(hw.stack_frames < soft.stack_frames / 3);
        assert!(hw.total_ram() > soft.total_ram() * 2);
        assert!(hw.cycles < soft.cycles / 3);
    }

    #[test]
    fn the_static_pass_is_below_the_measured_figure() {
        // The whole reason ON_TARGET exists: the static analysis under-reports, so
        // it must never be quoted as a budget. If this ever inverts, the static
        // pass has started over-reporting and its docs are wrong.
        let repr = measurements::measurement(measurements::REPRESENTATIVE).unwrap();
        assert!(repr.stack_lower_bound < ON_TARGET[0].total_ram());
    }

    #[test]
    fn the_verifier_is_smaller_than_its_hash_function() {
        // The finding the crate exists to state, asserted so that a future change
        // which quietly reverses it cannot pass unnoticed.
        for m in LMS_MEASUREMENTS {
            assert!(
                m.code_marginal() < m.code_sha_only,
                "{}: LMS {} B vs SHA-256 {} B",
                m.core,
                m.code_marginal(),
                m.code_sha_only
            );
        }
    }

    #[test]
    fn lms_still_fits_the_tight_boot_rom_with_real_numbers() {
        // The estimate said it fits. The measurement has to agree, or the estimate
        // was doing work it had not earned.
        let tight = PARTS[0];
        for name in ["LMS w8/h5", "LMS w8/h10", "LMS w4/h10"] {
            assert_eq!(
                budget::scheme(name).unwrap().fits(&tight),
                Fit::Fits,
                "{name}"
            );
        }
        // And on the largest measured target, not just the representative one.
        let worst = LMS_MEASUREMENTS
            .iter()
            .max_by_key(|m| m.code_total)
            .unwrap();
        assert!(worst.code_total + 56 < tight.flash);
        // Measured on hardware rather than the static lower bound, which is not a
        // budget and must not be used as one.
        assert!(ON_TARGET[0].total_ram() < tight.ram);
    }

    #[test]
    fn signature_overhead_ordering_is_what_the_argument_claims() {
        // The point of the LMS-for-boot argument: ML-DSA's key is what hurts, and
        // SLH-DSA's signature is what hurts. LMS is modest on both.
        let lms = budget::scheme("LMS w8/h5").unwrap();
        let mldsa = budget::scheme("ML-DSA-44").unwrap();
        let slh = budget::scheme("SLH-DSA-128s").unwrap();
        assert!(lms.public_key < mldsa.public_key / 20);
        assert!(lms.per_image_overhead() < slh.per_image_overhead() / 5);
    }
}
